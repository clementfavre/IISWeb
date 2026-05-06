using System.Text.Json;
using IISWeb.Configuration;
using IISWeb.Data;
using IISWeb.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IISWeb.Services;

public class UserService : IUserService
{
    private const int MinPasswordLength = 12;

    private readonly AppDbContext _db;
    private readonly IPasswordHasher<AppUser> _hasher;
    private readonly IOptionsMonitor<AppOptions> _opt;
    private readonly ITotpService _totp;

    public UserService(AppDbContext db, IPasswordHasher<AppUser> hasher, IOptionsMonitor<AppOptions> opt, ITotpService totp)
    {
        _db = db;
        _hasher = hasher;
        _opt = opt;
        _totp = totp;
    }

    public Task<AppUser?> FindByNameAsync(string userName)
        => _db.Users.SingleOrDefaultAsync(u => u.UserName == userName);

    public Task<AppUser?> FindByIdAsync(int id)
        => _db.Users.SingleOrDefaultAsync(u => u.Id == id);

    public async Task<IReadOnlyList<AppUser>> ListAsync()
        => await _db.Users.AsNoTracking().OrderBy(u => u.UserName).ToListAsync();

    public async Task<(LoginResult Result, AppUser? User)> CheckPasswordAsync(string userName, string password)
    {
        var user = await FindByNameAsync(userName);
        if (user is null)
            return (LoginResult.NotFound, null);

        if (user.LockoutUntilUtc is { } until && until > DateTime.UtcNow)
            return (LoginResult.LockedOut, user);

        var v = _hasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (v == PasswordVerificationResult.Failed)
            return (LoginResult.InvalidPassword, user);

        if (v == PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = _hasher.HashPassword(user, password);
            await _db.SaveChangesAsync();
        }

        return (LoginResult.Success, user);
    }

    public async Task RegisterFailedAttemptAsync(AppUser user)
    {
        var opt = _opt.CurrentValue;
        user.FailedLoginAttempts++;
        if (user.FailedLoginAttempts >= opt.LoginMaxAttempts)
        {
            user.LockoutUntilUtc = DateTime.UtcNow.AddMinutes(Math.Max(1, opt.LoginLockoutMinutes));
            user.FailedLoginAttempts = 0;
        }
        await _db.SaveChangesAsync();
    }

    public async Task ClearFailedAttemptsAsync(AppUser user)
    {
        user.FailedLoginAttempts = 0;
        user.LockoutUntilUtc = null;
        user.LastLoginUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync();
    }

    public async Task<AppUser> CreateAdminAsync(string userName, string password)
    {
        var (result, user, err) = await CreateAsync(userName, password, Roles.Admin);
        return result switch
        {
            AdminUserOpResult.Success => user!,
            AdminUserOpResult.Conflict => throw new InvalidOperationException($"User '{userName}' already exists."),
            _ => throw new ArgumentException(err ?? "Invalid input.")
        };
    }

    public async Task<(AdminUserOpResult Result, AppUser? User, string? Error)> CreateAsync(string userName, string password, string role)
    {
        userName = (userName ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(userName))
            return (AdminUserOpResult.Invalid, null, "User name is required.");
        if (userName.Length > 64)
            return (AdminUserOpResult.Invalid, null, "User name must be at most 64 characters.");
        if (string.IsNullOrEmpty(password) || password.Length < MinPasswordLength)
            return (AdminUserOpResult.Invalid, null, $"Password must be at least {MinPasswordLength} characters long.");
        if (!Roles.IsKnown(role))
            return (AdminUserOpResult.Invalid, null, "Unknown role.");

        if (await _db.Users.AnyAsync(u => u.UserName == userName))
            return (AdminUserOpResult.Conflict, null, $"User '{userName}' already exists.");

        var u = new AppUser
        {
            UserName = userName,
            Role = role,
            MustChangePassword = true
        };
        u.PasswordHash = _hasher.HashPassword(u, password);
        _db.Users.Add(u);
        await _db.SaveChangesAsync();
        return (AdminUserOpResult.Success, u, null);
    }

    public async Task<AdminUserOpResult> UpdateRoleAsync(int id, string role)
    {
        if (!Roles.IsKnown(role)) return AdminUserOpResult.Invalid;

        var user = await _db.Users.FindAsync(id);
        if (user is null) return AdminUserOpResult.NotFound;

        if (user.Role == Roles.Admin && role != Roles.Admin && await IsLastAdminAsync(user.Id))
            return AdminUserOpResult.LastAdmin;

        user.Role = role;
        await _db.SaveChangesAsync();
        return AdminUserOpResult.Success;
    }

    public async Task<AdminUserOpResult> ResetPasswordAsync(int id, string newPassword)
    {
        if (string.IsNullOrEmpty(newPassword) || newPassword.Length < MinPasswordLength)
            return AdminUserOpResult.Invalid;

        var user = await _db.Users.FindAsync(id);
        if (user is null) return AdminUserOpResult.NotFound;

        user.PasswordHash = _hasher.HashPassword(user, newPassword);
        user.MustChangePassword = true;
        user.FailedLoginAttempts = 0;
        user.LockoutUntilUtc = null;
        await _db.SaveChangesAsync();
        return AdminUserOpResult.Success;
    }

    public async Task<AdminUserOpResult> UnlockAsync(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user is null) return AdminUserOpResult.NotFound;

        user.FailedLoginAttempts = 0;
        user.LockoutUntilUtc = null;
        await _db.SaveChangesAsync();
        return AdminUserOpResult.Success;
    }

    public async Task<AdminUserOpResult> DisableMfaAsync(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user is null) return AdminUserOpResult.NotFound;

        user.TotpEnabled = false;
        user.TotpSecret = null;
        user.TotpRecoveryCodesJson = null;
        await _db.SaveChangesAsync();
        return AdminUserOpResult.Success;
    }

    public async Task<AdminUserOpResult> DeleteAsync(int id, int? actingUserId)
    {
        var user = await _db.Users.FindAsync(id);
        if (user is null) return AdminUserOpResult.NotFound;

        if (actingUserId is { } me && me == id)
            return AdminUserOpResult.Invalid;

        if (user.Role == Roles.Admin && await IsLastAdminAsync(user.Id))
            return AdminUserOpResult.LastAdmin;

        _db.Users.Remove(user);
        await _db.SaveChangesAsync();
        return AdminUserOpResult.Success;
    }

    public async Task<bool> ChangeOwnPasswordAsync(int userId, string currentPassword, string newPassword)
    {
        if (string.IsNullOrEmpty(newPassword) || newPassword.Length < MinPasswordLength)
            return false;

        var user = await _db.Users.FindAsync(userId);
        if (user is null) return false;

        var v = _hasher.VerifyHashedPassword(user, user.PasswordHash, currentPassword);
        if (v == PasswordVerificationResult.Failed) return false;

        user.PasswordHash = _hasher.HashPassword(user, newPassword);
        user.MustChangePassword = false;
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task SetMustChangePasswordAsync(int userId, bool flag)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null) return;
        user.MustChangePassword = flag;
        await _db.SaveChangesAsync();
    }

    public async Task BeginMfaEnrolmentAsync(int userId, string base32Secret)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null) return;
        user.TotpSecret = base32Secret;
        user.TotpEnabled = false;
        user.TotpRecoveryCodesJson = null;
        await _db.SaveChangesAsync();
    }

    public async Task<bool> ConfirmMfaEnrolmentAsync(int userId, string code, IReadOnlyList<string> recoveryHashes)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null || string.IsNullOrEmpty(user.TotpSecret)) return false;

        if (!_totp.Validate(user.TotpSecret, code)) return false;

        user.TotpEnabled = true;
        user.TotpRecoveryCodesJson = JsonSerializer.Serialize(recoveryHashes);
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task ClearMfaAsync(int userId)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null) return;
        user.TotpEnabled = false;
        user.TotpSecret = null;
        user.TotpRecoveryCodesJson = null;
        await _db.SaveChangesAsync();
    }

    public async Task<bool> ConsumeRecoveryCodeAsync(AppUser user, string clearCode)
    {
        if (string.IsNullOrEmpty(user.TotpRecoveryCodesJson)) return false;

        var hashes = JsonSerializer.Deserialize<List<string>>(user.TotpRecoveryCodesJson) ?? new List<string>();
        var candidate = _totp.HashRecoveryCode(clearCode);
        var idx = hashes.FindIndex(h => string.Equals(h, candidate, StringComparison.OrdinalIgnoreCase));
        if (idx < 0) return false;

        hashes.RemoveAt(idx);
        var tracked = await _db.Users.FindAsync(user.Id);
        if (tracked is null) return false;
        tracked.TotpRecoveryCodesJson = JsonSerializer.Serialize(hashes);
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task ReplaceRecoveryCodesAsync(int userId, IReadOnlyList<string> hashes)
    {
        var user = await _db.Users.FindAsync(userId);
        if (user is null) return;
        user.TotpRecoveryCodesJson = JsonSerializer.Serialize(hashes);
        await _db.SaveChangesAsync();
    }

    private async Task<bool> IsLastAdminAsync(int candidateId)
    {
        var others = await _db.Users.CountAsync(u => u.Role == Roles.Admin && u.Id != candidateId);
        return others == 0;
    }
}

using IISWeb.Models;

namespace IISWeb.Services;

public enum LoginResult
{
    Success,
    NotFound,
    InvalidPassword,
    LockedOut
}

public enum AdminUserOpResult
{
    Success,
    NotFound,
    LastAdmin,
    Conflict,
    Invalid
}

public interface IUserService
{
    Task<AppUser?> FindByNameAsync(string userName);
    Task<AppUser?> FindByIdAsync(int id);
    Task<IReadOnlyList<AppUser>> ListAsync();
    Task<(LoginResult Result, AppUser? User)> CheckPasswordAsync(string userName, string password);
    Task RegisterFailedAttemptAsync(AppUser user);
    Task ClearFailedAttemptsAsync(AppUser user);
    Task<AppUser> CreateAdminAsync(string userName, string password);

    // Admin management
    Task<(AdminUserOpResult Result, AppUser? User, string? Error)> CreateAsync(string userName, string password, string role);
    Task<AdminUserOpResult> UpdateRoleAsync(int id, string role);
    Task<AdminUserOpResult> ResetPasswordAsync(int id, string newPassword);
    Task<AdminUserOpResult> UnlockAsync(int id);
    Task<AdminUserOpResult> DisableMfaAsync(int id);
    Task<AdminUserOpResult> DeleteAsync(int id, int? actingUserId);

    // Self-service
    Task<bool> ChangeOwnPasswordAsync(int userId, string currentPassword, string newPassword);
    Task SetMustChangePasswordAsync(int userId, bool flag);

    // MFA enrolment
    Task BeginMfaEnrolmentAsync(int userId, string base32Secret);
    Task<bool> ConfirmMfaEnrolmentAsync(int userId, string code, IReadOnlyList<string> recoveryHashes);
    Task ClearMfaAsync(int userId);
    Task<bool> ConsumeRecoveryCodeAsync(AppUser user, string clearCode);
    Task ReplaceRecoveryCodesAsync(int userId, IReadOnlyList<string> hashes);
}

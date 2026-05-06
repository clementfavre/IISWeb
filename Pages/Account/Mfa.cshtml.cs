using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using IISWeb.Models;
using IISWeb.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IISWeb.Pages.Account;

public class MfaModel : PageModel
{
    private const string PendingSecretKey = "Mfa.PendingSecret";
    private const string PendingCodesKey = "Mfa.PendingCodes";
    private const string ShowOnceCodesKey = "Mfa.NewRecoveryCodes";

    private readonly IUserService _users;
    private readonly IAuditService _audit;
    private readonly ITotpService _totp;
    private readonly IPasswordHasher<AppUser> _hasher;

    public MfaModel(IUserService users, IAuditService audit, ITotpService totp, IPasswordHasher<AppUser> hasher)
    {
        _users = users;
        _audit = audit;
        _totp = totp;
        _hasher = hasher;
    }

    public AppUser? CurrentUser { get; private set; }
    public bool TotpEnabled => CurrentUser?.TotpEnabled == true;
    public string? PendingOtpAuthUri { get; private set; }
    public string? PendingQrSvg { get; private set; }
    public string? PendingSecret { get; private set; }
    public IReadOnlyList<string>? RecoveryCodesToShow { get; private set; }
    public int RemainingRecoveryCodes { get; private set; }

    public string? StatusMessage { get; private set; }
    public bool StatusSuccess { get; private set; } = true;

    [BindProperty] public string? VerifyCode { get; set; }
    [BindProperty] public string? CurrentPassword { get; set; }
    [BindProperty] public string? DisableCode { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var u = await CurrentUserAsync();
        if (u is null) return Forbid();

        ConsumeStatus();
        ConsumePendingEnrolment(u);
        ConsumeShowOnceCodes();
        return Page();
    }

    public async Task<IActionResult> OnPostBeginAsync()
    {
        var u = await CurrentUserAsync();
        if (u is null) return Forbid();
        if (u.TotpEnabled)
        {
            SetStatus(false, "MFA is already enabled. Disable it first to re-enrol.");
            return RedirectToPage();
        }

        var secret = _totp.GenerateSecret();
        await _users.BeginMfaEnrolmentAsync(u.Id, secret);
        TempData[PendingSecretKey] = secret;
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostConfirmAsync()
    {
        var u = await CurrentUserAsync();
        if (u is null) return Forbid();
        if (u.TotpEnabled)
        {
            SetStatus(false, "MFA is already enabled.");
            return RedirectToPage();
        }
        if (string.IsNullOrEmpty(u.TotpSecret))
        {
            SetStatus(false, "Start enrolment first.");
            return RedirectToPage();
        }
        if (string.IsNullOrWhiteSpace(VerifyCode))
        {
            SetStatus(false, "Enter the 6-digit code.");
            TempData[PendingSecretKey] = u.TotpSecret;
            return RedirectToPage();
        }

        var (clear, hashes) = _totp.GenerateRecoveryCodes();
        var ok = await _users.ConfirmMfaEnrolmentAsync(u.Id, VerifyCode.Trim(), hashes);
        if (!ok)
        {
            SetStatus(false, "Code did not match. Try again.");
            TempData[PendingSecretKey] = u.TotpSecret;
            return RedirectToPage();
        }

        await _audit.LogAsync(AuditActions.MfaEnable, null, true, userNameOverride: u.UserName);
        TempData[ShowOnceCodesKey] = string.Join(',', clear);
        SetStatus(true, "MFA enabled. Save the recovery codes shown below.");
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostDisableAsync()
    {
        var u = await CurrentUserAsync();
        if (u is null) return Forbid();
        if (!u.TotpEnabled)
        {
            SetStatus(false, "MFA is not enabled.");
            return RedirectToPage();
        }

        if (string.IsNullOrEmpty(CurrentPassword) ||
            _hasher.VerifyHashedPassword(u, u.PasswordHash, CurrentPassword) == PasswordVerificationResult.Failed)
        {
            await _audit.LogAsync(AuditActions.MfaDisable, null, false, "Wrong password.", userNameOverride: u.UserName);
            SetStatus(false, "Wrong current password.");
            return RedirectToPage();
        }

        if (string.IsNullOrWhiteSpace(DisableCode) ||
            string.IsNullOrEmpty(u.TotpSecret) ||
            !_totp.Validate(u.TotpSecret, DisableCode.Trim()))
        {
            await _audit.LogAsync(AuditActions.MfaDisable, null, false, "Wrong TOTP code.", userNameOverride: u.UserName);
            SetStatus(false, "Wrong TOTP code.");
            return RedirectToPage();
        }

        await _users.ClearMfaAsync(u.Id);
        await _audit.LogAsync(AuditActions.MfaDisable, null, true, userNameOverride: u.UserName);
        SetStatus(true, "MFA disabled.");
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostRegenerateCodesAsync()
    {
        var u = await CurrentUserAsync();
        if (u is null) return Forbid();
        if (!u.TotpEnabled)
        {
            SetStatus(false, "MFA is not enabled.");
            return RedirectToPage();
        }

        var (clear, hashes) = _totp.GenerateRecoveryCodes();
        await _users.ReplaceRecoveryCodesAsync(u.Id, hashes);
        await _audit.LogAsync(AuditActions.MfaEnable, null, true, "Recovery codes regenerated.", userNameOverride: u.UserName);
        TempData[ShowOnceCodesKey] = string.Join(',', clear);
        SetStatus(true, "New recovery codes generated. Save them below.");
        return RedirectToPage();
    }

    private async Task<AppUser?> CurrentUserAsync()
    {
        var idStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!int.TryParse(idStr, out var id)) return null;
        CurrentUser = await _users.FindByIdAsync(id);
        if (CurrentUser is not null && !string.IsNullOrEmpty(CurrentUser.TotpRecoveryCodesJson))
        {
            try
            {
                var list = System.Text.Json.JsonSerializer.Deserialize<List<string>>(CurrentUser.TotpRecoveryCodesJson);
                RemainingRecoveryCodes = list?.Count ?? 0;
            }
            catch { RemainingRecoveryCodes = 0; }
        }
        return CurrentUser;
    }

    private void ConsumePendingEnrolment(AppUser u)
    {
        if (u.TotpEnabled) return;

        var secret = TempData[PendingSecretKey] as string ?? u.TotpSecret;
        if (string.IsNullOrEmpty(secret)) return;

        // Persist for the next render in case the user POSTs Confirm.
        TempData.Keep(PendingSecretKey);

        PendingSecret = secret;
        PendingOtpAuthUri = _totp.BuildOtpAuthUri("IISWeb", u.UserName, secret);
        PendingQrSvg = _totp.BuildQrCodeSvg(PendingOtpAuthUri);
    }

    private void ConsumeShowOnceCodes()
    {
        if (TempData[ShowOnceCodesKey] is string s && !string.IsNullOrEmpty(s))
            RecoveryCodesToShow = s.Split(',', StringSplitOptions.RemoveEmptyEntries);
    }

    private void SetStatus(bool ok, string msg)
    {
        TempData["MfaStatus"] = (ok ? "ok|" : "err|") + msg;
    }

    private void ConsumeStatus()
    {
        if (TempData["MfaStatus"] is string s)
        {
            var parts = s.Split('|', 2);
            StatusSuccess = parts[0] == "ok";
            StatusMessage = parts.Length > 1 ? parts[1] : null;
        }
    }
}

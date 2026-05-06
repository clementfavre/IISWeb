using System.ComponentModel.DataAnnotations;
using IISWeb.Models;
using IISWeb.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IISWeb.Pages.Admin.Users;

[Authorize(Policy = "Admin")]
public class EditModel : PageModel
{
    private readonly IUserService _users;
    private readonly IAuditService _audit;

    public EditModel(IUserService users, IAuditService audit)
    {
        _users = users;
        _audit = audit;
    }

    [BindProperty(SupportsGet = true)] public int Id { get; set; }
    [BindProperty] public string Role { get; set; } = string.Empty;
    [BindProperty] public string? NewPassword { get; set; }
    public AppUser? Target { get; private set; }
    public string? ErrorMessage { get; set; }
    public string? StatusMessage { get; private set; }
    public bool StatusSuccess { get; private set; } = true;
    public IReadOnlyList<string> Roles => IISWeb.Models.Roles.All;

    public async Task<IActionResult> OnGetAsync()
    {
        Target = await _users.FindByIdAsync(Id);
        if (Target is null) return NotFound();
        Role = Target.Role;
        ConsumeStatus();
        return Page();
    }

    public async Task<IActionResult> OnPostRoleAsync()
    {
        var u = await _users.FindByIdAsync(Id);
        if (u is null) return NotFound();

        var result = await _users.UpdateRoleAsync(Id, Role);
        await Audit(result, AuditActions.UserUpdate, u.UserName, $"Role -> {Role}");
        SetStatus(result, "Role updated.");
        return RedirectToPage(new { id = Id });
    }

    public async Task<IActionResult> OnPostResetPasswordAsync()
    {
        var u = await _users.FindByIdAsync(Id);
        if (u is null) return NotFound();

        if (string.IsNullOrEmpty(NewPassword) || NewPassword.Length < 12)
        {
            await _audit.LogAsync(AuditActions.UserResetPwd, null, false, "Weak new password.", userNameOverride: User.Identity?.Name);
            SetStatus(AdminUserOpResult.Invalid, "Password must be at least 12 characters.");
            return RedirectToPage(new { id = Id });
        }

        var result = await _users.ResetPasswordAsync(Id, NewPassword);
        await Audit(result, AuditActions.UserResetPwd, u.UserName, "Password reset (must change on next sign-in).");
        SetStatus(result, "Password reset. The user must change it on next sign-in.");
        return RedirectToPage(new { id = Id });
    }

    public async Task<IActionResult> OnPostUnlockAsync()
    {
        var u = await _users.FindByIdAsync(Id);
        if (u is null) return NotFound();

        var result = await _users.UnlockAsync(Id);
        await Audit(result, AuditActions.UserUnlock, u.UserName);
        SetStatus(result, "Account unlocked.");
        return RedirectToPage(new { id = Id });
    }

    public async Task<IActionResult> OnPostDisableMfaAsync()
    {
        var u = await _users.FindByIdAsync(Id);
        if (u is null) return NotFound();

        var result = await _users.DisableMfaAsync(Id);
        await Audit(result, AuditActions.UserDisableMfa, u.UserName);
        SetStatus(result, "MFA disabled. The user can re-enrol from /Account/Mfa.");
        return RedirectToPage(new { id = Id });
    }

    private async Task Audit(AdminUserOpResult result, string action, string targetUser, string? extra = null)
    {
        var ok = result == AdminUserOpResult.Success;
        var msg = ok ? $"on {targetUser}" + (extra is null ? "" : $". {extra}") : $"on {targetUser}: {result}";
        await _audit.LogAsync(action, null, ok, msg, userNameOverride: User.Identity?.Name);
    }

    private void SetStatus(AdminUserOpResult result, string okMessage)
    {
        var ok = result == AdminUserOpResult.Success;
        var msg = result switch
        {
            AdminUserOpResult.Success => okMessage,
            AdminUserOpResult.LastAdmin => "Cannot change: this is the last Admin.",
            AdminUserOpResult.NotFound => "User not found.",
            AdminUserOpResult.Invalid => "Invalid input.",
            _ => result.ToString()
        };
        TempData["EditStatus"] = (ok ? "ok|" : "err|") + msg;
    }

    private void ConsumeStatus()
    {
        if (TempData["EditStatus"] is string s)
        {
            var parts = s.Split('|', 2);
            StatusSuccess = parts[0] == "ok";
            StatusMessage = parts.Length > 1 ? parts[1] : null;
        }
    }
}

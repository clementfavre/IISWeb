using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using IISWeb.Models;
using IISWeb.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IISWeb.Pages.Account;

public class ChangePasswordModel : PageModel
{
    private readonly IUserService _users;
    private readonly IAuditService _audit;

    public ChangePasswordModel(IUserService users, IAuditService audit)
    {
        _users = users;
        _audit = audit;
    }

    [BindProperty] public InputModel Input { get; set; } = new();
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; set; }
    public bool MustChange { get; private set; }

    public class InputModel
    {
        [Required, DataType(DataType.Password), StringLength(256, MinimumLength = 1)]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required, DataType(DataType.Password), StringLength(256, MinimumLength = 12)]
        public string NewPassword { get; set; } = string.Empty;

        [Required, DataType(DataType.Password), Compare(nameof(NewPassword))]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var u = await CurrentAsync();
        if (u is null) return Forbid();
        MustChange = u.MustChangePassword;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var u = await CurrentAsync();
        if (u is null) return Forbid();
        MustChange = u.MustChangePassword;

        if (!ModelState.IsValid)
        {
            ErrorMessage = "Please correct the errors below.";
            return Page();
        }

        if (Input.NewPassword == Input.CurrentPassword)
        {
            ErrorMessage = "The new password must be different from the current one.";
            return Page();
        }

        var ok = await _users.ChangeOwnPasswordAsync(u.Id, Input.CurrentPassword, Input.NewPassword);
        if (!ok)
        {
            await _audit.LogAsync(AuditActions.PasswordChange, null, false, "Wrong current password or weak new password.", userNameOverride: u.UserName);
            ErrorMessage = "Wrong current password.";
            return Page();
        }

        await _audit.LogAsync(AuditActions.PasswordChange, null, true, userNameOverride: u.UserName);

        if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
            return LocalRedirect(ReturnUrl);
        return RedirectToPage("/Index");
    }

    private async Task<AppUser?> CurrentAsync()
    {
        var idStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return int.TryParse(idStr, out var id) ? await _users.FindByIdAsync(id) : null;
    }
}

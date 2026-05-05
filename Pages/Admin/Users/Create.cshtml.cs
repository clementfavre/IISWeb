using System.ComponentModel.DataAnnotations;
using IISWeb.Models;
using IISWeb.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IISWeb.Pages.Admin.Users;

[Authorize(Policy = "Admin")]
public class CreateModel : PageModel
{
    private readonly IUserService _users;
    private readonly IAuditService _audit;

    public CreateModel(IUserService users, IAuditService audit)
    {
        _users = users;
        _audit = audit;
    }

    [BindProperty] public InputModel Input { get; set; } = new();
    public string? ErrorMessage { get; set; }
    public IReadOnlyList<string> Roles => IISWeb.Models.Roles.All;

    public class InputModel
    {
        [Required, StringLength(64, MinimumLength = 1)]
        public string UserName { get; set; } = string.Empty;

        [Required, DataType(DataType.Password), StringLength(256, MinimumLength = 12)]
        public string Password { get; set; } = string.Empty;

        [Required] public string Role { get; set; } = IISWeb.Models.Roles.Viewer;
    }

    public IActionResult OnGet() => Page();

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            ErrorMessage = "Please correct the errors below.";
            return Page();
        }

        var (result, user, err) = await _users.CreateAsync(Input.UserName, Input.Password, Input.Role);
        if (result != AdminUserOpResult.Success)
        {
            ErrorMessage = err ?? result.ToString();
            await _audit.LogAsync(AuditActions.UserCreate, null, false, ErrorMessage, userNameOverride: User.Identity?.Name);
            return Page();
        }

        await _audit.LogAsync(AuditActions.UserCreate, null, true, $"Created {user!.UserName} ({user.Role}).");
        TempData["UsersStatus"] = $"ok|User '{user.UserName}' created. They will be required to change the password on first sign-in.";
        return RedirectToPage("Index");
    }
}

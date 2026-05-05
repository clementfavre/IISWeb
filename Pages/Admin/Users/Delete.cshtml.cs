using System.Security.Claims;
using IISWeb.Models;
using IISWeb.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IISWeb.Pages.Admin.Users;

[Authorize(Policy = "Admin")]
public class DeleteModel : PageModel
{
    private readonly IUserService _users;
    private readonly IAuditService _audit;

    public DeleteModel(IUserService users, IAuditService audit)
    {
        _users = users;
        _audit = audit;
    }

    [BindProperty(SupportsGet = true)] public int Id { get; set; }
    public AppUser? Target { get; private set; }
    public bool IsSelf { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        Target = await _users.FindByIdAsync(Id);
        if (Target is null) return NotFound();
        IsSelf = ActingUserId() == Id;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var u = await _users.FindByIdAsync(Id);
        if (u is null) return NotFound();
        Target = u;
        IsSelf = ActingUserId() == Id;

        var result = await _users.DeleteAsync(Id, ActingUserId());
        if (result != AdminUserOpResult.Success)
        {
            ErrorMessage = result switch
            {
                AdminUserOpResult.LastAdmin => "Cannot delete the last Admin.",
                AdminUserOpResult.Invalid => "You cannot delete your own account.",
                _ => result.ToString()
            };
            await _audit.LogAsync(AuditActions.UserDelete, null, false, $"Refused on {u.UserName}: {result}", userNameOverride: User.Identity?.Name);
            return Page();
        }

        await _audit.LogAsync(AuditActions.UserDelete, null, true, $"Deleted {u.UserName}", userNameOverride: User.Identity?.Name);
        TempData["UsersStatus"] = $"ok|User '{u.UserName}' has been deleted.";
        return RedirectToPage("Index");
    }

    private int? ActingUserId()
    {
        var s = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return int.TryParse(s, out var id) ? id : null;
    }
}

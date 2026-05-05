using IISWeb.Models;
using IISWeb.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IISWeb.Pages.Admin.Users;

[Authorize(Policy = "Admin")]
public class IndexModel : PageModel
{
    private readonly IUserService _users;
    public IndexModel(IUserService users) => _users = users;

    public IReadOnlyList<AppUser> Users { get; private set; } = Array.Empty<AppUser>();
    public string? StatusMessage { get; private set; }
    public bool StatusSuccess { get; private set; } = true;

    public async Task OnGetAsync()
    {
        Users = await _users.ListAsync();
        if (TempData["UsersStatus"] is string s)
        {
            var parts = s.Split('|', 2);
            StatusSuccess = parts[0] == "ok";
            StatusMessage = parts.Length > 1 ? parts[1] : null;
        }
    }
}

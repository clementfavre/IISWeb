using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using IISWeb.Models;
using IISWeb.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace IISWeb.Pages.Account;

[AllowAnonymous]
[EnableRateLimiting("login")]
public class LoginModel : PageModel
{
    private readonly IUserService _users;
    private readonly IAuditService _audit;
    private readonly MfaTicketService _mfaTickets;

    public LoginModel(IUserService users, IAuditService audit, MfaTicketService mfaTickets)
    {
        _users = users;
        _audit = audit;
        _mfaTickets = mfaTickets;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Reason { get; set; }

    public string? ErrorMessage { get; set; }
    public string? InfoMessage { get; set; }

    public class InputModel
    {
        [Required, StringLength(64, MinimumLength = 1)]
        [Display(Name = "Username")]
        public string UserName { get; set; } = string.Empty;

        [Required, DataType(DataType.Password)]
        [StringLength(256, MinimumLength = 1)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        if (User?.Identity?.IsAuthenticated == true)
            return LocalRedirect(SafeReturnUrl());

        // Make sure to clear out any half-broken auth.
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        Response.Cookies.Delete(MfaTicketService.CookieName);

        // Surface the reason when the user got bounced back from /LoginMfa,
        // otherwise the bounce looks silent and indistinguishable from a typo.
        InfoMessage = Reason switch
        {
            "expired" => "Your verification session expired. Please sign in again.",
            _         => null
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            ErrorMessage = "Invalid form submission.";
            return Page();
        }

        var name = (Input.UserName ?? string.Empty).Trim();

        var (result, user) = await _users.CheckPasswordAsync(name, Input.Password);

        switch (result)
        {
            case LoginResult.Success when user is not null:
                await _users.ClearFailedAttemptsAsync(user);

                if (user.TotpEnabled && !string.IsNullOrEmpty(user.TotpSecret))
                {
                    // Step 1 done — issue an MFA ticket and ask for the code.
                    var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
                    var token = _mfaTickets.Issue(user.Id, user.UserName, ip, user.MustChangePassword, ReturnUrl);
                    Response.Cookies.Append(MfaTicketService.CookieName, token, BuildMfaCookieOptions());
                    await _audit.LogAsync(AuditActions.Login, null, true, "Password OK, MFA required.", userNameOverride: user.UserName);
                    return RedirectToPage("/Account/LoginMfa");
                }

                await SignInAsync(user);
                await _audit.LogAsync(AuditActions.Login, null, true, userNameOverride: user.UserName);

                if (user.MustChangePassword)
                    return RedirectToPage("/Account/ChangePassword", new { returnUrl = SafeReturnUrl() });

                return LocalRedirect(SafeReturnUrl());

            case LoginResult.LockedOut:
                await _audit.LogAsync(AuditActions.Login, null, false, "Account locked.", userNameOverride: name);
                ErrorMessage = "Account is temporarily locked. Try again later.";
                return Page();

            case LoginResult.InvalidPassword when user is not null:
                await _users.RegisterFailedAttemptAsync(user);
                await _audit.LogAsync(AuditActions.Login, null, false, "Invalid password.", userNameOverride: name);
                ErrorMessage = "Invalid username or password.";
                return Page();

            default:
                await _audit.LogAsync(AuditActions.Login, null, false, "Unknown user.", userNameOverride: name);
                ErrorMessage = "Invalid username or password.";
                return Page();
        }
    }

    internal static async Task SignInAsync(HttpContext http, AppUser user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Role, user.Role),
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await http.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = false,
                AllowRefresh = true
            });
    }

    private Task SignInAsync(AppUser user) => SignInAsync(HttpContext, user);

    internal CookieOptions BuildMfaCookieOptions()
        => new()
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = Request.IsHttps,
            IsEssential = true,
            Expires = DateTimeOffset.UtcNow.AddMinutes(5),
            Path = "/"
        };

    private string SafeReturnUrl()
    {
        if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
            return ReturnUrl;
        return Url.Page("/Index") ?? "/";
    }
}

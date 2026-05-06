using System.ComponentModel.DataAnnotations;
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
public class LoginMfaModel : PageModel
{
    private readonly IUserService _users;
    private readonly IAuditService _audit;
    private readonly ITotpService _totp;
    private readonly MfaTicketService _tickets;

    public LoginMfaModel(IUserService users, IAuditService audit, ITotpService totp, MfaTicketService tickets)
    {
        _users = users;
        _audit = audit;
        _totp = totp;
        _tickets = tickets;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [Required, StringLength(16, MinimumLength = 6)]
        public string Code { get; set; } = string.Empty;
    }

    public IActionResult OnGet()
    {
        var ticket = ReadTicket();
        if (ticket is null) return RedirectToPage("/Account/Login", new { reason = "expired" });
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var ticket = ReadTicket();
        if (ticket is null) return RedirectToPage("/Account/Login", new { reason = "expired" });

        if (!ModelState.IsValid)
        {
            ErrorMessage = "Invalid form submission.";
            return Page();
        }

        var user = await _users.FindByIdAsync(ticket.UserId);
        if (user is null || !user.TotpEnabled || string.IsNullOrEmpty(user.TotpSecret))
        {
            await ClearTicketAndSignOutAsync();
            return RedirectToPage("/Account/Login");
        }

        var code = (Input.Code ?? string.Empty).Trim();

        // 6 digits => TOTP. Anything else (letters or longer) => recovery code.
        var isAllDigits = code.Length == 6 && code.All(char.IsDigit);

        bool ok;
        string action;
        string? message = null;
        if (isAllDigits)
        {
            ok = _totp.Validate(user.TotpSecret, code);
            action = AuditActions.LoginMfa;
            if (!ok) message = "Invalid TOTP code.";
        }
        else
        {
            ok = await _users.ConsumeRecoveryCodeAsync(user, code);
            action = AuditActions.MfaRecoveryUsed;
            if (!ok) message = "Invalid recovery code.";
        }

        if (!ok)
        {
            await _users.RegisterFailedAttemptAsync(user);
            await _audit.LogAsync(action, null, false, message, userNameOverride: user.UserName);
            ErrorMessage = "Invalid code.";
            return Page();
        }

        // Success — promote the ticket to a real cookie auth session.
        Response.Cookies.Delete(MfaTicketService.CookieName);
        await LoginModel.SignInAsync(HttpContext, user);
        await _audit.LogAsync(action, null, true, userNameOverride: user.UserName);

        if (ticket.MustChangePassword)
            return RedirectToPage("/Account/ChangePassword", new { returnUrl = SafeReturnUrl(ticket.ReturnUrl) });

        return LocalRedirect(SafeReturnUrl(ticket.ReturnUrl));
    }

    public async Task<IActionResult> OnPostCancelAsync()
    {
        await ClearTicketAndSignOutAsync();
        return RedirectToPage("/Account/Login");
    }

    private MfaTicket? ReadTicket()
    {
        var token = Request.Cookies[MfaTicketService.CookieName];
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        return _tickets.TryValidate(token, ip);
    }

    private async Task ClearTicketAndSignOutAsync()
    {
        Response.Cookies.Delete(MfaTicketService.CookieName);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    private string SafeReturnUrl(string? r)
        => !string.IsNullOrEmpty(r) && Url.IsLocalUrl(r) ? r : (Url.Page("/Index") ?? "/");
}

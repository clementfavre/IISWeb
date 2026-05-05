using System.Security.Claims;
using IISWeb.Services;

namespace IISWeb.Middleware;

/// <summary>
/// Sends authenticated users with the MustChangePassword flag to /Account/ChangePassword
/// for any non-static, non-exempt request.
/// </summary>
public class MustChangePasswordMiddleware
{
    private static readonly string[] ExemptPaths =
    {
        "/Account/ChangePassword",
        "/Account/Logout",
        "/Account/Login",
        "/Account/LoginMfa",
        "/Account/AccessDenied",
        "/Error"
    };

    private readonly RequestDelegate _next;

    public MustChangePasswordMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx, IUserService users)
    {
        if (ctx.User?.Identity?.IsAuthenticated != true)
        {
            await _next(ctx);
            return;
        }

        var path = ctx.Request.Path.Value ?? string.Empty;
        if (IsExempt(path))
        {
            await _next(ctx);
            return;
        }

        var idStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!int.TryParse(idStr, out var id))
        {
            await _next(ctx);
            return;
        }

        var user = await users.FindByIdAsync(id);
        if (user is { MustChangePassword: true })
        {
            ctx.Response.Redirect("/Account/ChangePassword");
            return;
        }

        await _next(ctx);
    }

    private static bool IsExempt(string path)
    {
        foreach (var p in ExemptPaths)
            if (path.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}

public static class MustChangePasswordMiddlewareExtensions
{
    public static IApplicationBuilder UseMustChangePassword(this IApplicationBuilder app)
        => app.UseMiddleware<MustChangePasswordMiddleware>();
}

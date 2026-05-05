using System.Threading.RateLimiting;
using IISWeb;
using IISWeb.Configuration;
using IISWeb.Data;
using IISWeb.Middleware;
using IISWeb.Models;
using IISWeb.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// ----- Configuration -----
builder.Services.Configure<AppOptions>(builder.Configuration.GetSection(AppOptions.SectionName));
var appOptions = builder.Configuration.GetSection(AppOptions.SectionName).Get<AppOptions>() ?? new AppOptions();

// ----- SQLite path resolution -----
var sqlitePath = string.IsNullOrWhiteSpace(appOptions.SqlitePath)
    ? "App_Data/iisweb.db"
    : appOptions.SqlitePath;
var fullPath = Path.IsPathRooted(sqlitePath)
    ? sqlitePath
    : Path.Combine(builder.Environment.ContentRootPath, sqlitePath);
var dbDir = Path.GetDirectoryName(fullPath);
if (!string.IsNullOrEmpty(dbDir))
    Directory.CreateDirectory(dbDir);

builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseSqlite($"Data Source={fullPath};Foreign Keys=True"));

// ----- Identity primitives (just the password hasher) -----
builder.Services.AddSingleton<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>();

// ----- Authentication: cookie -----
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.ReturnUrlParameter = "ReturnUrl";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(Math.Max(5, appOptions.SessionTimeoutMinutes));
        options.SlidingExpiration = true;
        options.Cookie.Name = "IISWeb.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = appOptions.RequireHttps
            ? CookieSecurePolicy.Always
            : CookieSecurePolicy.SameAsRequest;
        options.Events.OnRedirectToLogin = ctx =>
        {
            // For non-HTML / API-style requests answer with 401 instead of redirect.
            var isApi = ctx.Request.Headers["Accept"].ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase);
            if (isApi || ctx.Request.Headers.XRequestedWith == "XMLHttpRequest")
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            }
            ctx.Response.Redirect(ctx.RedirectUri);
            return Task.CompletedTask;
        };
    });

// ----- Authorization: protect everything by default -----
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", p => p.RequireAuthenticatedUser().RequireRole(Roles.Admin));
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// ----- Antiforgery / CSRF -----
builder.Services.AddAntiforgery(opt =>
{
    opt.Cookie.Name = "IISWeb.Csrf";
    opt.Cookie.HttpOnly = true;
    opt.Cookie.SameSite = SameSiteMode.Strict;
    opt.Cookie.SecurePolicy = appOptions.RequireHttps
        ? CookieSecurePolicy.Always
        : CookieSecurePolicy.SameAsRequest;
    opt.HeaderName = "X-CSRF-TOKEN";
});

// ----- Rate limiting (login) -----
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("login", httpCtx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpCtx.Connection.RemoteIpAddress?.ToString() ?? "anon",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                Window = TimeSpan.FromMinutes(1),
                PermitLimit = 10,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});

// ----- Razor Pages -----
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AllowAnonymousToPage("/Account/Login");
    options.Conventions.AllowAnonymousToPage("/Account/AccessDenied");
    options.Conventions.AllowAnonymousToPage("/Error");
});

// ----- Forwarded headers (when behind IIS / proxy) -----
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    // Trust loopback only (IIS uses 127.0.0.1 to forward to ANCM out-of-process).
});

// ----- HTTPS settings -----
if (appOptions.RequireHttps)
{
    builder.Services.AddHsts(opt =>
    {
        opt.Preload = false;
        opt.IncludeSubDomains = true;
        opt.MaxAge = TimeSpan.FromDays(30);
    });
}

// ----- Application services -----
builder.Services.AddHttpContextAccessor();
builder.Services.AddDataProtection();
builder.Services.AddSingleton<ITotpService, TotpService>();
builder.Services.AddSingleton<MfaTicketService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IIisPoolService, IisPoolService>();

var app = builder.Build();

// ----- DB init / CLI seed-admin -----
using (var scope = app.Services.CreateScope())
{
    var sp = scope.ServiceProvider;
    var startupLogger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");

    if (CommandLine.IsCommand(args, out var cmd) && cmd == "seed-admin")
    {
        var db = sp.GetRequiredService<AppDbContext>();
        await db.Database.EnsureCreatedAsync();
        var users = sp.GetRequiredService<IUserService>();
        var exit = await CommandLine.SeedAdminAsync(users, args);
        return exit;
    }

    await DbInitializer.InitializeAsync(sp, startupLogger);
}

// ----- HTTP pipeline -----
app.UseForwardedHeaders();

// IP allow-list. Runs after UseForwardedHeaders so the client IP reflects
// X-Forwarded-For when the app sits behind a trusted proxy (loopback only,
// by default).
app.UseIpAllowList();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    if (appOptions.RequireHttps)
        app.UseHsts();
}

if (appOptions.RequireHttps)
    app.UseHttpsRedirection();

// Security headers (defence in depth on top of IIS configuration)
app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "no-referrer";
    h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=()";
    h["Cross-Origin-Opener-Policy"] = "same-origin";
    h["Cross-Origin-Resource-Policy"] = "same-origin";
    h["X-Permitted-Cross-Domain-Policies"] = "none";
    h["Content-Security-Policy"] =
        "default-src 'self'; " +
        "img-src 'self' data:; " +
        "style-src 'self' https://cdn.jsdelivr.net; " +
        "script-src 'self' https://cdn.jsdelivr.net; " +
        "font-src 'self' https://cdn.jsdelivr.net; " +
        "connect-src 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'";
    h.Remove("Server");
    h.Remove("X-Powered-By");
    await next(ctx);
});

app.UseStaticFiles();

app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseMustChangePassword();

app.MapRazorPages();

return await RunAsync(app);

static async Task<int> RunAsync(WebApplication app)
{
    await app.RunAsync();
    return 0;
}

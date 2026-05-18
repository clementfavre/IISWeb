# IISWeb security guide

How IISWeb is hardened and what the host needs to grant it. Read this before exposing the app.

IISWeb is meant to be reachable only from inside the VPN. Don't publish it on the public Internet, even if the auth looks solid. Defense in depth means not exposing what you don't have to.

## Threat model

The pieces being protected are the set of running App Pools (against unauthenticated browsing, non-Admin users, CSRF and replay), the audit trail (against tampering and reads from outside the VPN), and the local user database (against brute force, via rate limiting, lockouts and hashed passwords). The server filesystem and OS are out of scope since the app exposes no file or shell.

## Application Pool and account

Run IISWeb in its own dedicated Application Pool, never one that also serves other apps.

The .NET process needs to call the IIS configuration API (`Microsoft.Web.Administration.ServerManager`) and start, stop or recycle pools. By default only members of the local Administrators group on a server can do that.

### Recommended account

The preferred option is a custom local Windows account such as `iisweb-svc`, made a member of the local Administrators group on this server only. Deny "Log on locally", "Log on through Remote Desktop" and any network share access not strictly needed (use `secpol.msc` then User Rights Assignment), and set the App Pool identity to "Custom account" with this user. It still has admin rights, but the logon-type denies contain the blast radius.

A custom domain service account (`DOMAIN\svc-iisweb`) works the same way and is the right choice when AD password rotation is required.

The strictest model is `ApplicationPoolIdentity` with IIS configuration delegation, granting `system.applicationHost/applicationPools` to the virtual identity `IIS AppPool\IISWeb-AppPool` only. Delegation for App Pools isn't granular on most builds and usually requires custom ACLs via `appcmd.exe set config`. Only attempt this if you have time to test Start, Stop and Recycle on a non-prod pool first.

### NTFS permissions

The App Pool identity needs Read & Execute on `C:\inetpub\IISWeb\` and Modify on `C:\inetpub\IISWeb\App_Data\`. The managed wrapper under `%windir%\System32\inetsrv\` already grants Read & Execute to administrators by default.

```powershell
icacls "C:\inetpub\IISWeb\App_Data" `
    /inheritance:r `
    /grant:r "IIS AppPool\IISWeb-AppPool:(OI)(CI)M" `
    /grant:r "BUILTIN\Administrators:(OI)(CI)F" `
    /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F"
```

## Network and IIS configuration

HTTPS only. Bind only port 443. If port 80 is bound, configure IIS to return `301 Moved Permanently` with HSTS. IISWeb also enforces this from the app side when `App.RequireHttps` is true.

Restrict site bindings to an internal IP or hostname reachable through the VPN. Optionally add an IIS-level IP restriction limiting access to the VPN subnet. Disable directory browsing. Leave IIS site authentication on Anonymous only, since auth is handled by the app cookie and not by Windows auth.

## Application-level controls

These are enabled by default in `Program.cs` and the Razor Pages.

* `IpAllowListMiddleware` runs before auth, so off-list IPs never see the login page
* `FallbackPolicy = RequireAuthenticatedUser()`, with explicit `AllowAnonymousToPage` only on login and error
* Cookies are `HttpOnly`, `Secure` and `SameSite=Strict`
* Anti-CSRF via `AddAntiforgery`, tokens injected by tag helpers and validated on every POST
* `app.UseHttpsRedirection()` and `app.UseHsts()` in production when `RequireHttps` is true
* Login rate limit of 10 POST per minute per IP via `EnableRateLimiting("login")`
* Per-account lockout after `LoginMaxAttempts` for `LoginLockoutMinutes`
* Passwords stored with ASP.NET Core `PasswordHasher<TUser>` (PBKDF2-HMAC-SHA256, 100k+ iters, per-user salt), never logged
* Forced password change via `MustChangePassword` flag, which redirects to `/Account/ChangePassword`
* Optional TOTP MFA, RFC 6238 SHA1 30s 6 digits with one step tolerance, recovery codes stored hashed
* Two-step login uses a 5 min IP-pinned cookie protected by ASP.NET Data Protection
* Pool names validated server-side against `^[A-Za-z0-9 _\.\-]{1,64}$` and the whitelist
* `App.AllowedAppPools` is checked on List and on every Start, Stop or Recycle
* `RequireRole(Admin)` guards every pool action
* Defensive headers (CSP, X-Content-Type-Options, X-Frame-Options DENY, Referrer-Policy no-referrer, Permissions-Policy, COOP, CORP), and `Server` / `X-Powered-By` removed
* Native `confirm()` prompt on every Start, Stop and Recycle button

### IP allowlist (`App.AllowedIpRanges`)

A list of bare IPs or CIDR ranges. An empty list disables filtering. A non-empty list rejects any request whose `Connection.RemoteIpAddress` is not in the list with `403 Forbidden`, before the auth middleware runs. Unparseable entries are logged and ignored, and if every entry fails to parse the middleware fails closed and denies everything. The IP is read after `UseForwardedHeaders`, so behind IIS/ANCM the real client IP is used.

Treat this as a hardening layer on top of the VPN, not a replacement. Typical use is restricting access to the admin subnet or a single jump host inside an already-private network.

## Audit log

Every login (success or failure), MFA challenge, logout, pool action, password change, MFA enrol or disable, and user-management action writes a row into `AuditLog` in SQLite. Each row stores `TimestampUtc`, `UserName`, `IpAddress` (from the connection), `Action`, `AppPool` when relevant, `Success`, a free-text `Message` (never the password), and a `PrevHash` / `RowHash` pair.

Action values currently emitted are `Login`, `LoginMfa`, `MfaRecoveryUsed`, `Logout`, `Start`, `Stop`, `Recycle`, `PasswordChange`, `MfaEnable`, `MfaDisable`, `UserCreate`, `UserUpdate`, `UserDelete`, `UserResetPwd`, `UserUnlock`, `UserDisableMfa`.

### Tamper-evident chain

Each row stores the SHA-256 of the previous row's `RowHash` in `PrevHash`, and a `RowHash` computed over `PrevHash || canonical(fields)`. Inserting, deleting or editing a row breaks the chain at that row and every row after it.

The Audit log page has a `Verify chain integrity` button that recomputes the chain server-side and reports either intact (with the last row hash) or broken at row N. Operators should run this periodically, or script it. A chain that breaks when nobody added an entry means the SQLite file was touched directly.

The audit page is read-only and only authenticated users can view it. Back up `App_Data\iisweb.db` regularly if you need long-term retention.

## Operational practices

Place IISWeb behind the corporate VPN and do not put it behind a public reverse proxy just in case. Keep the Admin role in IISWeb to a very small group and use Viewer for read-only oversight. Rotate the App Pool service account password regularly and update the App Pool identity in IIS afterwards. Back up `App_Data/iisweb.db` along with the rest of the app. After the very first start, remove any `IISWEB_INITIAL_ADMIN_USER` and `IISWEB_INITIAL_ADMIN_PASS` env vars used to seed the admin. Forward the Windows Event Log for this server (including the `IISWeb` source and Microsoft-Windows-IIS-Configuration) to your SIEM, so pool changes are visible alongside the application audit.

## Known limitations

The app requires admin rights on IIS unless you set up IIS configuration delegation manually. Audit logs live in SQLite, so a host compromise with file access could tamper with them. Mitigate by streaming logs to a central server, since the app also writes every audit entry through `ILogger` and any standard log shipper can pick them up.

The CSP allows `cdn.jsdelivr.net` because Bootstrap is loaded from there. If the VPN blocks outbound HTTPS to that CDN, copy `bootstrap.min.css` and `bootstrap.bundle.min.js` into `wwwroot/lib/bootstrap/`, update both `_Layout.cshtml` references and the CSP `style-src`, `script-src` and `font-src` directives in `Program.cs`.

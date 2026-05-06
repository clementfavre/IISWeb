# IISWeb — Security guide

This document explains the security posture of IISWeb and the **minimum
privileges** required on the host. Read it before exposing the app.

## 1. Threat model

| Asset                            | Protected against                                           |
| -------------------------------- | ----------------------------------------------------------- |
| The set of running App Pools     | Unauthenticated browsing; non-Admin users; CSRF; replay     |
| Audit trail (SQLite)             | Tampering by random web users; reads from outside the VPN  |
| Local user database              | Brute force (rate limit, lockout, hashed passwords)         |
| Server filesystem / OS           | Directly *out of scope* — the app exposes no file or shell  |

The app is intended to be reachable only from inside the VPN. **Do not publish
it on the public Internet.** Even if the auth is solid, defense in depth means
"don't expose what you don't have to".

## 2. Application Pool & account for IISWeb itself

Run IISWeb in its **own dedicated Application Pool**, never in a pool that
also serves other applications.

The .NET process that hosts IISWeb needs to be allowed to call the IIS
configuration API (`Microsoft.Web.Administration.ServerManager`) and to start /
stop / recycle pools. By default, only members of the local **Administrators**
group can do that on a given server.

### Recommended account

Three patterns, in order of preference:

1. **Custom local Windows account** (e.g. `iisweb-svc`)
   - Member of the **local Administrators** group on this server only.
   - **Deny** "Log on locally", "Log on through Remote Desktop", and any
     network share access not strictly required (use `secpol.msc` ➝ User
     Rights Assignment).
   - Set the App Pool identity to "Custom account" with this user.
   - Pros: clear isolation, auditable name, no domain coupling.
   - Cons: still has admin rights — mitigated by Logon-type denies.

2. **Custom domain service account** (`DOMAIN\svc-iisweb`)
   - Member of local Administrators on the IISWeb host **only**.
   - Same logon-type denies as above.
   - Use when AD password rotation/policy is required.

3. **`ApplicationPoolIdentity` granted via IIS configuration delegation**
   - Use IIS *Feature Delegation* / `applicationHost.config` ACLs to delegate
     **only** the `system.applicationHost/applicationPools` section to the
     virtual identity `IIS AppPool\IISWeb-AppPool`.
   - This is the strictest model (no admin rights at all) but configuration
     delegation for App Pools is not granular enough on most builds and
     usually requires writing a custom ACL via `appcmd.exe set config`. Only
     attempt this if you have time to test it carefully.

> The **least privilege** chosen by this project is option 1 with logon-type
> denies. Option 3 is documented for completeness; if you adopt it, validate
> Start/Stop/Recycle on a non-prod pool first.

### NTFS permissions

The App Pool identity needs:

| Path                                           | Right         |
| ---------------------------------------------- | ------------- |
| `C:\inetpub\IISWeb\` (binaries)            | Read & Execute |
| `C:\inetpub\IISWeb\App_Data\` (SQLite)     | **Modify**    |
| `%windir%\System32\inetsrv\` (managed wrapper) | Read & Execute (granted to administrators by default) |

Sample ACL for `App_Data` (replace the identity name):

```powershell
icacls "C:\inetpub\IISWeb\App_Data" `
    /inheritance:r `
    /grant:r "IIS AppPool\IISWeb-AppPool:(OI)(CI)M" `
    /grant:r "BUILTIN\Administrators:(OI)(CI)F" `
    /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F"
```

## 3. Network / IIS configuration

- **HTTPS only**. Bind only port 443. If port 80 is bound, configure IIS to
  return `301 Moved Permanently` to the HTTPS URL with HSTS — IISWeb also
  enforces this from the application side when `App.RequireHttps = true`.
- Restrict the site bindings to internal IP / hostname reachable through the
  VPN.
- Optional: add an IIS-level IP restriction to the site to limit access to the
  VPN subnet.
- Disable directory browsing on this site.
- Make sure the IIS site authentication is set to **Anonymous only** at the IIS
  level. Application-level authentication is handled by the app cookie, not by
  Windows auth.

## 4. Application-level controls

The following are implemented by `Program.cs` and the Razor Pages and are
already enabled by default:

| Control                              | Mechanism                                                      |
| ------------------------------------ | -------------------------------------------------------------- |
| IP allow-list (network gate)         | `IpAllowListMiddleware`, runs before auth and pages             |
| All routes auth-required by default  | `FallbackPolicy = RequireAuthenticatedUser()`                  |
| Anonymous allowed only for login/error | Explicit `AllowAnonymousToPage`                              |
| Cookie security                      | `HttpOnly`, `Secure`, `SameSite=Strict`                        |
| Anti-CSRF                            | `AddAntiforgery` + tag-helper-injected tokens, validated on POST |
| HTTPS redirection                    | `app.UseHttpsRedirection()` when `RequireHttps=true`           |
| HSTS                                 | `app.UseHsts()` in production when `RequireHttps=true`         |
| Login rate limit                     | `EnableRateLimiting("login")`, 10 POST/min/IP                  |
| Account lockout                      | Per user: `LoginMaxAttempts` then `LoginLockoutMinutes`        |
| Password storage                     | ASP.NET Core `PasswordHasher<TUser>` (PBKDF2-HMAC-SHA256, 100k+ iters), per-user salt |
| Forced password change               | `MustChangePassword` flag => `/Account/ChangePassword` redirect |
| Optional MFA (TOTP)                  | RFC 6238 SHA1 30s/6 digits, ±1 step tolerance, hashed recovery codes |
| Two-step login session               | Step-1 result stored in a 5-min IP-pinned cookie protected by ASP.NET Data Protection |
| No password is logged                | Login form excludes Password from any logger / audit field     |
| Strict pool-name validation          | `^[A-Za-z0-9 _\.\-]{1,64}$` server-side, plus whitelist check  |
| Whitelist enforcement                | `App.AllowedAppPools` checked on List **and** on every action  |
| Authorization                        | `RequireRole(Admin)` on Start/Stop/Recycle                     |
| Defensive HTTP headers               | CSP, X-Content-Type-Options, X-Frame-Options=DENY, Referrer-Policy=no-referrer, Permissions-Policy, COOP, CORP, removes `Server`/`X-Powered-By` |
| Confirmation prompts                 | Native `confirm()` on every Start / Stop / Recycle button      |

### IP allow-list (`App.AllowedIpRanges`)

Configured as a list of bare IPs or CIDR ranges. Behaviour:

- empty list => no filtering (default);
- non-empty list => every request whose `Connection.RemoteIpAddress` is not in
  the list is rejected with `403 Forbidden` before the auth middleware even
  runs (so even the login page is hidden);
- entries that fail to parse are logged and ignored;
- if **all** entries fail to parse the middleware fails closed (denies all);
- the IP is read after `UseForwardedHeaders`, so behind IIS/ANCM the real
  client IP is used.

Use this as a hardening layer **on top of** the VPN, not as a replacement —
e.g. limit access to the subnet your admins use to connect to the VPN, or to
a single jump host.

## 5. Audit log

Every login (success/failure), MFA challenge, logout, pool action, password
change, MFA enrol/disable, and user-management action writes a row into
`AuditLog` (SQLite). The fields stored are:

- `TimestampUtc`
- `UserName`
- `IpAddress` (from the connection)
- `Action` (`Login`, `LoginMfa`, `MfaRecoveryUsed`, `Logout`, `Start`, `Stop`,
  `Recycle`, `PasswordChange`, `MfaEnable`, `MfaDisable`, `UserCreate`,
  `UserUpdate`, `UserDelete`, `UserResetPwd`, `UserUnlock`, `UserDisableMfa`)
- `AppPool` (when relevant)
- `Success` (boolean)
- `Message` (free-text, e.g. error message — never contains the password)
- `PrevHash`, `RowHash` — see below.

### Tamper-evident chain

Each row stores the SHA-256 of the previous row's `RowHash` in `PrevHash`,
and a `RowHash` computed over `PrevHash || canonical(fields)`. Inserting,
deleting or editing a row breaks the chain at that row and at every row
after it.

The **Audit log** page exposes a `Verify chain integrity` button that
recomputes the chain server-side and reports either *intact* with the last
row hash, or *broken at row N*. Operators should run this periodically (or
script it) — if the chain is broken when nobody added an entry, the SQLite
file has been touched directly.

The audit page is read-only and only authenticated users can view it. Back up
`App_Data\iisweb.db` regularly if you need long-term retention.

## 6. Recommended operational practices

- Place IISWeb behind the corporate VPN. Do not expose it through a
  reverse proxy on the Internet "just in case".
- Restrict who has Admin in IISWeb to a very small group — keep `Viewer`
  for read-only oversight (extend role checks as you add users).
- Rotate the IISWeb App Pool service account password regularly. After
  rotation, update the App Pool identity in IIS.
- Backup `App_Data/iisweb.db` together with the rest of the application.
- After the very first start, **remove** any
  `IISWEB_INITIAL_ADMIN_USER` / `IISWEB_INITIAL_ADMIN_PASS` env vars
  you used to seed the admin.
- Enable Windows Event Log forwarding from this server to your SIEM, including
  the `IISWeb` source and Microsoft-Windows-IIS-Configuration logs, so
  pool changes are visible alongside the application audit.

## 7. Known limitations

- The application requires admin rights on IIS unless you implement IIS
  configuration delegation manually (option 3 in §2).
- Audit logs are stored locally in SQLite, if the host is compromised, an
  attacker with file access could tamper with them. Mitigate by streaming logs
  to a central log server (the application also writes each audit entry through
  `ILogger`, so any standard log shipper can pick them up).
- The CSP allows `cdn.jsdelivr.net` because Bootstrap is loaded from there. If
  the VPN does not allow outbound HTTPS to that CDN, copy
  `bootstrap.min.css` and `bootstrap.bundle.min.js` into
  `wwwroot/lib/bootstrap/` and update both `_Layout.cshtml` references and the
  CSP `style-src` / `script-src` / `font-src` directives in `Program.cs`.

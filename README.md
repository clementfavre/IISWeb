# IISWeb

Small web app to **start, stop or recycle IIS Application Pools** from a UI
that works fine on a phone. Handy when an old site needs a quick kick and
you're not in front of a desk

Runs on the same Windows Server / IIS that hosts the pools. Usually accessed
through a VPN. If not, make sure you protect it some other way
(firewall, IP allowlist, reverse proxy auth).

The scope is intentionally narrow:

| Allowed                                          | Refused (out of scope)                       |
| ------------------------------------------------ | -------------------------------------------- |
| List Application Pools (whitelisted)             | Sites, bindings, virtual directories         |
| Start / Stop / Recycle a pool                    | Creating or deleting pools / sites           |
| Audit log (read only, tamper-evident)            | Editing files, web shell, server reboot      |
| Manage local users (create / role / reset / lock)| External identity providers (AD, OIDC)       |
| Per-user TOTP MFA (RFC 6238)                     | Hardware tokens / WebAuthn                   |

Tech stack: ASP.NET Core 10 (LTS), Razor Pages, EF Core + SQLite, cookie auth,
`Microsoft.Web.Administration`, Bootstrap 5.

---

## 1. Build

Prerequisites on the build host:

- .NET 10 SDK
- Windows with IIS (or IIS Management Tools) installed, provides
  `Microsoft.Web.Administration.dll`

```powershell
dotnet restore
dotnet publish -c Release -r win-x64 --self-contained false -o .\publish
```

`publish/` is what you copy to the server.

## 2. Install on IIS

1. Install the **.NET 10 Hosting Bundle** on the server
   (it ships the `AspNetCoreModuleV2` IIS module).
2. Create a folder, e.g. `C:\inetpub\IISWeb`, and copy the `publish/` content
   into it.
3. Create a dedicated Application Pool, e.g. **`IISWeb-AppPool`**:
   - .NET CLR version: **No Managed Code**
   - Pipeline: Integrated
   - Identity: see [README-SECURITY.md](README-SECURITY.md) for the recommended
     account and minimum privileges.
4. Create a Site or Application bound to that pool:
   - Physical path: `C:\inetpub\IISWeb`
   - Bindings: HTTPS only (port 443) with a valid certificate. HTTP can also be
     bound to issue a 301 redirect.
   - Hostname: an internal-only DNS name reachable through the VPN only.
5. Grant **modify** rights on the `App_Data\` subfolder to the App Pool identity
   so it can create/update the SQLite file:

   ```powershell
   icacls "C:\inetpub\IISWeb\App_Data" /grant "IIS AppPool\IISWeb-AppPool:(OI)(CI)M"
   ```

   (Replace the App Pool name if you used a different one, or use the actual
   service account name.)
6. Edit `appsettings.Production.json` — see `appsettings.Example.json` for the
   shape — and set:
   - `App.AllowedAppPools` (whitelist)
   - `App.RequireHttps = true`
   - any other tuning

## 3. Create the initial admin

Two equivalent options.

### Option A — CLI (recommended for production)

Run from a Windows shell, on the server, **logged in as an Administrator**:

```powershell
cd C:\inetpub\IISWeb
.\IISWeb.exe seed-admin --username alice
# password is asked interactively (not echoed)
```

Password must be at least 12 characters. Re-running the command for the same
username fails.

### Option B — environment variables (one-shot, first start)

If the database has no users when the app starts, IISWeb reads:

- `IISWEB_INITIAL_ADMIN_USER`
- `IISWEB_INITIAL_ADMIN_PASS`

…and creates that admin once. Set these on the App Pool (Advanced Settings =>
Environment Variables on IIS 10+, or `web.config`/`environmentVariables`),
then **remove them after the first successful start**.

## 4. Configuration reference (`appsettings.json`)

```jsonc
{
  "App": {
    "AllowedAppPools": ["DefaultAppPool", "MyApp"],
    "AllowedIpRanges": ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1", "::1"],
    "LoginMaxAttempts": 5,
    "LoginLockoutMinutes": 15,
    "RequireHttps": true,
    "SqlitePath": "App_Data/iisweb.db",
    "SessionTimeoutMinutes": 60
  }
}
```

| Key                       | Purpose                                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------------------------- |
| `AllowedAppPools`         | Whitelist of pool names the app may see and act on. Empty array = all pools (not recommended in prod).   |
| `AllowedIpRanges`         | IP allow-list (single IPs or CIDR). Empty array disables filtering. See §6 below.                        |
| `LoginMaxAttempts`        | Failed logins per account before lockout.                                                                |
| `LoginLockoutMinutes`     | Lockout duration in minutes.                                                                             |
| `RequireHttps`            | Forces HTTPS redirection and `Secure` cookies. Set `false` only for local HTTP dev.                      |
| `SqlitePath`              | Path to the SQLite file (relative paths are relative to the content root).                               |
| `SessionTimeoutMinutes`   | Auth cookie sliding expiration in minutes.                                                               |

A separate global rate-limit of 10 login POSTs per minute per IP is applied at
the framework level.

### IP allow-list

`App.AllowedIpRanges` is checked **before** authentication. Any request whose
remote IP is not in the list receives `403 Forbidden` with no body. Even the
login page is invisible. Accepts both bare IPs and CIDR:

```jsonc
"AllowedIpRanges": [
  "127.0.0.1",          // loopback
  "::1",                // IPv6 loopback
  "10.20.30.0/24",      // VPN client subnet
  "10.20.31.40"         // a single jump host
]
```

- An empty array disables the filter (default).
- Invalid entries are logged and ignored.
- If **all** entries are invalid the middleware fails closed (denies everything).
- The check runs after `UseForwardedHeaders`, so when the app is behind a
  trusted proxy / IIS the original client IP is used. If you place an external
  reverse proxy in front, make sure to whitelist its rewriting behaviour and
  the proxy's network in the trusted-proxies section of `Program.cs`.

This is **complementary** to the VPN, not a replacement: it lets you scope the
service to a specific admin subnet inside an already-private network.

## 5. Using the app

- Navigate to the HTTPS hostname over the VPN.
- Sign in. If MFA is enabled on your account, enter the 6-digit code from your
  authenticator app (or one of your recovery codes).
- The home page lists the whitelisted pools. Each card shows the current state
  and (for **Admin** users) Start / Stop / Recycle buttons. Buttons disabled
  when irrelevant for the current state.
- Every action is auditable in **Audit log**. The audit chain can be verified
  for tampering from that page.

### Two-factor authentication

Each user can enrol in TOTP MFA from the user-menu => **Two-factor**:

1. Click **Enable MFA**, scan the QR code with Google Authenticator,
   Microsoft Authenticator, 1Password, Bitwarden or any RFC 6238 app.
2. Enter the first code to confirm.
3. **Save the 10 recovery codes** shown only once. Each code can be used as a
   one-time replacement for an authenticator code if the device is lost.

To disable MFA, the user must enter their current password **and** a current
TOTP code. An Admin can disable a user's MFA from `Users => Edit`.

### User management (Admin)

`Users` (visible to Admins only) allows: create user, change role, reset
password (the user is forced to change it on next sign-in), unlock locked
accounts, disable MFA (admin override), delete user. Last-Admin and self-delete
guards are enforced.

## 6. Authorization model

- **Admin**: sees pools and can Start / Stop / Recycle. Manages users.
- **Viewer**: sees pools and audit log but cannot act on pools.

## 7. Files & layout

```
IISWeb/
├── IISWeb.csproj
├── Program.cs                 # pipeline, auth, antiforgery, rate limit, CSP
├── CommandLine.cs             # `seed-admin` CLI handler
├── appsettings*.json          # configuration (Example, Development)
├── web.config                 # IIS / ANCM hosting config
├── Configuration/AppOptions.cs
├── Models/                    # AppUser, Roles, AuditLog, AuditActions
├── Data/                      # AppDbContext, DbInitializer
├── Services/                  # IUserService, IAuditService, IIisPoolService
├── Pages/
│   ├── Account/Login + Logout + AccessDenied
│   ├── Index   (pools)
│   ├── Audit
│   ├── Error
│   └── Shared/_Layout.cshtml
└── wwwroot/                   # css / js (Bootstrap from CDN)
```

## 8. Local development

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
dotnet run
# in another shell, seed an admin:
dotnet run -- seed-admin --username admin --password ChooseAStrongPwd!
```

`appsettings.Development.json` disables HTTPS so the app works on plain HTTP
during development. **Never** ship `RequireHttps=false` to production.

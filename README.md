# IISWeb

A tiny web app to start, stop or recycle IIS Application Pools from a mobile-friendly UI. Handy when an old site needs a quick kick and you're not in front of a desk

Runs on the same Windows Server that hosts the pools, usually behind a VPN

## Features

* Start, stop and recycle whitelisted App Pools
* Mobile-friendly UI built on Bootstrap 5
* Cookie auth with account lockout and login rate limiting
* Optional TOTP two-factor with recovery codes
* IP allowlist (single IPs or CIDR) checked before login
* Tamper-evident audit log of every action
* SQLite, no external database to host

Out of scope: site or binding management, pool creation or deletion, file editing, web shell, server reboot

## Quick start

Grab the latest zip from the [Releases](https://github.com/D0LBA3B/IISWeb/releases) page.

Install the .NET 10 Hosting Bundle on the server, unzip the release into `C:\inetpub\IISWeb`, then create an IIS Site bound to a dedicated App Pool (No Managed Code, integrated pipeline).

Give the App Pool identity write access to `App_Data`.

```powershell
icacls "C:\inetpub\IISWeb\App_Data" /grant "IIS AppPool\IISWeb-AppPool:(OI)(CI)M"
```

Edit `appsettings.Production.json` from `appsettings.Example.json` and at minimum set `App.AllowedAppPools` and `App.RequireHttps` to true.

Seed the first admin from a Windows shell on the server.

```powershell
.\IISWeb.exe seed-admin --username alice
```

Browse to the HTTPS hostname, sign in, and you're done.

See [README-SECURITY.md](README-SECURITY.md) for the recommended service account and minimum privileges.

## Configuration

```jsonc
{
  "App": {
    "AllowedAppPools": ["DefaultAppPool", "MyApp"],
    "AllowedIpRanges": ["10.0.0.0/8", "127.0.0.1", "::1"],
    "LoginMaxAttempts": 5,
    "LoginLockoutMinutes": 15,
    "RequireHttps": true,
    "SqlitePath": "App_Data/iisweb.db",
    "SessionTimeoutMinutes": 60
  }
}
```

`AllowedAppPools` is the whitelist of pools visible from the UI. An empty array means all pools, which is fine in dev but not recommended in production.

`AllowedIpRanges` runs before authentication, so any IP outside the list gets a `403` without seeing the login page. An empty array disables the filter.

## Development

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
dotnet run
dotnet run -- seed-admin --username admin --password ChooseAStrongPwd!
```

`appsettings.Development.json` ships with HTTPS turned off so the app works over plain HTTP locally. Never push `RequireHttps=false` to production.

## Build from source

```powershell
dotnet publish -c Release -r win-x64 --self-contained false -o .\publish
```

The `publish/` folder is what gets zipped into a release.

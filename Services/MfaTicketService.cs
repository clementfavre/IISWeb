using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.DataProtection;

namespace IISWeb.Services;

public record MfaTicket(int UserId, string UserName, string Ip, DateTime ExpiresUtc, bool MustChangePassword, string? ReturnUrl);

/// <summary>
/// Encrypted, short-lived blob proving a user passed step 1 of login. Stored
/// in a cookie until the TOTP code is verified or the ticket expires (5 min).
/// </summary>
public class MfaTicketService
{
    public const string CookieName = "IISWeb.Mfa";
    private const string Purpose = "IISWeb.MfaTicket.v1";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private readonly IDataProtector _protector;

    public MfaTicketService(IDataProtectionProvider provider)
        => _protector = provider.CreateProtector(Purpose);

    public string Issue(int userId, string userName, string ip, bool mustChangePassword, string? returnUrl)
    {
        var expires = DateTime.UtcNow.Add(Lifetime);
        // pipe-separated; user names are <=64 ASCII (validated upstream).
        var payload = string.Join('|',
            userId.ToString(CultureInfo.InvariantCulture),
            userName,
            NormalizeIp(ip),
            expires.ToString("O", CultureInfo.InvariantCulture),
            mustChangePassword ? "1" : "0",
            returnUrl ?? string.Empty);
        return _protector.Protect(payload);
    }

    public MfaTicket? TryValidate(string? token, string currentIp)
    {
        if (string.IsNullOrEmpty(token)) return null;

        string raw;
        try { raw = _protector.Unprotect(token); }
        catch { return null; }

        var parts = raw.Split('|');
        if (parts.Length < 5) return null;

        if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var id))
            return null;
        if (!DateTime.TryParse(parts[3], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var expires))
            return null;
        if (expires < DateTime.UtcNow) return null;

        // IP-pinning: a stolen ticket replayed from another IP is rejected.
        // Normalise IPv4-mapped-IPv6 (::ffff:127.0.0.1) so a Kestrel switch
        // between IPv4 and IPv6 loopback between two POSTs does not lock the user out.
        if (!string.Equals(parts[2], NormalizeIp(currentIp), StringComparison.Ordinal)) return null;

        var must = parts[4] == "1";
        var ret = parts.Length > 5 ? parts[5] : null;
        return new MfaTicket(id, parts[1], parts[2], expires, must, string.IsNullOrEmpty(ret) ? null : ret);
    }

    private static string NormalizeIp(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return raw;
        if (!IPAddress.TryParse(raw, out var ip)) return raw;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString();
    }
}

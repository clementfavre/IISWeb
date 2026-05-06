using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using IISWeb.Data;
using IISWeb.Models;
using Microsoft.EntityFrameworkCore;

namespace IISWeb.Services;

public class AuditService : IAuditService
{
    private readonly AppDbContext _db;
    private readonly IHttpContextAccessor _http;
    private readonly ILogger<AuditService> _logger;

    // Serialise inserts so the chain can't fork under concurrent requests.
    private static readonly SemaphoreSlim _chainLock = new(1, 1);

    public AuditService(AppDbContext db, IHttpContextAccessor http, ILogger<AuditService> logger)
    {
        _db = db;
        _http = http;
        _logger = logger;
    }

    public IQueryable<AuditLog> Query() =>
        _db.AuditLogs.AsNoTracking().OrderByDescending(a => a.TimestampUtc);

    public async Task LogAsync(string action, string? appPool, bool success, string? message = null, string? userNameOverride = null)
    {
        await _chainLock.WaitAsync();
        try
        {
            var ctx = _http.HttpContext;
            string? ip = ctx?.Connection.RemoteIpAddress?.ToString();
            string? user = userNameOverride ?? ctx?.User?.Identity?.Name;

            var entry = new AuditLog
            {
                TimestampUtc = DateTime.UtcNow,
                UserName = Truncate(user, 64),
                IpAddress = Truncate(ip, 64),
                Action = Truncate(action ?? "Unknown", 64)!,
                AppPool = Truncate(appPool, 128),
                Success = success,
                Message = Truncate(message, 512)
            };

            var prev = await _db.AuditLogs
                .AsNoTracking()
                .OrderByDescending(a => a.Id)
                .Select(a => new { a.RowHash })
                .FirstOrDefaultAsync();

            entry.PrevHash = prev?.RowHash ?? string.Empty;
            entry.RowHash = ComputeRowHash(entry);

            _db.AuditLogs.Add(entry);
            await _db.SaveChangesAsync();

            _logger.LogInformation(
                "AUDIT user={User} ip={Ip} action={Action} pool={Pool} success={Success} msg={Message} hash={Hash}",
                entry.UserName, entry.IpAddress, entry.Action, entry.AppPool, entry.Success, entry.Message, entry.RowHash);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write audit log entry.");
        }
        finally
        {
            _chainLock.Release();
        }
    }

    public async Task<AuditChainStatus> VerifyChainAsync(CancellationToken ct = default)
    {
        var rows = await _db.AuditLogs
            .AsNoTracking()
            .OrderBy(a => a.Id)
            .ToListAsync(ct);

        string expectedPrev = string.Empty;
        foreach (var r in rows)
        {
            if (r.PrevHash != expectedPrev)
                return new AuditChainStatus(false, r.Id, rows.Count, rows[^1].RowHash);

            var recomputed = ComputeRowHash(r);
            if (!string.Equals(recomputed, r.RowHash, StringComparison.OrdinalIgnoreCase))
                return new AuditChainStatus(false, r.Id, rows.Count, rows[^1].RowHash);

            expectedPrev = r.RowHash;
        }

        return new AuditChainStatus(true, null, rows.Count, rows.Count > 0 ? rows[^1].RowHash : null);
    }

    /// <summary>
    /// Canonical SHA-256 over PrevHash || tab-separated fields. The format is
    /// stable so a future external verifier can recompute it.
    /// </summary>
    internal static string ComputeRowHash(AuditLog e)
    {
        var canonical = string.Join("\t",
            e.PrevHash,
            e.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
            e.UserName ?? string.Empty,
            e.IpAddress ?? string.Empty,
            e.Action,
            e.AppPool ?? string.Empty,
            e.Success ? "1" : "0",
            e.Message ?? string.Empty);

        var bytes = Encoding.UTF8.GetBytes(canonical);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }

    private static string? Truncate(string? s, int max)
        => string.IsNullOrEmpty(s) ? s : (s.Length > max ? s[..max] : s);
}

using IISWeb.Models;

namespace IISWeb.Services;

public record AuditChainStatus(bool IsIntact, int? FirstBrokenId, long TotalRows, string? LastRowHash);

public interface IAuditService
{
    Task LogAsync(string action, string? appPool, bool success, string? message = null, string? userNameOverride = null);
    IQueryable<AuditLog> Query();
    Task<AuditChainStatus> VerifyChainAsync(CancellationToken ct = default);
}

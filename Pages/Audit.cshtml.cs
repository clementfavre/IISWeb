using IISWeb.Models;
using IISWeb.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IISWeb.Pages;

public class AuditModel : PageModel
{
    private readonly IAuditService _audit;

    public AuditModel(IAuditService audit) { _audit = audit; }

    public List<AuditLog> Logs { get; private set; } = new();
    public int CurrentPage { get; private set; } = 1;
    public int PageSize { get; } = 50;
    public int TotalPages { get; private set; } = 1;
    public AuditChainStatus? ChainStatus { get; private set; }

    public async Task OnGetAsync(int? p, bool verify)
    {
        CurrentPage = p is null || p < 1 ? 1 : p.Value;

        var q = _audit.Query();
        var total = await q.CountAsync();
        TotalPages = total == 0 ? 1 : (int)Math.Ceiling(total / (double)PageSize);

        if (CurrentPage > TotalPages) CurrentPage = TotalPages;

        Logs = await q
            .Skip((CurrentPage - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync();

        if (verify)
            ChainStatus = await _audit.VerifyChainAsync();
    }
}

using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Admin;
using Auth.Domain.Audit;
using Auth.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Services;

internal sealed class AuditReader(AppDbContext db) : IAuditReader
{
    public async Task<Result<PagedResult<AuditEventDto>>> QueryAsync(AuditQuery query, CancellationToken cancellationToken)
    {
        var (page, pageSize) = Paging.Normalize(query.Page, query.PageSize);
        var events = db.AuditEvents.AsNoTracking();

        if (query.UserId is { } userId)
        {
            events = events.Where(e => e.UserId == userId);
        }

        if (!string.IsNullOrWhiteSpace(query.Type))
        {
            if (!Enum.TryParse<AuditEventType>(query.Type, ignoreCase: true, out var type) || !Enum.IsDefined(type))
            {
                return Error.Validation(new Dictionary<string, string[]> { ["type"] = [$"Unknown audit event type '{query.Type}'."] });
            }

            events = events.Where(e => e.Type == type);
        }

        if (query.From is { } from)
        {
            var f = DateTime.SpecifyKind(from.ToUniversalTime(), DateTimeKind.Utc);
            events = events.Where(e => e.OccurredAt >= f);
        }

        if (query.To is { } to)
        {
            var t = DateTime.SpecifyKind(to.ToUniversalTime(), DateTimeKind.Utc);
            events = events.Where(e => e.OccurredAt <= t);
        }

        var total = await events.CountAsync(cancellationToken);
        var items = await events
            .OrderByDescending(e => e.OccurredAt).ThenByDescending(e => e.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(e => new AuditEventDto(e.Id, e.OccurredAt, e.Type.ToString(), e.UserId, e.ActorUserId, e.SessionId, e.Email, e.IpAddress, e.UserAgent, e.Success, e.Details))
            .ToListAsync(cancellationToken);

        return new PagedResult<AuditEventDto>(items, page, pageSize, total);
    }
}

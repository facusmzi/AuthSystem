using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Sessions;
using Auth.Domain.Audit;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Persistence;
using Auth.Infrastructure.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Services;

internal sealed record CreatedSession(Session Session, string? RefreshToken);

internal sealed class SessionService(
    AppDbContext db,
    ISessionValidator validator,
    IClientInfo client,
    IAuditLogger audit,
    TimeProvider time,
    IOptions<UserSessionOptions> options) : ISessionService
{
    private DateTime UtcNow => time.GetUtcNow().UtcDateTime;

    internal async Task<CreatedSession> CreateAsync(Guid userId, SessionKind kind, LoginMethod method, CancellationToken cancellationToken)
    {
        var refreshToken = kind == SessionKind.Bearer ? RefreshTokenGenerator.Generate() : null;
        var session = Session.Create(
            userId,
            kind,
            method,
            refreshToken is null ? null : RefreshTokenGenerator.Hash(refreshToken),
            client.IpAddress,
            client.UserAgent,
            UtcNow,
            options.Value.Sliding,
            options.Value.Absolute);

        db.Sessions.Add(session);
        await db.SaveChangesAsync(cancellationToken);
        return new CreatedSession(session, refreshToken);
    }

    public async Task<IReadOnlyList<SessionDto>> ListActiveAsync(Guid userId, Guid? currentSessionId, CancellationToken cancellationToken)
    {
        var now = UtcNow;
        var sessions = await db.Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now && s.AbsoluteExpiresAt > now)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(cancellationToken);

        return sessions.Select(s => ToDto(s, currentSessionId)).ToList();
    }

    public async Task<Result<RevokeSessionResponse>> RevokeOwnAsync(Guid userId, Guid sessionId, Guid? currentSessionId, CancellationToken cancellationToken)
    {
        var now = UtcNow;
        var exists = await db.Sessions.AnyAsync(
            s => s.Id == sessionId && s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now && s.AbsoluteExpiresAt > now,
            cancellationToken);
        if (!exists)
        {
            return Error.NotFound("Session not found.");
        }

        var wasCurrent = sessionId == currentSessionId;
        await RevokeAsync(sessionId, RevocationReason.Logout, cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.SessionRevoked, true, userId, SessionId: sessionId,
            Details: new Dictionary<string, object?> { ["wasCurrent"] = wasCurrent }), cancellationToken);
        return new RevokeSessionResponse(wasCurrent);
    }

    public async Task<bool> RevokeAsync(Guid sessionId, RevocationReason reason, CancellationToken cancellationToken)
    {
        var now = UtcNow;
        var affected = await db.Sessions
            .Where(s => s.Id == sessionId && s.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.RevokedAt, now)
                .SetProperty(x => x.RevokedReason, reason), cancellationToken);
        validator.Invalidate(sessionId);
        return affected > 0;
    }

    public async Task<int> RevokeAllAsync(Guid userId, RevocationReason reason, Guid? exceptSessionId, CancellationToken cancellationToken)
    {
        var now = UtcNow;
        var query = db.Sessions.Where(s => s.UserId == userId && s.RevokedAt == null);
        if (exceptSessionId is { } except)
        {
            query = query.Where(s => s.Id != except);
        }

        var ids = await query.Select(s => s.Id).ToListAsync(cancellationToken);
        if (ids.Count == 0)
        {
            return 0;
        }

        var affected = await db.Sessions
            .Where(s => ids.Contains(s.Id) && s.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.RevokedAt, now)
                .SetProperty(x => x.RevokedReason, reason), cancellationToken);

        foreach (var id in ids)
        {
            validator.Invalidate(id);
        }

        return affected;
    }

    public async Task LogoutAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken)
    {
        await RevokeAsync(sessionId, RevocationReason.Logout, cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.Logout, true, userId, SessionId: sessionId), cancellationToken);
    }

    public async Task LogoutAllAsync(Guid userId, Guid? currentSessionId, CancellationToken cancellationToken)
    {
        var count = await RevokeAllAsync(userId, RevocationReason.LogoutAll, exceptSessionId: null, cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.LogoutAll, true, userId, SessionId: currentSessionId,
            Details: new Dictionary<string, object?> { ["revoked"] = count }), cancellationToken);
    }

    internal static SessionDto ToDto(Session s, Guid? currentSessionId) => new(
        s.Id,
        s.Kind.ToString(),
        s.LoginMethod.ToString(),
        s.IpAddress,
        s.UserAgent,
        s.CreatedAt,
        s.LastSeenAt,
        s.ExpiresAt,
        s.Id == currentSessionId);
}

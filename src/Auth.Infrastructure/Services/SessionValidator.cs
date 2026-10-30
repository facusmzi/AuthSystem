using Auth.Application.Abstractions;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Caching;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Verifica que la sesión exista, pertenezca al usuario, no esté revocada ni vencida y que el usuario no
/// esté bloqueado por un administrador. Cachea solo resultados positivos. Singleton.
/// </summary>
internal sealed class SessionValidator(
    IDbContextFactory<AppDbContext> dbFactory,
    TimedCache cache,
    TimeProvider time,
    IOptions<UserSessionOptions> options) : ISessionValidator
{
    public async Task<SessionValidationResult> ValidateAsync(Guid sessionId, Guid userId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow().UtcDateTime;
        if (cache.TryGet<CachedSession>(Key(sessionId), out var cached))
        {
            return cached.UserId == userId && cached.ExpiresAt > now && cached.AbsoluteExpiresAt > now
                ? SessionValidationResult.Valid
                : SessionValidationResult.Invalid;
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var row = await db.Sessions.AsNoTracking()
            .Where(s => s.Id == sessionId)
            .Join(db.Users, s => s.UserId, u => u.Id, (s, u) => new
            {
                s.UserId,
                s.Kind,
                s.LastSeenAt,
                s.ExpiresAt,
                s.AbsoluteExpiresAt,
                s.RevokedAt,
                u.LockoutEnd,
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (row is null
            || row.UserId != userId
            || row.RevokedAt is not null
            || row.ExpiresAt <= now
            || row.AbsoluteExpiresAt <= now
            || AccountLockout.IsAdminLocked(row.LockoutEnd))
        {
            return SessionValidationResult.Invalid;
        }

        var o = options.Value;
        var expiresAt = row.ExpiresAt;
        if (now - row.LastSeenAt >= o.LastSeenUpdate)
        {
            // Las sesiones cookie se deslizan con el uso; las Bearer se deslizan al refrescar.
            if (row.Kind == SessionKind.Cookie)
            {
                var slid = now + o.Sliding;
                expiresAt = slid < row.AbsoluteExpiresAt ? slid : row.AbsoluteExpiresAt;
            }

            await db.Sessions
                .Where(s => s.Id == sessionId && s.RevokedAt == null)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(x => x.LastSeenAt, now)
                    .SetProperty(x => x.ExpiresAt, expiresAt), cancellationToken);
        }

        if (o.ValidationCache > TimeSpan.Zero)
        {
            cache.Set(Key(sessionId), new CachedSession(row.UserId, expiresAt, row.AbsoluteExpiresAt), o.ValidationCache);
        }

        return SessionValidationResult.Valid;
    }

    public void Invalidate(Guid sessionId) => cache.Remove(Key(sessionId));

    private static string Key(Guid sessionId) => $"session:{sessionId:N}";

    private sealed record CachedSession(Guid UserId, DateTime ExpiresAt, DateTime AbsoluteExpiresAt);
}

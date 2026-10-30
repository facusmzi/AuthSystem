using Auth.Application.Abstractions;
using Auth.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Resuelve roles y permisos efectivos (unión de los permisos de todos los roles del usuario).
/// Cache de 5 min por usuario; se invalida por usuario al cambiar sus roles y globalmente al cambiar un rol.
/// </summary>
internal sealed class PermissionService(IDbContextFactory<AppDbContext> dbFactory, IMemoryCache cache, PermissionCacheVersion version)
    : IPermissionService
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    public async Task<IReadOnlySet<string>> GetPermissionsAsync(Guid userId, CancellationToken cancellationToken) =>
        (await GetAsync(userId, cancellationToken)).Permissions;

    public async Task<IReadOnlyList<string>> GetRolesAsync(Guid userId, CancellationToken cancellationToken) =>
        (await GetAsync(userId, cancellationToken)).Roles;

    public void InvalidateUser(Guid userId) => cache.Remove(Key(userId));

    public void InvalidateAll() => version.Reset();

    private async Task<Entry> GetAsync(Guid userId, CancellationToken cancellationToken)
    {
        if (cache.TryGetValue(Key(userId), out Entry? cached) && cached is not null)
        {
            return cached;
        }

        var token = version.Token;
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var roleIds = db.UserRoles.Where(ur => ur.UserId == userId).Select(ur => ur.RoleId);

        var roles = await db.Roles
            .Where(r => roleIds.Contains(r.Id))
            .Select(r => r.Name!)
            .OrderBy(n => n)
            .ToListAsync(cancellationToken);

        var permissions = await db.RolePermissions
            .Where(p => roleIds.Contains(p.RoleId))
            .Select(p => p.Permission)
            .Distinct()
            .ToListAsync(cancellationToken);

        var entry = new Entry(roles, permissions.ToHashSet(StringComparer.Ordinal));
        using var cacheEntry = cache.CreateEntry(Key(userId));
        cacheEntry.Value = entry;
        cacheEntry.AbsoluteExpirationRelativeToNow = Ttl;
        cacheEntry.AddExpirationToken(token);
        return entry;
    }

    private static string Key(Guid userId) => $"permissions:{userId:N}";

    private sealed record Entry(IReadOnlyList<string> Roles, IReadOnlySet<string> Permissions);
}

/// <summary>Token compartido por todas las entradas de permisos: cancelarlo invalida el cache completo.</summary>
internal sealed class PermissionCacheVersion : IDisposable
{
    private readonly Lock _gate = new();
    private CancellationTokenSource _source = new();

    public IChangeToken Token
    {
        get
        {
            lock (_gate)
            {
                return new CancellationChangeToken(_source.Token);
            }
        }
    }

    public void Reset()
    {
        CancellationTokenSource old;
        lock (_gate)
        {
            old = _source;
            _source = new CancellationTokenSource();
        }

        old.Cancel();
        old.Dispose();
    }

    public void Dispose() => _source.Dispose();
}

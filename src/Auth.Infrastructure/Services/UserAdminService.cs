using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Admin;
using Auth.Application.Features.Sessions;
using Auth.Domain.Audit;
using Auth.Domain.Authorization;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Services;

internal sealed class UserAdminService(
    AppDbContext db,
    UserManager<ApplicationUser> users,
    RoleManager<ApplicationRole> roles,
    SessionService sessions,
    IPermissionService permissions,
    IAuditLogger audit,
    TimeProvider time) : IUserAdminService
{
    public async Task<PagedResult<AdminUserDto>> ListAsync(string? search, int page, int pageSize, CancellationToken cancellationToken)
    {
        (page, pageSize) = Paging.Normalize(page, pageSize);
        var query = db.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var normalized = search.Trim().ToUpperInvariant();
            query = query.Where(u => u.NormalizedEmail!.Contains(normalized));
        }

        var total = await query.CountAsync(cancellationToken);
        var pageItems = await query
            .OrderByDescending(u => u.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        var rolesByUser = await RolesByUserAsync(pageItems.Select(u => u.Id).ToList(), cancellationToken);
        var items = pageItems.Select(u => ToDto(u, rolesByUser.GetValueOrDefault(u.Id, []))).ToList();
        return new PagedResult<AdminUserDto>(items, page, pageSize, total);
    }

    public async Task<Result<AdminUserDto>> GetAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        var rolesByUser = await RolesByUserAsync([userId], cancellationToken);
        return ToDto(user, rolesByUser.GetValueOrDefault(userId, []));
    }

    public async Task<Result> LockAsync(Guid userId, Guid actorUserId, CancellationToken cancellationToken)
    {
        if (userId == actorUserId)
        {
            return Error.Conflict("You cannot lock your own account.");
        }

        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        user.LockoutEnabled = true;
        user.LockoutEnd = AccountLockout.AdminLockEnd;
        user.UpdatedAt = time.GetUtcNow().UtcDateTime;
        await users.UpdateAsync(user);

        var revoked = await sessions.RevokeAllAsync(userId, RevocationReason.UserLocked, exceptSessionId: null, cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.UserLocked, true, userId, user.Email, ActorUserId: actorUserId,
            Details: new Dictionary<string, object?> { ["revokedSessions"] = revoked }), cancellationToken);
        return Result.Success();
    }

    public async Task<Result> UnlockAsync(Guid userId, Guid actorUserId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        user.LockoutEnd = null;
        user.AccessFailedCount = 0;
        user.UpdatedAt = time.GetUtcNow().UtcDateTime;
        await users.UpdateAsync(user);
        await audit.LogAsync(new AuditEntry(AuditEventType.UserUnlocked, true, userId, user.Email, ActorUserId: actorUserId), cancellationToken);
        return Result.Success();
    }

    public async Task<Result<AdminUserDto>> SetRolesAsync(Guid userId, IReadOnlyList<string> requested, Guid actorUserId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        var target = new List<string>();
        var unknown = new List<string>();
        foreach (var name in requested.Select(r => r.Trim()).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var role = await roles.FindByNameAsync(name);
            if (role is null)
            {
                unknown.Add(name);
            }
            else
            {
                target.Add(role.Name!);
            }
        }

        if (unknown.Count > 0)
        {
            return Error.Validation(new Dictionary<string, string[]>
            {
                ["roles"] = unknown.Select(n => $"Unknown role '{n}'.").ToArray(),
            });
        }

        var current = await users.GetRolesAsync(user);
        var toRemove = current.Except(target, StringComparer.OrdinalIgnoreCase).ToList();
        var toAdd = target.Except(current, StringComparer.OrdinalIgnoreCase).ToList();

        if (toRemove.Contains(SystemRoles.Admin, StringComparer.OrdinalIgnoreCase)
            && (await users.GetUsersInRoleAsync(SystemRoles.Admin)).Count <= 1)
        {
            return Error.Conflict("The last administrator cannot lose the Admin role.");
        }

        if (toRemove.Count > 0)
        {
            await users.RemoveFromRolesAsync(user, toRemove);
        }

        if (toAdd.Count > 0)
        {
            await users.AddToRolesAsync(user, toAdd);
        }

        permissions.InvalidateUser(userId);
        await audit.LogAsync(new AuditEntry(AuditEventType.UserRolesChanged, true, userId, user.Email, ActorUserId: actorUserId,
            Details: new Dictionary<string, object?> { ["added"] = toAdd, ["removed"] = toRemove }), cancellationToken);

        return await GetAsync(userId, cancellationToken);
    }

    public async Task<Result<IReadOnlyList<SessionDto>>> ListSessionsAsync(Guid userId, CancellationToken cancellationToken)
    {
        if (!await db.Users.AnyAsync(u => u.Id == userId, cancellationToken))
        {
            return Error.NotFound("User not found.");
        }

        return Result.Success(await sessions.ListActiveAsync(userId, currentSessionId: null, cancellationToken));
    }

    public async Task<Result> RevokeSessionAsync(Guid sessionId, Guid actorUserId, CancellationToken cancellationToken)
    {
        var session = await db.Sessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == sessionId && s.RevokedAt == null, cancellationToken);
        if (session is null)
        {
            return Error.NotFound("Session not found.");
        }

        await sessions.RevokeAsync(sessionId, RevocationReason.Admin, cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.AdminSessionRevoked, true, session.UserId, SessionId: sessionId, ActorUserId: actorUserId), cancellationToken);
        return Result.Success();
    }

    private async Task<Dictionary<Guid, List<string>>> RolesByUserAsync(List<Guid> userIds, CancellationToken cancellationToken)
    {
        var rows = await db.UserRoles
            .Where(ur => userIds.Contains(ur.UserId))
            .Join(db.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => new { ur.UserId, r.Name })
            .ToListAsync(cancellationToken);

        return rows.GroupBy(r => r.UserId).ToDictionary(g => g.Key, g => g.Select(r => r.Name!).Order(StringComparer.Ordinal).ToList());
    }

    private AdminUserDto ToDto(ApplicationUser u, List<string> userRoles) => new(
        u.Id,
        u.Email!,
        u.EmailConfirmed,
        u.TwoFactorEnabled,
        u.LockoutEnd is { } end && end > time.GetUtcNow(),
        u.LockoutEnd,
        userRoles,
        u.CreatedAt,
        u.LastLoginAt);
}

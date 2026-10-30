using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Admin;
using Auth.Domain.Audit;
using Auth.Domain.Authorization;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Services;

internal sealed class RoleAdminService(
    AppDbContext db,
    RoleManager<ApplicationRole> roles,
    IPermissionService permissions,
    IAuditLogger audit) : IRoleAdminService
{
    public async Task<IReadOnlyList<RoleDto>> ListAsync(CancellationToken cancellationToken)
    {
        var all = await db.Roles.AsNoTracking().Include(r => r.Permissions).OrderBy(r => r.Name).ToListAsync(cancellationToken);
        return all.Select(ToDto).ToList();
    }

    public async Task<Result<RoleDto>> GetAsync(Guid roleId, CancellationToken cancellationToken)
    {
        var role = await db.Roles.AsNoTracking().Include(r => r.Permissions).SingleOrDefaultAsync(r => r.Id == roleId, cancellationToken);
        return role is null ? Error.NotFound("Role not found.") : ToDto(role);
    }

    public async Task<Result<RoleDto>> CreateAsync(RoleRequest request, Guid actorUserId, CancellationToken cancellationToken)
    {
        var name = request.Name.Trim();
        if (await roles.FindByNameAsync(name) is not null)
        {
            return Error.Conflict("A role with that name already exists.");
        }

        var role = new ApplicationRole { Id = Guid.CreateVersion7(), Name = name, Description = request.Description?.Trim(), IsSystem = false };
        var result = await roles.CreateAsync(role);
        if (!result.Succeeded)
        {
            return Error.Conflict(string.Join(" ", result.Errors.Select(e => e.Description)));
        }

        db.RolePermissions.AddRange(request.Permissions.Distinct(StringComparer.Ordinal).Select(p => new RolePermission { RoleId = role.Id, Permission = p }));
        await db.SaveChangesAsync(cancellationToken);

        await audit.LogAsync(new AuditEntry(AuditEventType.RoleCreated, true, ActorUserId: actorUserId,
            Details: new Dictionary<string, object?> { ["role"] = name, ["permissions"] = request.Permissions }), cancellationToken);
        return await GetAsync(role.Id, cancellationToken);
    }

    public async Task<Result<RoleDto>> UpdateAsync(Guid roleId, RoleRequest request, Guid actorUserId, CancellationToken cancellationToken)
    {
        var role = await db.Roles.Include(r => r.Permissions).SingleOrDefaultAsync(r => r.Id == roleId, cancellationToken);
        if (role is null)
        {
            return Error.NotFound("Role not found.");
        }

        var name = request.Name.Trim();
        var requested = request.Permissions.Distinct(StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);

        if (role.IsSystem && !string.Equals(role.Name, name, StringComparison.Ordinal))
        {
            return Error.Conflict("System roles cannot be renamed.");
        }

        if (role.Name == SystemRoles.Admin && !requested.SetEquals(Permissions.All))
        {
            return Error.Conflict("The Admin role must keep every permission.");
        }

        if (!string.Equals(role.Name, name, StringComparison.OrdinalIgnoreCase) && await roles.FindByNameAsync(name) is not null)
        {
            return Error.Conflict("A role with that name already exists.");
        }

        role.Name = name;
        role.NormalizedName = roles.NormalizeKey(name);
        role.Description = request.Description?.Trim();
        role.Permissions.RemoveAll(p => !requested.Contains(p.Permission));
        foreach (var permission in requested.Where(p => role.Permissions.All(x => x.Permission != p)))
        {
            role.Permissions.Add(new RolePermission { RoleId = role.Id, Permission = permission });
        }

        await db.SaveChangesAsync(cancellationToken);
        permissions.InvalidateAll();

        await audit.LogAsync(new AuditEntry(AuditEventType.RoleUpdated, true, ActorUserId: actorUserId,
            Details: new Dictionary<string, object?> { ["role"] = name, ["permissions"] = requested.Order(StringComparer.Ordinal).ToList() }), cancellationToken);
        return await GetAsync(role.Id, cancellationToken);
    }

    public async Task<Result> DeleteAsync(Guid roleId, Guid actorUserId, CancellationToken cancellationToken)
    {
        var role = await roles.FindByIdAsync(roleId.ToString());
        if (role is null)
        {
            return Error.NotFound("Role not found.");
        }

        if (role.IsSystem)
        {
            return Error.Conflict("System roles cannot be deleted.");
        }

        await roles.DeleteAsync(role);
        permissions.InvalidateAll();
        await audit.LogAsync(new AuditEntry(AuditEventType.RoleDeleted, true, ActorUserId: actorUserId,
            Details: new Dictionary<string, object?> { ["role"] = role.Name }), cancellationToken);
        return Result.Success();
    }

    private static RoleDto ToDto(ApplicationRole r) => new(
        r.Id,
        r.Name!,
        r.Description,
        r.IsSystem,
        r.Permissions.Select(p => p.Permission).Order(StringComparer.Ordinal).ToList());
}

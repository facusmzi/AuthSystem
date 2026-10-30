using Auth.Application.Common;
using Auth.Application.Features.Admin;
using Auth.Application.Features.Sessions;

namespace Auth.Application.Abstractions;

public interface IUserAdminService
{
    Task<PagedResult<AdminUserDto>> ListAsync(string? search, int page, int pageSize, CancellationToken cancellationToken);

    Task<Result<AdminUserDto>> GetAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>Bloquea indefinidamente y revoca todas las sesiones del usuario.</summary>
    Task<Result> LockAsync(Guid userId, Guid actorUserId, CancellationToken cancellationToken);

    Task<Result> UnlockAsync(Guid userId, Guid actorUserId, CancellationToken cancellationToken);

    /// <summary>Reemplaza los roles. Nunca deja al sistema sin administradores.</summary>
    Task<Result<AdminUserDto>> SetRolesAsync(Guid userId, IReadOnlyList<string> roles, Guid actorUserId, CancellationToken cancellationToken);

    Task<Result<IReadOnlyList<SessionDto>>> ListSessionsAsync(Guid userId, CancellationToken cancellationToken);

    Task<Result> RevokeSessionAsync(Guid sessionId, Guid actorUserId, CancellationToken cancellationToken);
}

public interface IRoleAdminService
{
    Task<IReadOnlyList<RoleDto>> ListAsync(CancellationToken cancellationToken);

    Task<Result<RoleDto>> GetAsync(Guid roleId, CancellationToken cancellationToken);

    Task<Result<RoleDto>> CreateAsync(RoleRequest request, Guid actorUserId, CancellationToken cancellationToken);

    Task<Result<RoleDto>> UpdateAsync(Guid roleId, RoleRequest request, Guid actorUserId, CancellationToken cancellationToken);

    Task<Result> DeleteAsync(Guid roleId, Guid actorUserId, CancellationToken cancellationToken);
}

public interface IAuditReader
{
    Task<Result<PagedResult<AuditEventDto>>> QueryAsync(AuditQuery query, CancellationToken cancellationToken);
}

namespace Auth.Application.Features.Admin;

public sealed record AdminUserDto(
    Guid Id,
    string Email,
    bool EmailConfirmed,
    bool MfaEnabled,
    bool Locked,
    DateTimeOffset? LockoutEnd,
    IReadOnlyList<string> Roles,
    DateTime CreatedAt,
    DateTime? LastLoginAt);

public sealed record RoleDto(Guid Id, string Name, string? Description, bool IsSystem, IReadOnlyList<string> Permissions);

public sealed record RoleRequest(string Name, string? Description, IReadOnlyList<string> Permissions);

public sealed record SetUserRolesRequest(IReadOnlyList<string> Roles);

public sealed record AuditEventDto(
    long Id,
    DateTime OccurredAt,
    string Type,
    Guid? UserId,
    Guid? ActorUserId,
    Guid? SessionId,
    string? Email,
    string? IpAddress,
    string? UserAgent,
    bool Success,
    string? Details);

public sealed record AuditQuery(Guid? UserId, string? Type, DateTime? From, DateTime? To, int Page = 1, int PageSize = 50);

public static class Paging
{
    public const int MaxPageSize = 100;

    public static (int Page, int PageSize) Normalize(int page, int pageSize) =>
        (Math.Max(1, page), Math.Clamp(pageSize, 1, MaxPageSize));
}

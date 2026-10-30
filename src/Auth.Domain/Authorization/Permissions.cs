namespace Auth.Domain.Authorization;

/// <summary>Permisos granulares. Los roles agrupan permisos; la autorización se evalúa siempre por permiso.</summary>
public static class Permissions
{
    public const string UsersRead = "users.read";
    public const string UsersManage = "users.manage";
    public const string RolesRead = "roles.read";
    public const string RolesManage = "roles.manage";
    public const string RolesAssign = "roles.assign";
    public const string SessionsReadAny = "sessions.read.any";
    public const string SessionsRevokeAny = "sessions.revoke.any";
    public const string AuditRead = "audit.read";

    public static IReadOnlyList<string> All { get; } =
    [
        UsersRead,
        UsersManage,
        RolesRead,
        RolesManage,
        RolesAssign,
        SessionsReadAny,
        SessionsRevokeAny,
        AuditRead,
    ];

    public static bool IsKnown(string permission) => All.Contains(permission, StringComparer.Ordinal);
}

namespace Auth.Domain.Authorization;

/// <summary>Roles del sistema: se crean en el seed y no se pueden borrar ni renombrar.</summary>
public static class SystemRoles
{
    public const string Admin = "Admin";
    public const string User = "User";

    public static IReadOnlyList<string> All { get; } = [Admin, User];

    public static bool IsSystem(string roleName) => All.Contains(roleName, StringComparer.OrdinalIgnoreCase);
}

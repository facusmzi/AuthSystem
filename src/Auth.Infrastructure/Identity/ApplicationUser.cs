using Microsoft.AspNetCore.Identity;

namespace Auth.Infrastructure.Identity;

public sealed class ApplicationUser : IdentityUser<Guid>
{
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
    public DateTime? PasswordChangedAt { get; set; }
}

public sealed class ApplicationRole : IdentityRole<Guid>
{
    public string? Description { get; set; }

    /// <summary>Roles del sistema (<c>Admin</c>, <c>User</c>): no se pueden borrar ni renombrar.</summary>
    public bool IsSystem { get; set; }

    public List<RolePermission> Permissions { get; set; } = [];
}

public sealed class RolePermission
{
    public Guid RoleId { get; set; }
    public string Permission { get; set; } = string.Empty;
}

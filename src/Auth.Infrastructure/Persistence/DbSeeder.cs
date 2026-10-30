using Auth.Domain.Authorization;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Persistence;

/// <summary>Aplica migraciones y siembra roles del sistema, sus permisos y el primer administrador.</summary>
public sealed class DbSeeder(
    AppDbContext db,
    RoleManager<ApplicationRole> roleManager,
    UserManager<ApplicationUser> userManager,
    IOptions<SeedOptions> seedOptions,
    ILogger<DbSeeder> logger)
{
    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        await db.Database.MigrateAsync(cancellationToken);

        await EnsureRoleAsync(SystemRoles.Admin, "Full administrative access.", Permissions.All, cancellationToken);
        await EnsureRoleAsync(SystemRoles.User, "Default role for every account.", [], cancellationToken);

        var adminEmail = seedOptions.Value.AdminEmail;
        if (!string.IsNullOrWhiteSpace(adminEmail))
        {
            await AssignAdminAsync(adminEmail, cancellationToken);
        }
    }

    /// <summary>Asigna el rol Admin si el usuario existe y confirmó su email. No crea usuarios ni contraseñas.</summary>
    public async Task<bool> AssignAdminAsync(string email, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await userManager.FindByEmailAsync(email);
        if (user is null || !user.EmailConfirmed)
        {
            logger.LogWarning("Seed admin skipped: the configured user does not exist or has not confirmed the email");
            return false;
        }

        if (!await userManager.IsInRoleAsync(user, SystemRoles.Admin))
        {
            var result = await userManager.AddToRoleAsync(user, SystemRoles.Admin);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException("Could not assign the Admin role: " + string.Join(", ", result.Errors.Select(e => e.Code)));
            }

            logger.LogInformation("Admin role assigned to user {UserId}", user.Id);
        }

        return true;
    }

    private async Task EnsureRoleAsync(string name, string description, IReadOnlyCollection<string> permissions, CancellationToken cancellationToken)
    {
        var role = await roleManager.FindByNameAsync(name);
        if (role is null)
        {
            role = new ApplicationRole { Id = Guid.CreateVersion7(), Name = name, Description = description, IsSystem = true };
            var result = await roleManager.CreateAsync(role);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"Could not create role {name}: " + string.Join(", ", result.Errors.Select(e => e.Code)));
            }
        }

        var existing = await db.RolePermissions
            .Where(p => p.RoleId == role.Id)
            .Select(p => p.Permission)
            .ToListAsync(cancellationToken);

        var missing = permissions.Except(existing, StringComparer.Ordinal).ToList();
        if (missing.Count > 0)
        {
            db.RolePermissions.AddRange(missing.Select(p => new RolePermission { RoleId = role.Id, Permission = p }));
            await db.SaveChangesAsync(cancellationToken);
        }
    }
}

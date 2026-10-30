using Auth.Application.Abstractions;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Persistence;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Authorization;

public sealed class PermissionServiceTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    [Fact]
    public async Task Effective_permissions_are_the_union_of_all_roles_and_cache_is_invalidated()
    {
        var client = factory.CreateHttpsClient();
        var session = await factory.CreateUserAndLoginAsync(client);
        var permissions = factory.Services.GetRequiredService<IPermissionService>();
        var a = $"A-{Guid.NewGuid():N}"[..10];
        var b = $"B-{Guid.NewGuid():N}"[..10];

        await factory.WithScopeAsync(async sp =>
        {
            var roles = sp.GetRequiredService<RoleManager<ApplicationRole>>();
            var db = sp.GetRequiredService<AppDbContext>();
            foreach (var (name, perms) in new[] { (a, new[] { "users.read", "audit.read" }), (b, new[] { "audit.read", "roles.read" }) })
            {
                var role = new ApplicationRole { Id = Guid.CreateVersion7(), Name = name };
                await roles.CreateAsync(role);
                db.RolePermissions.AddRange(perms.Select(p => new RolePermission { RoleId = role.Id, Permission = p }));
            }
            await db.SaveChangesAsync();

            var users = sp.GetRequiredService<UserManager<ApplicationUser>>();
            await users.AddToRolesAsync((await users.FindByIdAsync(session.UserId.ToString()))!, [a, b]);
        });

        // Cacheado desde el login (sin permisos) hasta que se invalide.
        (await permissions.GetPermissionsAsync(session.UserId, default)).ShouldBeEmpty();

        permissions.InvalidateUser(session.UserId);
        (await permissions.GetPermissionsAsync(session.UserId, default)).ShouldBe(["users.read", "audit.read", "roles.read"], ignoreOrder: true);

        await factory.WithScopeAsync(async sp =>
        {
            var db = sp.GetRequiredService<AppDbContext>();
            db.RolePermissions.RemoveRange(db.RolePermissions.Where(p => p.Permission == "roles.read"));
            await db.SaveChangesAsync();
        });
        permissions.InvalidateAll();

        (await permissions.GetPermissionsAsync(session.UserId, default)).ShouldBe(["users.read", "audit.read"], ignoreOrder: true);
    }
}

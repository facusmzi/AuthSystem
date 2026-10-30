using Auth.Domain.Authorization;
using Auth.Infrastructure.Persistence;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Persistence;

public sealed class DatabaseTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    [Fact]
    public async Task Startup_applies_migrations_and_seeds_system_roles_with_permissions()
    {
        _ = factory.CreateHttpsClient();
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        (await db.Database.GetPendingMigrationsAsync()).ShouldBeEmpty();

        var roles = await db.Roles.Include(r => r.Permissions).ToListAsync();
        roles.Select(r => r.Name).ShouldBe([SystemRoles.Admin, SystemRoles.User], ignoreOrder: true);
        roles.ShouldAllBe(r => r.IsSystem);

        var admin = roles.Single(r => r.Name == SystemRoles.Admin);
        admin.Permissions.Select(p => p.Permission).ShouldBe(Permissions.All, ignoreOrder: true);
        roles.Single(r => r.Name == SystemRoles.User).Permissions.ShouldBeEmpty();
    }

    [Fact]
    public async Task Sqlite_runs_in_wal_mode()
    {
        _ = factory.CreateHttpsClient();
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var mode = await db.Database.SqlQueryRaw<string>("PRAGMA journal_mode").ToListAsync();
        mode.Single().ShouldBe("wal");
    }
}

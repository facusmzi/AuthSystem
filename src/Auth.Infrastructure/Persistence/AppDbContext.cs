using Auth.Domain.Audit;
using Auth.Domain.Registration;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Auth.Infrastructure.Persistence;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options)
    : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>(options)
{
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<SecurityAuditEvent> AuditEvents => Set<SecurityAuditEvent>();
    public DbSet<BetaWhitelistEntry> BetaWhitelist => Set<BetaWhitelistEntry>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        // SQLite no tiene tipo fecha: guardamos UTC y marcamos Kind=Utc al leer.
        configurationBuilder.Properties<DateTime>().HaveConversion<UtcDateTimeConverter>();
        configurationBuilder.Properties<DateTime?>().HaveConversion<NullableUtcDateTimeConverter>();

        // DateTimeOffset (LockoutEnd de Identity) como entero ordenable.
        configurationBuilder.Properties<DateTimeOffset>().HaveConversion<DateTimeOffsetToBinaryConverter>();
        configurationBuilder.Properties<DateTimeOffset?>().HaveConversion<DateTimeOffsetToBinaryConverter>();
    }
}

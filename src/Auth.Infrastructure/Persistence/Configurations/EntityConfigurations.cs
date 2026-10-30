using Auth.Domain.Audit;
using Auth.Domain.Registration;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.Infrastructure.Persistence.Configurations;

internal sealed class ApplicationUserConfiguration : IEntityTypeConfiguration<ApplicationUser>
{
    public void Configure(EntityTypeBuilder<ApplicationUser> builder)
    {
        // Identity crea un índice no único en NormalizedEmail; lo hacemos único.
        builder.HasIndex(u => u.NormalizedEmail).IsUnique();
        builder.HasMany<Session>().WithOne().HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class ApplicationRoleConfiguration : IEntityTypeConfiguration<ApplicationRole>
{
    public void Configure(EntityTypeBuilder<ApplicationRole> builder)
    {
        builder.Property(r => r.Description).HasMaxLength(256);
        builder.HasMany(r => r.Permissions).WithOne().HasForeignKey(p => p.RoleId).OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class RolePermissionConfiguration : IEntityTypeConfiguration<RolePermission>
{
    public void Configure(EntityTypeBuilder<RolePermission> builder)
    {
        builder.ToTable("RolePermissions");
        builder.HasKey(p => new { p.RoleId, p.Permission });
        builder.Property(p => p.Permission).HasMaxLength(64);
    }
}

internal sealed class SessionConfiguration : IEntityTypeConfiguration<Session>
{
    public void Configure(EntityTypeBuilder<Session> builder)
    {
        builder.ToTable("Sessions");
        builder.HasKey(s => s.Id);
        builder.Property(s => s.Id).ValueGeneratedNever();
        builder.Property(s => s.Kind).HasConversion<string>().HasMaxLength(16);
        builder.Property(s => s.LoginMethod).HasConversion<string>().HasMaxLength(32);
        builder.Property(s => s.RevokedReason).HasConversion<string>().HasMaxLength(32);
        builder.Property(s => s.RefreshTokenHash).HasMaxLength(64);
        builder.Property(s => s.PreviousRefreshTokenHash).HasMaxLength(64);
        builder.Property(s => s.IpAddress).HasMaxLength(Session.MaxIpAddressLength);
        builder.Property(s => s.UserAgent).HasMaxLength(Session.MaxUserAgentLength);

        builder.HasIndex(s => s.UserId);
        builder.HasIndex(s => s.RefreshTokenHash).IsUnique();
        builder.HasIndex(s => s.PreviousRefreshTokenHash);
        builder.HasIndex(s => s.ExpiresAt);
    }
}

internal sealed class SecurityAuditEventConfiguration : IEntityTypeConfiguration<SecurityAuditEvent>
{
    public void Configure(EntityTypeBuilder<SecurityAuditEvent> builder)
    {
        builder.ToTable("SecurityAuditEvents");
        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).ValueGeneratedOnAdd();
        builder.Property(e => e.Type).HasConversion<string>().HasMaxLength(64);
        builder.Property(e => e.Email).HasMaxLength(SecurityAuditEvent.MaxEmailLength);
        builder.Property(e => e.IpAddress).HasMaxLength(Session.MaxIpAddressLength);
        builder.Property(e => e.UserAgent).HasMaxLength(Session.MaxUserAgentLength);
        builder.Property(e => e.Details).HasMaxLength(SecurityAuditEvent.MaxDetailsLength);

        builder.HasIndex(e => new { e.UserId, e.OccurredAt });
        builder.HasIndex(e => new { e.Type, e.OccurredAt });
        builder.HasIndex(e => e.OccurredAt);
    }
}

internal sealed class BetaWhitelistEntryConfiguration : IEntityTypeConfiguration<BetaWhitelistEntry>
{
    public void Configure(EntityTypeBuilder<BetaWhitelistEntry> builder)
    {
        builder.ToTable("BetaWhitelist");
        builder.HasKey(e => e.NormalizedEmail);
        builder.Property(e => e.NormalizedEmail).HasMaxLength(256);
    }
}

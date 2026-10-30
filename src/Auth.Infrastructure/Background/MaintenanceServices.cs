using Auth.Infrastructure.Options;
using Auth.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Background;

/// <summary>Tarea periódica con reloj inyectable. <see cref="RunOnceAsync"/> es invocable directamente en tests.</summary>
public abstract class PeriodicMaintenanceService(IOptions<MaintenanceOptions> options, TimeProvider time, ILogger logger) : BackgroundService
{
    protected MaintenanceOptions Settings => options.Value;

    protected DateTime UtcNow => time.GetUtcNow().UtcDateTime;

    public abstract Task<int> RunOnceAsync(CancellationToken cancellationToken);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled)
        {
            return;
        }

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(options.Value.IntervalMinutes), time);
        do
        {
            try
            {
                var removed = await RunOnceAsync(stoppingToken);
                if (removed > 0)
                {
                    logger.LogInformation("{Task} removed {Count} rows", GetType().Name, removed);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "{Task} failed", GetType().Name);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

/// <summary>Borra sesiones vencidas o revocadas hace más de <c>KeepInactiveSessionsDays</c>.</summary>
public sealed class SessionCleanupService(
    IDbContextFactory<AppDbContext> dbFactory,
    IOptions<MaintenanceOptions> options,
    TimeProvider time,
    ILogger<SessionCleanupService> logger) : PeriodicMaintenanceService(options, time, logger)
{
    public override async Task<int> RunOnceAsync(CancellationToken cancellationToken)
    {
        var cutoff = UtcNow.AddDays(-Settings.KeepInactiveSessionsDays);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.Sessions
            .Where(s => (s.RevokedAt != null && s.RevokedAt < cutoff) || s.ExpiresAt < cutoff || s.AbsoluteExpiresAt < cutoff)
            .ExecuteDeleteAsync(cancellationToken);
    }
}

/// <summary>Borra eventos de auditoría más viejos que <c>Audit:RetentionDays</c>.</summary>
public sealed class AuditRetentionService(
    IDbContextFactory<AppDbContext> dbFactory,
    IOptions<AuditOptions> audit,
    IOptions<MaintenanceOptions> options,
    TimeProvider time,
    ILogger<AuditRetentionService> logger) : PeriodicMaintenanceService(options, time, logger)
{
    public override async Task<int> RunOnceAsync(CancellationToken cancellationToken)
    {
        var cutoff = UtcNow.AddDays(-audit.Value.RetentionDays);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.AuditEvents.Where(e => e.OccurredAt < cutoff).ExecuteDeleteAsync(cancellationToken);
    }
}

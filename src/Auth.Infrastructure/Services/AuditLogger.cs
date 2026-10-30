using System.Text.Json;
using Auth.Application.Abstractions;
using Auth.Domain.Audit;
using Auth.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Persiste eventos de auditoría en un DbContext propio (no arrastra cambios pendientes del flujo que audita).
/// Un fallo al auditar se loguea pero no rompe el flujo de negocio.
/// </summary>
internal sealed class AuditLogger(
    IDbContextFactory<AppDbContext> dbFactory,
    IClientInfo client,
    TimeProvider time,
    ILogger<AuditLogger> logger) : IAuditLogger
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task LogAsync(AuditEntry entry, CancellationToken cancellationToken = default)
    {
        var details = entry.Details is { Count: > 0 } ? JsonSerializer.Serialize(entry.Details, JsonOptions) : null;
        var ev = SecurityAuditEvent.Create(
            time.GetUtcNow().UtcDateTime,
            entry.Type,
            entry.Success,
            entry.UserId,
            entry.ActorUserId,
            entry.SessionId,
            entry.Email,
            client.IpAddress,
            client.UserAgent,
            details);

        var level = entry.Success ? LogLevel.Information : LogLevel.Warning;
        logger.Log(level, "Security event {EventType} success={Success} user={UserId} session={SessionId}", entry.Type, entry.Success, entry.UserId, entry.SessionId);

        try
        {
            await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
            db.AuditEvents.Add(ev);
            await db.SaveChangesAsync(CancellationToken.None);
        }
        catch (Exception ex) when (ex is DbUpdateException or InvalidOperationException)
        {
            logger.LogError(ex, "Failed to persist security audit event {EventType}", entry.Type);
        }
    }
}

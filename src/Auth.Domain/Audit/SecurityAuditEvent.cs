using Auth.Domain.Common;
using Auth.Domain.Sessions;

namespace Auth.Domain.Audit;

/// <summary>
/// Evento de auditoría de seguridad. No tiene FK al usuario: los eventos sobreviven al borrado de la cuenta.
/// <see cref="Details"/> es JSON y nunca contiene secretos.
/// </summary>
public sealed class SecurityAuditEvent
{
    public const int MaxEmailLength = 256;
    public const int MaxDetailsLength = 4000;

    private SecurityAuditEvent()
    {
    }

    public long Id { get; private set; }
    public DateTime OccurredAt { get; private set; }
    public AuditEventType Type { get; private set; }
    public Guid? UserId { get; private set; }
    public Guid? ActorUserId { get; private set; }
    public Guid? SessionId { get; private set; }
    public string? Email { get; private set; }
    public string? IpAddress { get; private set; }
    public string? UserAgent { get; private set; }
    public bool Success { get; private set; }
    public string? Details { get; private set; }

    public static SecurityAuditEvent Create(
        DateTime occurredAt,
        AuditEventType type,
        bool success,
        Guid? userId = null,
        Guid? actorUserId = null,
        Guid? sessionId = null,
        string? email = null,
        string? ipAddress = null,
        string? userAgent = null,
        string? details = null) => new()
        {
            OccurredAt = occurredAt,
            Type = type,
            Success = success,
            UserId = userId,
            ActorUserId = actorUserId,
            SessionId = sessionId,
            Email = Text.Truncate(email, MaxEmailLength),
            IpAddress = Text.Truncate(ipAddress, Session.MaxIpAddressLength),
            UserAgent = Text.Truncate(userAgent, Session.MaxUserAgentLength),
            Details = Text.Truncate(details, MaxDetailsLength),
        };
}

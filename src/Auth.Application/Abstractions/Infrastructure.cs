using Auth.Application.Common;
using Auth.Domain.Audit;

namespace Auth.Application.Abstractions;

/// <summary>Usuario autenticado de la request actual (vacío fuera de una request).</summary>
public interface ICurrentUser
{
    Guid? UserId { get; }
    Guid? SessionId { get; }
    bool IsAuthenticated { get; }

    Guid RequiredUserId => UserId ?? throw new InvalidOperationException("No authenticated user.");
    Guid RequiredSessionId => SessionId ?? throw new InvalidOperationException("No authenticated session.");
}

/// <summary>Datos del cliente de la request actual (IP real según la configuración de proxies).</summary>
public interface IClientInfo
{
    string? IpAddress { get; }
    string? UserAgent { get; }
}

public sealed record EmailMessage(string To, string Subject, string TextBody, string HtmlBody);

/// <summary>Envío de emails. Los cuerpos contienen tokens: las implementaciones nunca los loguean.</summary>
public interface IEmailSender
{
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken);
}

/// <summary>Entrada de auditoría. <see cref="Details"/> nunca debe contener secretos.</summary>
public sealed record AuditEntry(
    AuditEventType Type,
    bool Success,
    Guid? UserId = null,
    string? Email = null,
    Guid? SessionId = null,
    Guid? ActorUserId = null,
    IReadOnlyDictionary<string, object?>? Details = null);

public interface IAuditLogger
{
    Task LogAsync(AuditEntry entry, CancellationToken cancellationToken = default);
}

public enum BreachCheckStatus
{
    NotBreached = 0,
    Breached = 1,
    Unavailable = 2,
}

/// <summary>Chequeo de contraseñas filtradas (k-anonymity: la contraseña nunca sale del servidor).</summary>
public interface IPasswordBreachChecker
{
    Task<BreachCheckStatus> CheckAsync(string password, CancellationToken cancellationToken);
}

/// <summary>Valida una contraseña nueva contra la política completa (longitud, email, HIBP).</summary>
public interface IPasswordService
{
    Task<Result> ValidateNewPasswordAsync(string email, string password, CancellationToken cancellationToken);
}

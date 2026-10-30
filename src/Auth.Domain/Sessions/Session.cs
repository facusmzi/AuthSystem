using Auth.Domain.Common;

namespace Auth.Domain.Sessions;

/// <summary>
/// Sesión de un usuario. Es la fuente de verdad para la revocación: tanto el JWT (claim <c>sid</c>)
/// como la cookie apuntan a una fila de esta tabla y se validan contra ella.
/// </summary>
public sealed class Session
{
    public const int MaxUserAgentLength = 512;
    public const int MaxIpAddressLength = 45;

    private Session()
    {
    }

    public Guid Id { get; private set; }
    public Guid UserId { get; private set; }
    public SessionKind Kind { get; private set; }

    /// <summary>SHA-256 (hex) del refresh token vigente. Null en sesiones cookie.</summary>
    public string? RefreshTokenHash { get; private set; }

    /// <summary>Hash del refresh token anterior, para detectar reutilización.</summary>
    public string? PreviousRefreshTokenHash { get; private set; }

    public DateTime? RefreshRotatedAt { get; private set; }
    public LoginMethod LoginMethod { get; private set; }
    public string? IpAddress { get; private set; }
    public string? UserAgent { get; private set; }
    public DateTime CreatedAt { get; private set; }
    public DateTime LastSeenAt { get; private set; }

    /// <summary>Vencimiento deslizante.</summary>
    public DateTime ExpiresAt { get; private set; }

    /// <summary>Tope duro: la sesión nunca vive más allá de esta fecha, aunque se use.</summary>
    public DateTime AbsoluteExpiresAt { get; private set; }

    public DateTime? RevokedAt { get; private set; }
    public RevocationReason? RevokedReason { get; private set; }

    public static Session Create(
        Guid userId,
        SessionKind kind,
        LoginMethod loginMethod,
        string? refreshTokenHash,
        string? ipAddress,
        string? userAgent,
        DateTime now,
        TimeSpan slidingLifetime,
        TimeSpan absoluteLifetime)
    {
        if (kind == SessionKind.Bearer && string.IsNullOrEmpty(refreshTokenHash))
        {
            throw new DomainException("Bearer sessions require a refresh token hash.");
        }

        if (kind == SessionKind.Cookie && refreshTokenHash is not null)
        {
            throw new DomainException("Cookie sessions must not have a refresh token.");
        }

        var absolute = now + absoluteLifetime;
        return new Session
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            Kind = kind,
            LoginMethod = loginMethod,
            RefreshTokenHash = refreshTokenHash,
            IpAddress = Text.Truncate(ipAddress, MaxIpAddressLength),
            UserAgent = Text.Truncate(userAgent, MaxUserAgentLength),
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = Min(now + slidingLifetime, absolute),
            AbsoluteExpiresAt = absolute,
        };
    }

    public bool IsActive(DateTime now) => RevokedAt is null && ExpiresAt > now && AbsoluteExpiresAt > now;

    /// <summary>Nuevo vencimiento deslizante, sin superar nunca el tope absoluto.</summary>
    public DateTime SlideExpiration(DateTime now, TimeSpan slidingLifetime) => Min(now + slidingLifetime, AbsoluteExpiresAt);

    private static DateTime Min(DateTime a, DateTime b) => a <= b ? a : b;
}

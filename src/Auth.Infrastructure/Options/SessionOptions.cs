using System.ComponentModel.DataAnnotations;

namespace Auth.Infrastructure.Options;

public sealed class UserSessionOptions
{
    public const string SectionName = "Sessions";

    [Range(1, 365)]
    public int SlidingDays { get; set; } = 30;

    [Range(1, 3650)]
    public int AbsoluteDays { get; set; } = 90;

    [Range(0, 60)]
    public int RefreshGraceMinutes { get; set; } = 3;

    [Range(0, 600)]
    public int ValidationCacheSeconds { get; set; } = 30;

    /// <summary>Cada cuánto se persiste <c>LastSeenAt</c> como máximo.</summary>
    [Range(1, 1440)]
    public int LastSeenUpdateMinutes { get; set; } = 5;

    public TimeSpan Sliding => TimeSpan.FromDays(SlidingDays);
    public TimeSpan Absolute => TimeSpan.FromDays(AbsoluteDays);
    public TimeSpan RefreshGrace => TimeSpan.FromMinutes(RefreshGraceMinutes);
    public TimeSpan ValidationCache => TimeSpan.FromSeconds(ValidationCacheSeconds);
    public TimeSpan LastSeenUpdate => TimeSpan.FromMinutes(LastSeenUpdateMinutes);
}

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    [Required]
    public string Issuer { get; set; } = string.Empty;

    [Required]
    public string Audience { get; set; } = string.Empty;

    [Range(1, 60)]
    public int AccessTokenMinutes { get; set; } = 10;

    [Range(0, 300)]
    public int ClockSkewSeconds { get; set; } = 30;

    /// <summary>Genera las claves faltantes al arrancar. Solo para desarrollo/tests.</summary>
    public bool GenerateMissingKeys { get; set; }

    [MinLength(1)]
    public List<SigningKeyOptions> SigningKeys { get; set; } = [];
}

public sealed class SigningKeyOptions
{
    [Required]
    public string Kid { get; set; } = string.Empty;

    /// <summary>Ruta al PEM PKCS#8 de la clave privada EC P-256 (relativa al content root).</summary>
    [Required]
    public string Path { get; set; } = string.Empty;

    /// <summary>La clave activa firma tokens nuevos; las demás solo validan (rotación).</summary>
    public bool Active { get; set; }
}

public sealed class MfaOptions
{
    public const string SectionName = "Mfa";

    [Required]
    public string Issuer { get; set; } = "Auth";

    [Range(1, 30)]
    public int ChallengeMinutes { get; set; } = 5;

    [Range(5, 20)]
    public int RecoveryCodes { get; set; } = 10;
}

public sealed class EmailTokenOptions
{
    public const string SectionName = "Tokens";

    [Range(1, 168)]
    public int EmailConfirmationHours { get; set; } = 24;

    [Range(5, 24 * 60)]
    public int PasswordResetMinutes { get; set; } = 60;

    /// <summary>Cooldown por usuario para reenviar confirmación / pedir reset.</summary>
    [Range(0, 3600)]
    public int EmailCooldownSeconds { get; set; } = 60;
}

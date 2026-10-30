using System.ComponentModel.DataAnnotations;

namespace Auth.Infrastructure.Options;

public sealed class FrontendOptions
{
    public const string SectionName = "Frontend";

    [Required, Url]
    public string BaseUrl { get; set; } = string.Empty;
}

public sealed class FeatureOptions
{
    public const string SectionName = "Features";

    public bool BetaWhitelist { get; set; }
}

public sealed class EmailOptions
{
    public const string SectionName = "Email";

    /// <summary><c>Logging</c> (solo destinatario/asunto), <c>Pickup</c> (archivos .eml, dev) o <c>Smtp</c>.</summary>
    [Required, RegularExpression("^(Logging|Pickup|Smtp)$")]
    public string Provider { get; set; } = "Logging";

    [Required, EmailAddress]
    public string From { get; set; } = "noreply@example.com";

    public string FromName { get; set; } = "Auth";

    public string PickupDirectory { get; set; } = "mail";

    public SmtpOptions Smtp { get; set; } = new();
}

public sealed class SmtpOptions
{
    public string Host { get; set; } = string.Empty;

    [Range(1, 65535)]
    public int Port { get; set; } = 587;

    public bool UseStartTls { get; set; } = true;

    public string? User { get; set; }

    public string? Password { get; set; }
}

public sealed class KeyStorageOptions
{
    public const string SectionName = "DataProtection";

    [Required]
    public string KeysPath { get; set; } = "keys/dp";
}

public sealed class AuditOptions
{
    public const string SectionName = "Audit";

    [Range(1, 3650)]
    public int RetentionDays { get; set; } = 180;
}

public sealed class MaintenanceOptions
{
    public const string SectionName = "Maintenance";

    public bool Enabled { get; set; } = true;

    [Range(1, 1440)]
    public int IntervalMinutes { get; set; } = 60;

    /// <summary>Días que se conservan las sesiones revocadas/vencidas antes de borrarlas.</summary>
    [Range(0, 365)]
    public int KeepInactiveSessionsDays { get; set; } = 30;
}

public sealed class SeedOptions
{
    public const string SectionName = "Seed";

    /// <summary>Si existe y está confirmado, se le asigna el rol Admin al arrancar.</summary>
    public string? AdminEmail { get; set; }
}

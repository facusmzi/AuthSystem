using System.ComponentModel.DataAnnotations;

namespace Auth.Infrastructure.Options;

/// <summary>Parámetros de Argon2id. Cambiarlos provoca rehash transparente en el siguiente login.</summary>
public sealed class PasswordHashingOptions
{
    public const string SectionName = "PasswordHashing";

    [Range(8 * 1024, 4 * 1024 * 1024)]
    public int MemoryKiB { get; set; } = 65536;

    [Range(1, 20)]
    public int Iterations { get; set; } = 3;

    [Range(1, 64)]
    public int Parallelism { get; set; } = 4;

    /// <summary>Máximo de hashes simultáneos (cada uno reserva <see cref="MemoryKiB"/> de RAM).</summary>
    [Range(1, 256)]
    public int MaxConcurrentHashes { get; set; } = 4;
}

/// <summary>Política NIST SP 800-63B: longitud, sin reglas de composición.</summary>
public sealed class PasswordPolicyOptions
{
    public const string SectionName = "PasswordPolicy";

    [Range(8, 128)]
    public int MinLength { get; set; } = 12;

    [Range(64, 1024)]
    public int MaxLength { get; set; } = 128;
}

public sealed class AccountLockoutOptions
{
    public const string SectionName = "Lockout";

    [Range(1, 100)]
    public int MaxFailedAttempts { get; set; } = 5;

    [Range(1, 24 * 60)]
    public int LockoutMinutes { get; set; } = 15;
}

public sealed class HibpOptions
{
    public const string SectionName = "Hibp";

    public bool Enabled { get; set; } = true;

    /// <summary>Si HIBP no responde: true = aceptar la contraseña (con warning + auditoría).</summary>
    public bool FailOpen { get; set; } = true;

    [Range(1, 30)]
    public int TimeoutSeconds { get; set; } = 3;

    [Range(1, int.MaxValue)]
    public int MinBreachCount { get; set; } = 1;

    [Required, Url]
    public string BaseUrl { get; set; } = "https://api.pwnedpasswords.com/";
}

namespace Auth.Domain.Registration;

/// <summary>Email habilitado para registrarse cuando el feature flag <c>Features:BetaWhitelist</c> está activo.</summary>
public sealed class BetaWhitelistEntry
{
    private BetaWhitelistEntry()
    {
    }

    public string NormalizedEmail { get; private set; } = string.Empty;
    public DateTime AddedAt { get; private set; }
    public DateTime? ConsumedAt { get; private set; }

    public static BetaWhitelistEntry Create(string normalizedEmail, DateTime now) => new()
    {
        NormalizedEmail = normalizedEmail,
        AddedAt = now,
    };

    public void Consume(DateTime now) => ConsumedAt ??= now;
}

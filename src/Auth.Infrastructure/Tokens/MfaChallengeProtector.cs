using System.Security.Cryptography;
using System.Text.Json;
using Auth.Infrastructure.Caching;
using Auth.Infrastructure.Options;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Tokens;

public sealed record MfaChallenge(Guid UserId, string SecurityStamp, string Jti, bool UseCookies, DateTimeOffset ExpiresAt);

/// <summary>
/// Token opaco del paso intermedio "contraseña OK, falta MFA". Cifrado y autenticado con Data Protection,
/// vence en pocos minutos (reloj inyectable), queda atado al security stamp y es de uso único (jti).
/// </summary>
public sealed class MfaChallengeProtector(IDataProtectionProvider dataProtection, TimedCache cache, TimeProvider time, IOptions<MfaOptions> options)
{
    private readonly IDataProtector _protector = dataProtection.CreateProtector("Auth.Mfa.Challenge");

    private TimeSpan Lifetime => TimeSpan.FromMinutes(options.Value.ChallengeMinutes);

    public string Protect(Guid userId, string securityStamp, bool useCookies)
    {
        var challenge = new MfaChallenge(userId, securityStamp, Guid.NewGuid().ToString("N"), useCookies, time.GetUtcNow() + Lifetime);
        return _protector.Protect(JsonSerializer.Serialize(challenge));
    }

    /// <summary>Devuelve el challenge si es auténtico, no venció y no se usó todavía.</summary>
    public MfaChallenge? Unprotect(string token)
    {
        MfaChallenge? challenge;
        try
        {
            challenge = JsonSerializer.Deserialize<MfaChallenge>(_protector.Unprotect(token));
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        {
            return null;
        }

        if (challenge is null || challenge.ExpiresAt <= time.GetUtcNow() || cache.TryGet<bool>(JtiKey(challenge.Jti), out _))
        {
            return null;
        }

        return challenge;
    }

    /// <summary>Marca el challenge como usado. False si otra request lo consumió primero.</summary>
    public bool TryConsume(MfaChallenge challenge) => cache.TryAdd(JtiKey(challenge.Jti), Lifetime);

    private static string JtiKey(string jti) => $"mfa-jti:{jti}";
}

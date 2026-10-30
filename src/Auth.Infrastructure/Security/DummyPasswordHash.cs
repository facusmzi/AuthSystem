using System.Security.Cryptography;
using Auth.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;

namespace Auth.Infrastructure.Security;

/// <summary>
/// Hash precomputado con los parámetros actuales. Verificar contra él cuando el usuario no existe (o está
/// bloqueado) iguala el tiempo de respuesta del login y evita enumerar emails por latencia.
/// </summary>
public sealed class DummyPasswordHash(IPasswordHasher<ApplicationUser> hasher)
{
    private static readonly ApplicationUser Nobody = new();
    private readonly Lazy<string> _hash = new(() => hasher.HashPassword(Nobody, Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))));

    /// <summary>Gasta el mismo trabajo que una verificación real. El resultado siempre es fallido.</summary>
    public void Verify(string password) =>
        _ = hasher.VerifyHashedPassword(Nobody, _hash.Value, string.IsNullOrEmpty(password) ? "x" : password);
}

internal static class EmailNormalizer
{
    public static string Normalize(string email) => email.Trim().ToLowerInvariant();
}

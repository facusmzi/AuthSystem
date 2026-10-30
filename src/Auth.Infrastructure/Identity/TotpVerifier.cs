using Auth.Infrastructure.Caching;
using Microsoft.AspNetCore.Identity;

namespace Auth.Infrastructure.Identity;

/// <summary>Verifica códigos TOTP y rechaza la reutilización del mismo código dentro de su ventana de validez.</summary>
public sealed class TotpVerifier(UserManager<ApplicationUser> users, TimedCache cache)
{
    /// <summary>La ventana de Identity es ±2 pasos de 30 s; 90 s cubre de sobra la vida útil de un código.</summary>
    private static readonly TimeSpan ReplayWindow = TimeSpan.FromSeconds(90);

    public async Task<bool> VerifyAsync(ApplicationUser user, string code)
    {
        var normalized = code.Trim().Replace(" ", string.Empty, StringComparison.Ordinal);
        if (normalized.Length != 6 || !normalized.All(char.IsAsciiDigit))
        {
            return false;
        }

        if (!await users.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, normalized))
        {
            return false;
        }

        // Un código interceptado no se puede reutilizar aunque siga dentro de su ventana.
        return cache.TryAdd($"totp-used:{user.Id:N}:{normalized}", ReplayWindow);
    }
}

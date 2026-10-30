using System.Security.Cryptography;
using System.Text;
using Auth.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace Auth.Infrastructure.Identity;

/// <summary>
/// UserStore de Identity endurecido: por defecto Identity guarda los recovery codes y la clave TOTP en texto
/// plano en <c>AspNetUserTokens</c>. Acá los recovery codes se guardan como SHA-256 y la clave del
/// autenticador cifrada con Data Protection.
/// </summary>
public sealed class AppUserStore(AppDbContext context, IDataProtectionProvider dataProtection, IdentityErrorDescriber? describer = null)
    : UserStore<ApplicationUser, ApplicationRole, AppDbContext, Guid>(context, describer)
{
    private readonly IDataProtector _keyProtector = dataProtection.CreateProtector("Auth.Identity.AuthenticatorKey");

    public override Task SetAuthenticatorKeyAsync(ApplicationUser user, string key, CancellationToken cancellationToken) =>
        base.SetAuthenticatorKeyAsync(user, _keyProtector.Protect(key), cancellationToken);

    public override async Task<string?> GetAuthenticatorKeyAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        var stored = await base.GetAuthenticatorKeyAsync(user, cancellationToken);
        if (stored is null)
        {
            return null;
        }

        try
        {
            return _keyProtector.Unprotect(stored);
        }
        catch (CryptographicException)
        {
            // Clave ilegible (p.ej. claves de Data Protection perdidas): el usuario debe reconfigurar MFA.
            return null;
        }
    }

    public override Task ReplaceCodesAsync(ApplicationUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken) =>
        base.ReplaceCodesAsync(user, recoveryCodes.Select(HashCode), cancellationToken);

    public override Task<bool> RedeemCodeAsync(ApplicationUser user, string code, CancellationToken cancellationToken) =>
        base.RedeemCodeAsync(user, HashCode(code), cancellationToken);

    /// <summary>Los códigos tienen ~50 bits de entropía y son de un solo uso: SHA-256 alcanza.</summary>
    internal static string HashCode(string code) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(NormalizeCode(code))));

    internal static string NormalizeCode(string code) => code.Trim().Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
}

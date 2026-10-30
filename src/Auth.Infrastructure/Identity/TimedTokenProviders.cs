using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Auth.Infrastructure.Options;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Identity;

/// <summary>
/// Equivalente a <c>DataProtectorTokenProvider</c> pero con reloj inyectable (<see cref="TimeProvider"/>) y
/// tokens base64url. El token incluye creación, usuario, propósito y security stamp: queda invalidado
/// en cuanto cambia el stamp (p.ej. tras un reset de contraseña → uso único).
/// </summary>
public abstract class TimedTokenProvider(IDataProtectionProvider dataProtection, TimeProvider time, string name)
    : IUserTwoFactorTokenProvider<ApplicationUser>
{
    private readonly IDataProtector _protector = dataProtection.CreateProtector("Auth.Identity.Tokens", name);

    protected abstract TimeSpan Lifespan { get; }

    public async Task<string> GenerateAsync(string purpose, UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        using var stream = new MemoryStream();
        await using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(time.GetUtcNow().UtcTicks);
            writer.Write(user.Id.ToString("N"));
            writer.Write(purpose);
            writer.Write(await GetStampAsync(manager, user));
        }

        return Base64Url.EncodeToString(_protector.Protect(stream.ToArray()));
    }

    public async Task<bool> ValidateAsync(string purpose, string token, UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        byte[] payload;
        try
        {
            payload = _protector.Unprotect(Base64Url.DecodeFromChars(token));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return false;
        }

        using var reader = new BinaryReader(new MemoryStream(payload), Encoding.UTF8);
        try
        {
            var created = new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero);
            if (created + Lifespan < time.GetUtcNow())
            {
                return false;
            }

            var userId = reader.ReadString();
            var tokenPurpose = reader.ReadString();
            var stamp = reader.ReadString();

            return userId == user.Id.ToString("N")
                && tokenPurpose == purpose
                && stamp == await GetStampAsync(manager, user)
                && reader.PeekChar() == -1;
        }
        catch (EndOfStreamException)
        {
            return false;
        }
    }

    public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<ApplicationUser> manager, ApplicationUser user) => Task.FromResult(false);

    private static async Task<string> GetStampAsync(UserManager<ApplicationUser> manager, ApplicationUser user) =>
        manager.SupportsUserSecurityStamp ? await manager.GetSecurityStampAsync(user) : string.Empty;
}

/// <summary>Confirmación de email: vida larga (24 h por defecto), el usuario puede abrir el mail más tarde.</summary>
public sealed class LongLivedEmailConfirmationTokenProvider(IDataProtectionProvider dp, TimeProvider time, IOptions<EmailTokenOptions> options)
    : TimedTokenProvider(dp, time, ProviderName)
{
    public const string ProviderName = "EmailConfirmation";

    protected override TimeSpan Lifespan => TimeSpan.FromHours(options.Value.EmailConfirmationHours);
}

/// <summary>Reset de contraseña: vida corta (1 h por defecto).</summary>
public sealed class PasswordResetTokenProvider(IDataProtectionProvider dp, TimeProvider time, IOptions<EmailTokenOptions> options)
    : TimedTokenProvider(dp, time, ProviderName)
{
    public const string ProviderName = "PasswordReset";

    protected override TimeSpan Lifespan => TimeSpan.FromMinutes(options.Value.PasswordResetMinutes);
}

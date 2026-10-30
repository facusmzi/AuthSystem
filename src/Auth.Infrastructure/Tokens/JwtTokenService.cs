using Auth.Application.Abstractions;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Infrastructure.Tokens;

/// <summary>
/// Emite access tokens ES256 (<c>typ: at+jwt</c>, RFC 9068) con <c>sub</c>, <c>sid</c>, <c>jti</c>, <c>amr</c> y
/// <c>email_verified</c>. Los roles no viajan en el token: la autorización se resuelve en el servidor.
/// </summary>
public sealed class JwtTokenService(EcdsaSigningKeyProvider keys, IOptions<JwtOptions> options, TimeProvider time) : ITokenService
{
    public const string TokenType = "at+jwt";

    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };

    public AccessToken CreateAccessToken(AccessTokenRequest request)
    {
        var o = options.Value;
        var now = time.GetUtcNow().UtcDateTime;
        var expires = now.AddMinutes(o.AccessTokenMinutes);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = o.Issuer,
            Audience = o.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            TokenType = TokenType,
            SigningCredentials = keys.SigningCredentials,
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = request.UserId.ToString(),
                ["sid"] = request.SessionId.ToString(),
                [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
                ["amr"] = AuthenticationMethods(request.LoginMethod),
                ["email_verified"] = request.EmailVerified,
            },
        };

        return new AccessToken(_handler.CreateToken(descriptor), expires);
    }

    public static string[] AuthenticationMethods(LoginMethod method) => method switch
    {
        LoginMethod.PasswordMfa or LoginMethod.RecoveryCode => ["pwd", "mfa"],
        _ => ["pwd"],
    };
}

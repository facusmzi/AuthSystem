using Auth.Infrastructure.Options;
using Auth.Infrastructure.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Authentication;

public static class AuthenticationSetup
{
    public static IServiceCollection AddAuthSchemes(this IServiceCollection services)
    {
        services.AddScoped<JwtBearerEventsHandler>();

        services.AddAuthentication(AuthSchemes.Bearer)
            .AddJwtBearer(AuthSchemes.Bearer, options =>
            {
                options.MapInboundClaims = false;
                options.EventsType = typeof(JwtBearerEventsHandler);
            });

        services.AddOptions<JwtBearerOptions>(AuthSchemes.Bearer)
            .Configure<EcdsaSigningKeyProvider, IOptions<JwtOptions>, TimeProvider>((options, keys, jwt, time) =>
            {
                var skew = TimeSpan.FromSeconds(jwt.Value.ClockSkewSeconds);
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwt.Value.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwt.Value.Audience,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ValidateIssuerSigningKey = true,
                    RequireSignedTokens = true,
                    IssuerSigningKeys = keys.ValidationKeys,
                    ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
                    ValidTypes = [JwtTokenService.TokenType],
                    ClockSkew = skew,
                    NameClaimType = AuthClaims.Subject,
                    RoleClaimType = "role",
                    // Vencimiento evaluado con el TimeProvider inyectado (testeable).
                    LifetimeValidator = (notBefore, expires, _, _) =>
                    {
                        var now = time.GetUtcNow().UtcDateTime;
                        if (notBefore is { } nbf && nbf > now + skew)
                        {
                            throw new SecurityTokenNotYetValidException("The token is not yet valid.") { NotBefore = nbf };
                        }

                        if (expires is not { } exp || exp < now - skew)
                        {
                            throw new SecurityTokenExpiredException("The token has expired.") { Expires = expires ?? DateTime.MinValue };
                        }

                        return true;
                    },
                };
            });

        return services;
    }

    public static IServiceCollection AddAuthPolicies(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            // Todo endpoint sin atributos exige usuario autenticado con email verificado.
            .SetFallbackPolicy(new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .RequireClaim(AuthClaims.EmailVerified, "true")
                .Build())
            .AddPolicy(AuthPolicies.Authenticated, policy => policy.RequireAuthenticatedUser());

        return services;
    }
}

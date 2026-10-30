using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Authentication;

public static class AuthenticationSetup
{
    /// <summary><c>__Host-</c>: el navegador exige Secure, Path=/ y sin Domain (no la puede pisar un subdominio).</summary>
    public const string CookieName = "__Host-auth";

    /// <summary>Principal que se guarda en la cookie (ticket protegido con Data Protection).</summary>
    public static ClaimsPrincipal CreateCookiePrincipal(Guid userId, Guid sessionId, IEnumerable<string> authenticationMethods)
    {
        var claims = new List<Claim>
        {
            new(AuthClaims.Subject, userId.ToString()),
            new(AuthClaims.SessionId, sessionId.ToString()),
            new(AuthClaims.EmailVerified, "true"),
        };
        claims.AddRange(authenticationMethods.Select(m => new Claim(AuthClaims.AuthenticationMethod, m)));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, AuthSchemes.Cookie, AuthClaims.Subject, "role"));
    }

    public static IServiceCollection AddAuthSchemes(this IServiceCollection services)
    {
        services.AddScoped<JwtBearerEventsHandler>();
        services.AddScoped<CookieEventsHandler>();

        services.AddAuthentication(AuthSchemes.Smart)
            // Un único esquema por request: con header Authorization se usa Bearer (y la cookie se ignora).
            .AddPolicyScheme(AuthSchemes.Smart, AuthSchemes.Smart, options =>
                options.ForwardDefaultSelector = ctx =>
                    ctx.Request.Headers.Authorization.Count > 0 ? AuthSchemes.Bearer : AuthSchemes.Cookie)
            .AddJwtBearer(AuthSchemes.Bearer, options =>
            {
                options.MapInboundClaims = false;
                options.EventsType = typeof(JwtBearerEventsHandler);
            })
            .AddCookie(AuthSchemes.Cookie, options =>
            {
                options.Cookie.Name = CookieName;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.Path = "/";
                options.Cookie.Domain = null;
                options.Cookie.IsEssential = true;
                options.SlidingExpiration = true;
                options.EventsType = typeof(CookieEventsHandler);
            });

        services.AddOptions<CookieAuthenticationOptions>(AuthSchemes.Cookie)
            .Configure<IOptions<UserSessionOptions>>((options, sessions) => options.ExpireTimeSpan = sessions.Value.Sliding);

        services.AddAntiforgery(options =>
        {
            options.HeaderName = Filters.AntiforgeryForCookiesFilter.HeaderName;
            options.Cookie.Name = "__Host-xsrf";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.Path = "/";
            options.SuppressXFrameOptionsHeader = true; // ya lo pone SecurityHeadersMiddleware
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

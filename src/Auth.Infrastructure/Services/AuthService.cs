using Auth.Application.Abstractions;
using Auth.Infrastructure.Caching;
using Auth.Infrastructure.Email;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Persistence;
using Auth.Infrastructure.Security;
using Auth.Infrastructure.Tokens;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Flujos anónimos de autenticación. Repartido en archivos parciales por flujo (registro, login, contraseñas).
/// Regla general: las respuestas nunca revelan si un email está registrado.
/// </summary>
internal sealed partial class AuthService(
    UserManager<ApplicationUser> users,
    IPasswordHasher<ApplicationUser> hasher,
    IPasswordService passwords,
    AppDbContext db,
    SessionService sessions,
    ITokenService tokens,
    IPermissionService permissions,
    AccountLockout lockout,
    TotpVerifier totp,
    MfaChallengeProtector mfaChallenges,
    IEmailSender email,
    EmailTemplates templates,
    IAuditLogger audit,
    IClientInfo client,
    TimedCache cache,
    TimeProvider time,
    DummyPasswordHash dummyHash,
    IOptions<FeatureOptions> features,
    IOptions<EmailTokenOptions> tokenOptions,
    IOptions<UserSessionOptions> sessionOptions,
    ILogger<AuthService> logger) : IAuthService
{
    private DateTime UtcNow => time.GetUtcNow().UtcDateTime;
}

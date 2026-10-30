using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Auth;
using Auth.Domain.Audit;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Security;
using Auth.Infrastructure.Tokens;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Services;

internal sealed partial class AuthService
{
    private static readonly Error InvalidCredentials = Error.Unauthorized(ErrorCodes.InvalidCredentials, "Invalid email or password.");
    private static readonly Error RefreshInvalid = Error.Unauthorized(ErrorCodes.RefreshInvalid, "The refresh token is invalid or has expired.");
    private const int RefreshAttempts = 5;

    public async Task<Result<LoginResult>> LoginAsync(LoginRequest request, SessionKind kind, CancellationToken cancellationToken)
    {
        var normalizedEmail = EmailNormalizer.Normalize(request.Email);
        var user = await users.FindByEmailAsync(normalizedEmail);

        if (user is null)
        {
            dummyHash.Verify(request.Password);
            await audit.LogAsync(new AuditEntry(AuditEventType.LoginFailed, false, Email: normalizedEmail,
                Details: new Dictionary<string, object?> { ["reason"] = "unknown_user" }), cancellationToken);
            return InvalidCredentials;
        }

        if (lockout.IsLockedOut(user))
        {
            dummyHash.Verify(request.Password);
            await audit.LogAsync(new AuditEntry(AuditEventType.LoginLockedOut, false, user.Id, normalizedEmail), cancellationToken);
            return InvalidCredentials;
        }

        // CheckPasswordAsync re-hashea automáticamente si el hasher devuelve SuccessRehashNeeded.
        if (!await users.CheckPasswordAsync(user, request.Password))
        {
            var locked = await lockout.RecordFailureAsync(user);
            await audit.LogAsync(new AuditEntry(locked ? AuditEventType.LoginLockedOut : AuditEventType.LoginFailed, false, user.Id, normalizedEmail,
                Details: new Dictionary<string, object?> { ["reason"] = "invalid_password" }), cancellationToken);
            return InvalidCredentials;
        }

        // Solo se revela con la contraseña correcta.
        if (!user.EmailConfirmed)
        {
            await audit.LogAsync(new AuditEntry(AuditEventType.LoginEmailNotConfirmed, false, user.Id, normalizedEmail), cancellationToken);
            return Error.Forbidden(ErrorCodes.EmailNotConfirmed, "The email address has not been confirmed.");
        }

        if (user.TwoFactorEnabled)
        {
            // Todavía no hay sesión ni se resetea el contador de fallos: los errores de MFA siguen sumando.
            var challenge = mfaChallenges.Protect(user.Id, await users.GetSecurityStampAsync(user), kind == SessionKind.Cookie);
            await audit.LogAsync(new AuditEntry(AuditEventType.MfaChallengeIssued, true, user.Id, normalizedEmail), cancellationToken);
            return LoginResult.MfaRequired(challenge);
        }

        await lockout.ResetAsync(user);
        return await CompleteLoginAsync(user, kind, LoginMethod.Password, cancellationToken);
    }

    public async Task<Result<LoginResult>> LoginMfaAsync(LoginMfaRequest request, SessionKind kind, CancellationToken cancellationToken)
    {
        var mfaInvalid = Error.Unauthorized(ErrorCodes.MfaInvalid, "The verification code or MFA token is invalid or has expired.");

        var challenge = mfaChallenges.Unprotect(request.MfaToken);
        if (challenge is null || challenge.UseCookies != (kind == SessionKind.Cookie))
        {
            return mfaInvalid;
        }

        var user = await users.FindByIdAsync(challenge.UserId.ToString());
        if (user is null
            || !user.TwoFactorEnabled
            || lockout.IsLockedOut(user)
            || !string.Equals(await users.GetSecurityStampAsync(user), challenge.SecurityStamp, StringComparison.Ordinal))
        {
            await audit.LogAsync(new AuditEntry(AuditEventType.MfaFailed, false, user?.Id, user?.Email,
                Details: new Dictionary<string, object?> { ["reason"] = "challenge_rejected" }), cancellationToken);
            return mfaInvalid;
        }

        var usedRecoveryCode = !string.IsNullOrWhiteSpace(request.RecoveryCode);
        var verified = usedRecoveryCode
            ? (await users.RedeemTwoFactorRecoveryCodeAsync(user, AppUserStore.NormalizeCode(request.RecoveryCode!))).Succeeded
            : await totp.VerifyAsync(user, request.Code!);

        if (!verified)
        {
            var locked = await lockout.RecordFailureAsync(user);
            await audit.LogAsync(new AuditEntry(locked ? AuditEventType.LoginLockedOut : AuditEventType.MfaFailed, false, user.Id, user.Email,
                Details: new Dictionary<string, object?> { ["method"] = usedRecoveryCode ? "recovery_code" : "totp" }), cancellationToken);
            return mfaInvalid;
        }

        // Uso único del challenge: si dos requests compiten, solo una crea sesión.
        if (!mfaChallenges.TryConsume(challenge))
        {
            return mfaInvalid;
        }

        await lockout.ResetAsync(user);

        if (usedRecoveryCode)
        {
            var remaining = await users.CountRecoveryCodesAsync(user);
            await audit.LogAsync(new AuditEntry(AuditEventType.RecoveryCodeUsed, true, user.Id, user.Email,
                Details: new Dictionary<string, object?> { ["remaining"] = remaining }), cancellationToken);
            await email.SendAsync(templates.RecoveryCodeUsed(user.Email!, remaining), cancellationToken);
        }

        return await CompleteLoginAsync(user, kind, usedRecoveryCode ? LoginMethod.RecoveryCode : LoginMethod.PasswordMfa, cancellationToken);
    }

    private async Task<Result<LoginResult>> CompleteLoginAsync(ApplicationUser user, SessionKind kind, LoginMethod method, CancellationToken cancellationToken)
    {
        var created = await sessions.CreateAsync(user.Id, kind, method, cancellationToken);
        var session = created.Session;

        user.LastLoginAt = UtcNow;
        user.UpdatedAt = UtcNow;
        await users.UpdateAsync(user);

        TokenResponse? tokenResponse = null;
        if (kind == SessionKind.Bearer)
        {
            var access = tokens.CreateAccessToken(new AccessTokenRequest(user.Id, session.Id, method, user.EmailConfirmed));
            tokenResponse = new TokenResponse(access.Token, access.ExpiresAt, created.RefreshToken!, session.ExpiresAt);
        }

        await audit.LogAsync(new AuditEntry(AuditEventType.LoginSucceeded, true, user.Id, user.Email, session.Id,
            Details: new Dictionary<string, object?> { ["kind"] = kind.ToString(), ["method"] = method.ToString() }), cancellationToken);

        var me = await AccountService.BuildMeAsync(user, permissions, cancellationToken);
        return new LoginResult(false, null, user.Id, session.Id, JwtTokenService.AuthenticationMethods(method), tokenResponse, me);
    }

    public async Task<Result<TokenResponse>> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken)
    {
        var hash = RefreshTokenGenerator.Hash(request.RefreshToken);
        var grace = sessionOptions.Value.RefreshGrace;

        for (var attempt = 0; attempt < RefreshAttempts; attempt++)
        {
            // Gracia: refrescos concurrentes con el mismo token reciben el mismo par.
            if (cache.TryGet<TokenResponse>(GraceKey(hash), out var cached))
            {
                return cached;
            }

            var now = UtcNow;
            var session = await db.Sessions.AsNoTracking().SingleOrDefaultAsync(s => s.RefreshTokenHash == hash, cancellationToken);
            if (session is null)
            {
                var previous = await db.Sessions.AsNoTracking().FirstOrDefaultAsync(s => s.PreviousRefreshTokenHash == hash, cancellationToken);
                if (previous is null)
                {
                    return RefreshInvalid;
                }

                if (previous.RefreshRotatedAt is { } rotatedAt && rotatedAt + grace > now && previous.IsActive(now))
                {
                    // Otra request lo rotó hace instantes y todavía no publicó el par en la gracia.
                    await Task.Delay(TimeSpan.FromMilliseconds(25 * (attempt + 1)), CancellationToken.None);
                    continue;
                }

                // Reutilización fuera de la gracia: el token pudo ser robado. Se corta la sesión entera.
                await sessions.RevokeAsync(previous.Id, RevocationReason.RefreshReuse, cancellationToken);
                await audit.LogAsync(new AuditEntry(AuditEventType.RefreshTokenReuseDetected, false, previous.UserId, SessionId: previous.Id), cancellationToken);
                return RefreshInvalid;
            }

            if (session.Kind != SessionKind.Bearer || !session.IsActive(now))
            {
                return RefreshInvalid;
            }

            var user = await users.FindByIdAsync(session.UserId.ToString());
            if (user is null || AccountLockout.IsAdminLocked(user))
            {
                return RefreshInvalid;
            }

            var newToken = RefreshTokenGenerator.Generate();
            var newHash = RefreshTokenGenerator.Hash(newToken);
            var expiresAt = session.SlideExpiration(now, sessionOptions.Value.Sliding);
            var ip = Domain.Common.Text.Truncate(client.IpAddress, Session.MaxIpAddressLength);
            var ua = Domain.Common.Text.Truncate(client.UserAgent, Session.MaxUserAgentLength);

            // Update condicional: solo una request concurrente gana la rotación.
            var affected = await db.Sessions
                .Where(s => s.Id == session.Id && s.RefreshTokenHash == hash && s.RevokedAt == null)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(x => x.RefreshTokenHash, newHash)
                    .SetProperty(x => x.PreviousRefreshTokenHash, hash)
                    .SetProperty(x => x.RefreshRotatedAt, now)
                    .SetProperty(x => x.ExpiresAt, expiresAt)
                    .SetProperty(x => x.LastSeenAt, now)
                    .SetProperty(x => x.IpAddress, ip)
                    .SetProperty(x => x.UserAgent, ua), cancellationToken);

            if (affected == 0)
            {
                continue;
            }

            var access = tokens.CreateAccessToken(new AccessTokenRequest(user.Id, session.Id, session.LoginMethod, user.EmailConfirmed));
            var response = new TokenResponse(access.Token, access.ExpiresAt, newToken, expiresAt);
            if (grace > TimeSpan.Zero)
            {
                cache.Set(GraceKey(hash), response, grace);
            }

            await audit.LogAsync(new AuditEntry(AuditEventType.TokenRefreshed, true, user.Id, SessionId: session.Id), cancellationToken);
            return response;
        }

        return RefreshInvalid;
    }

    private static string GraceKey(string hash) => $"refresh-grace:{hash}";
}

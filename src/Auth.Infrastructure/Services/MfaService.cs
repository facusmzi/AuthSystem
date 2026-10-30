using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Account;
using Auth.Domain.Audit;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Email;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Services;

internal sealed class MfaService(
    UserManager<ApplicationUser> users,
    TotpVerifier totp,
    AccountLockout lockout,
    SessionService sessions,
    IEmailSender email,
    EmailTemplates templates,
    IAuditLogger audit,
    IOptions<MfaOptions> options) : IMfaService
{
    private static readonly Error MfaInvalid = Error.BadRequest(ErrorCodes.MfaInvalid, "The verification code is invalid.");

    public async Task<Result<MfaStatusResponse>> GetStatusAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        var left = user.TwoFactorEnabled ? await users.CountRecoveryCodesAsync(user) : 0;
        return new MfaStatusResponse(user.TwoFactorEnabled, left);
    }

    public async Task<Result<MfaSetupResponse>> SetupAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        if (user.TwoFactorEnabled)
        {
            return Error.Conflict("Two-factor authentication is already enabled. Disable it first to set up a new authenticator.");
        }

        await users.ResetAuthenticatorKeyAsync(user);
        var key = await users.GetAuthenticatorKeyAsync(user)
            ?? throw new InvalidOperationException("The authenticator key could not be generated.");

        await audit.LogAsync(new AuditEntry(AuditEventType.MfaSetupStarted, true, user.Id, user.Email), cancellationToken);
        return new MfaSetupResponse(FormatKey(key), OtpAuthUri(user.Email!, key));
    }

    public async Task<Result<RecoveryCodesResponse>> EnableAsync(Guid userId, Guid? currentSessionId, string code, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        if (user.TwoFactorEnabled)
        {
            return Error.Conflict("Two-factor authentication is already enabled.");
        }

        if (await users.GetAuthenticatorKeyAsync(user) is null)
        {
            return Error.BadRequest(ErrorCodes.MfaInvalid, "Call the setup endpoint before enabling two-factor authentication.");
        }

        if (!await VerifyOrRecordFailureAsync(user, code, currentSessionId, cancellationToken))
        {
            return MfaInvalid;
        }

        await users.SetTwoFactorEnabledAsync(user, true);
        var codes = (await users.GenerateNewTwoFactorRecoveryCodesAsync(user, options.Value.RecoveryCodes))?.ToList() ?? [];

        var revoked = await sessions.RevokeAllAsync(user.Id, RevocationReason.MfaChanged, currentSessionId, cancellationToken);
        await email.SendAsync(templates.MfaEnabled(user.Email!), cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.MfaEnabled, true, user.Id, user.Email, currentSessionId,
            Details: new Dictionary<string, object?> { ["revokedSessions"] = revoked }), cancellationToken);
        return new RecoveryCodesResponse(codes);
    }

    public async Task<Result> DisableAsync(Guid userId, Guid? currentSessionId, DisableMfaRequest request, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        if (!user.TwoFactorEnabled)
        {
            return Error.Conflict("Two-factor authentication is not enabled.");
        }

        if (lockout.IsLockedOut(user) || !await users.CheckPasswordAsync(user, request.Password))
        {
            if (!lockout.IsLockedOut(user))
            {
                await lockout.RecordFailureAsync(user);
            }

            await audit.LogAsync(new AuditEntry(AuditEventType.MfaFailed, false, user.Id, user.Email, currentSessionId,
                Details: new Dictionary<string, object?> { ["operation"] = "disable", ["reason"] = "invalid_password" }), cancellationToken);
            return Error.BadRequest(ErrorCodes.InvalidCredentials, "The password is incorrect.");
        }

        if (!await VerifyOrRecordFailureAsync(user, request.Code, currentSessionId, cancellationToken))
        {
            return MfaInvalid;
        }

        await users.SetTwoFactorEnabledAsync(user, false);
        await users.ResetAuthenticatorKeyAsync(user); // la clave anterior deja de servir
        await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 0);

        var revoked = await sessions.RevokeAllAsync(user.Id, RevocationReason.MfaChanged, currentSessionId, cancellationToken);
        await email.SendAsync(templates.MfaDisabled(user.Email!), cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.MfaDisabled, true, user.Id, user.Email, currentSessionId,
            Details: new Dictionary<string, object?> { ["revokedSessions"] = revoked }), cancellationToken);
        return Result.Success();
    }

    public async Task<Result<RecoveryCodesResponse>> RegenerateRecoveryCodesAsync(Guid userId, string code, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        if (!user.TwoFactorEnabled)
        {
            return Error.Conflict("Two-factor authentication is not enabled.");
        }

        if (!await VerifyOrRecordFailureAsync(user, code, null, cancellationToken))
        {
            return MfaInvalid;
        }

        var codes = (await users.GenerateNewTwoFactorRecoveryCodesAsync(user, options.Value.RecoveryCodes))?.ToList() ?? [];
        await audit.LogAsync(new AuditEntry(AuditEventType.RecoveryCodesRegenerated, true, user.Id, user.Email), cancellationToken);
        return new RecoveryCodesResponse(codes);
    }

    private async Task<bool> VerifyOrRecordFailureAsync(ApplicationUser user, string code, Guid? sessionId, CancellationToken cancellationToken)
    {
        if (!lockout.IsLockedOut(user) && await totp.VerifyAsync(user, code))
        {
            return true;
        }

        if (!lockout.IsLockedOut(user))
        {
            await lockout.RecordFailureAsync(user);
        }

        await audit.LogAsync(new AuditEntry(AuditEventType.MfaFailed, false, user.Id, user.Email, sessionId), cancellationToken);
        return false;
    }

    private string OtpAuthUri(string email, string key)
    {
        var issuer = Uri.EscapeDataString(options.Value.Issuer);
        return $"otpauth://totp/{issuer}:{Uri.EscapeDataString(email)}?secret={key}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
    }

    /// <summary>Clave en grupos de 4 para tipearla a mano en la app autenticadora.</summary>
    private static string FormatKey(string key) =>
        string.Join(' ', key.ToLowerInvariant().Chunk(4).Select(c => new string(c)));
}

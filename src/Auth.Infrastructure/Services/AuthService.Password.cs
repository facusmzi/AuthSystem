using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Auth;
using Auth.Domain.Audit;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Security;

namespace Auth.Infrastructure.Services;

internal sealed partial class AuthService
{
    private static readonly Error InvalidResetToken = Error.BadRequest(ErrorCodes.InvalidToken, "The token is invalid or has expired.");

    public async Task<Result> ForgotPasswordAsync(EmailRequest request, CancellationToken cancellationToken)
    {
        var user = await users.FindByEmailAsync(EmailNormalizer.Normalize(request.Email));
        if (user is { EmailConfirmed: true } && !AccountLockout.IsAdminLocked(user) && TryStartEmailCooldown("password-reset", user.Id))
        {
            var token = await users.GeneratePasswordResetTokenAsync(user);
            await email.SendAsync(templates.PasswordReset(user.Email!, token, tokenOptions.Value.PasswordResetMinutes), cancellationToken);
            await audit.LogAsync(new AuditEntry(AuditEventType.PasswordResetRequested, true, user.Id, user.Email), cancellationToken);
        }

        return Result.Success();
    }

    public async Task<Result> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        var user = await users.FindByEmailAsync(EmailNormalizer.Normalize(request.Email));
        if (user is null || AccountLockout.IsAdminLocked(user))
        {
            await audit.LogAsync(new AuditEntry(AuditEventType.PasswordResetFailed, false, user?.Id, EmailNormalizer.Normalize(request.Email)), cancellationToken);
            return InvalidResetToken;
        }

        // Identity valida primero el token (incluye el security stamp → uso único) y después la política.
        var result = await users.ResetPasswordAsync(user, request.Token, request.NewPassword);
        if (!result.Succeeded)
        {
            await audit.LogAsync(new AuditEntry(AuditEventType.PasswordResetFailed, false, user.Id, user.Email), cancellationToken);
            return result.Errors.Any(e => e.Code == "InvalidToken")
                ? InvalidResetToken
                : IdentityErrors.ToPasswordError(result.Errors, "newPassword");
        }

        var now = UtcNow;
        user.PasswordChangedAt = now;
        user.UpdatedAt = now;
        user.AccessFailedCount = 0;
        user.LockoutEnd = null;
        await users.UpdateAsync(user);

        var revoked = await sessions.RevokeAllAsync(user.Id, RevocationReason.PasswordReset, exceptSessionId: null, cancellationToken);
        await email.SendAsync(templates.PasswordResetCompleted(user.Email!), cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.PasswordResetCompleted, true, user.Id, user.Email,
            Details: new Dictionary<string, object?> { ["revokedSessions"] = revoked }), cancellationToken);
        return Result.Success();
    }
}

using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Account;
using Auth.Domain.Audit;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Email;
using Auth.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;

namespace Auth.Infrastructure.Services;

internal sealed class AccountService(
    UserManager<ApplicationUser> users,
    IPermissionService permissions,
    SessionService sessions,
    AccountLockout lockout,
    IEmailSender email,
    EmailTemplates templates,
    IAuditLogger audit,
    TimeProvider time) : IAccountService
{
    public async Task<Result<MeResponse>> GetMeAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        return await BuildMeAsync(user, permissions, cancellationToken);
    }

    public async Task<Result> ChangePasswordAsync(Guid userId, Guid? currentSessionId, ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        // Con una sesión robada no se puede adivinar la contraseña actual: los fallos cuentan para el lockout.
        if (lockout.IsLockedOut(user) || !await users.CheckPasswordAsync(user, request.CurrentPassword))
        {
            if (!lockout.IsLockedOut(user))
            {
                await lockout.RecordFailureAsync(user);
            }

            await audit.LogAsync(new AuditEntry(AuditEventType.PasswordChangeFailed, false, userId, user.Email, currentSessionId), cancellationToken);
            return Error.BadRequest(ErrorCodes.InvalidCredentials, "The current password is incorrect.");
        }

        var result = await users.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            return IdentityErrors.ToPasswordError(result.Errors, "newPassword");
        }

        var now = time.GetUtcNow().UtcDateTime;
        user.PasswordChangedAt = now;
        user.UpdatedAt = now;
        user.AccessFailedCount = 0;
        await users.UpdateAsync(user);

        var revoked = await sessions.RevokeAllAsync(userId, RevocationReason.PasswordChanged, currentSessionId, cancellationToken);
        await email.SendAsync(templates.PasswordChanged(user.Email!), cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.PasswordChanged, true, userId, user.Email, currentSessionId,
            Details: new Dictionary<string, object?> { ["revokedSessions"] = revoked }), cancellationToken);
        return Result.Success();
    }

    internal static async Task<MeResponse> BuildMeAsync(ApplicationUser user, IPermissionService permissions, CancellationToken cancellationToken)
    {
        var roles = await permissions.GetRolesAsync(user.Id, cancellationToken);
        var perms = await permissions.GetPermissionsAsync(user.Id, cancellationToken);
        return new MeResponse(
            user.Id,
            user.Email!,
            user.EmailConfirmed,
            user.TwoFactorEnabled,
            roles,
            perms.Order(StringComparer.Ordinal).ToList(),
            user.CreatedAt);
    }
}

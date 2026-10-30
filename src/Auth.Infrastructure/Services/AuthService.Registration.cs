using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Auth;
using Auth.Domain.Audit;
using Auth.Domain.Authorization;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

internal sealed partial class AuthService
{
    private static readonly Error InvalidConfirmationToken = Error.BadRequest(ErrorCodes.InvalidToken, "The token is invalid or has expired.");

    public async Task<Result> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken)
    {
        var normalizedEmail = EmailNormalizer.Normalize(request.Email);

        // 1) Política de contraseña ANTES de mirar si el email existe: la respuesta 422 no depende de la cuenta.
        var passwordCheck = await passwords.ValidateNewPasswordAsync(normalizedEmail, request.Password, cancellationToken);
        if (!passwordCheck.IsSuccess)
        {
            return passwordCheck;
        }

        // 2) Whitelist beta (opcional): se responde igual que un registro normal, sin crear nada.
        if (features.Value.BetaWhitelist && !await IsWhitelistedAsync(normalizedEmail, cancellationToken))
        {
            dummyHash.Verify(request.Password);
            await audit.LogAsync(new AuditEntry(AuditEventType.RegistrationRejectedWhitelist, false, Email: normalizedEmail), cancellationToken);
            return Result.Success();
        }

        // 3) Email existente: avisar al dueño real en vez de devolver 409.
        var existing = await users.FindByEmailAsync(normalizedEmail);
        if (existing is not null)
        {
            dummyHash.Verify(request.Password);
            await NotifyExistingAccountAsync(existing, cancellationToken);
            return Result.Success();
        }

        var now = UtcNow;
        var user = new ApplicationUser
        {
            Id = Guid.CreateVersion7(),
            Email = normalizedEmail,
            UserName = normalizedEmail,
            CreatedAt = now,
            UpdatedAt = now,
            PasswordChangedAt = now,
        };
        user.PasswordHash = hasher.HashPassword(user, request.Password);

        IdentityResult created;
        try
        {
            created = await users.CreateAsync(user);
        }
        catch (DbUpdateException)
        {
            // Carrera con otro registro del mismo email: se comporta como "email existente".
            db.ChangeTracker.Clear();
            existing = await users.FindByEmailAsync(normalizedEmail);
            if (existing is not null)
            {
                await NotifyExistingAccountAsync(existing, cancellationToken);
            }
            return Result.Success();
        }

        if (!created.Succeeded)
        {
            if (created.Errors.Any(e => e.Code is "DuplicateEmail" or "DuplicateUserName"))
            {
                return Result.Success();
            }

            logger.LogError("User creation failed: {Errors}", string.Join(", ", created.Errors.Select(e => e.Code)));
            return new Error(ErrorCodes.InternalError, "The account could not be created.", 500);
        }

        var roleResult = await users.AddToRoleAsync(user, SystemRoles.User);
        if (!roleResult.Succeeded)
        {
            logger.LogError("Could not assign default role: {Errors}", string.Join(", ", roleResult.Errors.Select(e => e.Code)));
        }

        if (features.Value.BetaWhitelist)
        {
            var entry = await db.BetaWhitelist.FindAsync([normalizedEmail], cancellationToken);
            entry?.Consume(now);
            await db.SaveChangesAsync(cancellationToken);
        }

        await SendConfirmationAsync(user, cancellationToken);
        await audit.LogAsync(new AuditEntry(AuditEventType.Registered, true, user.Id, normalizedEmail), cancellationToken);
        return Result.Success();
    }

    public async Task<Result> ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(request.UserId.ToString());
        if (user is null)
        {
            await audit.LogAsync(new AuditEntry(AuditEventType.EmailConfirmationFailed, false), cancellationToken);
            return InvalidConfirmationToken;
        }

        var result = await users.ConfirmEmailAsync(user, request.Token);
        if (!result.Succeeded)
        {
            await audit.LogAsync(new AuditEntry(AuditEventType.EmailConfirmationFailed, false, user.Id, user.Email), cancellationToken);
            return InvalidConfirmationToken;
        }

        await audit.LogAsync(new AuditEntry(AuditEventType.EmailConfirmed, true, user.Id, user.Email), cancellationToken);
        return Result.Success();
    }

    public async Task<Result> ResendConfirmationAsync(EmailRequest request, CancellationToken cancellationToken)
    {
        var user = await users.FindByEmailAsync(EmailNormalizer.Normalize(request.Email));
        if (user is { EmailConfirmed: false } && TryStartEmailCooldown("resend-confirmation", user.Id))
        {
            await SendConfirmationAsync(user, cancellationToken);
            await audit.LogAsync(new AuditEntry(AuditEventType.ConfirmationResent, true, user.Id, user.Email), cancellationToken);
        }

        return Result.Success();
    }

    private async Task SendConfirmationAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        var token = await users.GenerateEmailConfirmationTokenAsync(user);
        await email.SendAsync(templates.ConfirmEmail(user.Email!, user.Id, token, tokenOptions.Value.EmailConfirmationHours), cancellationToken);
    }

    private async Task NotifyExistingAccountAsync(ApplicationUser existing, CancellationToken cancellationToken)
    {
        if (TryStartEmailCooldown("registration-attempt", existing.Id))
        {
            await email.SendAsync(templates.RegistrationAttempt(existing.Email!), cancellationToken);
        }

        await audit.LogAsync(new AuditEntry(AuditEventType.RegistrationAttemptExistingEmail, false, existing.Id, existing.Email), cancellationToken);
    }

    private Task<bool> IsWhitelistedAsync(string normalizedEmail, CancellationToken cancellationToken) =>
        db.BetaWhitelist.AnyAsync(e => e.NormalizedEmail == normalizedEmail && e.ConsumedAt == null, cancellationToken);

    /// <summary>Cooldown real por usuario y tipo de mail (además del rate limit por IP).</summary>
    private bool TryStartEmailCooldown(string kind, Guid userId) =>
        cache.TryAdd($"email-cooldown:{kind}:{userId:N}", TimeSpan.FromSeconds(tokenOptions.Value.EmailCooldownSeconds));
}

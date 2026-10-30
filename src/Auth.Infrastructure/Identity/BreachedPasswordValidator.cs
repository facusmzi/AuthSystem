using Auth.Application.Abstractions;
using Auth.Domain.Audit;
using Auth.Infrastructure.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Identity;

/// <summary>Rechaza contraseñas que aparecen en filtraciones conocidas (Have I Been Pwned).</summary>
public sealed class BreachedPasswordValidator(
    IPasswordBreachChecker checker,
    IOptions<HibpOptions> options,
    IAuditLogger audit,
    ILogger<BreachedPasswordValidator> logger) : IPasswordValidator<ApplicationUser>
{
    public const string Code = "PasswordBreached";
    public const string UnavailableCode = "PasswordBreachCheckUnavailable";

    public async Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user, string? password)
    {
        if (!options.Value.Enabled || string.IsNullOrEmpty(password))
        {
            return IdentityResult.Success;
        }

        var status = await checker.CheckAsync(password, CancellationToken.None);
        switch (status)
        {
            case BreachCheckStatus.Breached:
                return IdentityResult.Failed(new IdentityError
                {
                    Code = Code,
                    Description = "This password has appeared in a data breach and cannot be used.",
                });

            case BreachCheckStatus.Unavailable:
                await audit.LogAsync(new AuditEntry(AuditEventType.PasswordBreachCheckUnavailable, false,
                    UserId: user.Id == Guid.Empty ? null : user.Id,
                    Details: new Dictionary<string, object?> { ["failOpen"] = options.Value.FailOpen }));

                if (options.Value.FailOpen)
                {
                    logger.LogWarning("HIBP unavailable: password accepted without breach check (fail-open)");
                    return IdentityResult.Success;
                }

                return IdentityResult.Failed(new IdentityError
                {
                    Code = UnavailableCode,
                    Description = "The password could not be verified right now. Please try again later.",
                });

            default:
                return IdentityResult.Success;
        }
    }
}

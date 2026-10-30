using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;

namespace Auth.Infrastructure.Services;

internal sealed class PasswordService(UserManager<ApplicationUser> users) : IPasswordService
{
    public async Task<Result> ValidateNewPasswordAsync(string email, string password, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var probe = new ApplicationUser { Email = email, UserName = email };
        var errors = new List<IdentityError>();
        foreach (var validator in users.PasswordValidators)
        {
            var result = await validator.ValidateAsync(users, probe, password);
            errors.AddRange(result.Errors);
        }

        return errors.Count == 0 ? Result.Success() : IdentityErrors.ToPasswordError(errors);
    }
}

internal static class IdentityErrors
{
    /// <summary>422 con errores en el campo indicado; <c>PASSWORD_BREACHED</c> tiene prioridad.</summary>
    public static Error ToPasswordError(IEnumerable<IdentityError> errors, string field = "password")
    {
        var list = errors.ToList();
        var code = list.Any(e => e.Code == BreachedPasswordValidator.Code) ? ErrorCodes.PasswordBreached : ErrorCodes.PasswordTooWeak;
        var message = code == ErrorCodes.PasswordBreached
            ? "This password has appeared in a data breach. Choose a different one."
            : "The password does not meet the password policy.";

        return Error.Validation(new Dictionary<string, string[]>
        {
            [field] = list.Select(e => e.Description).Distinct().ToArray(),
        }, code, message);
    }

    public static bool IsPasswordError(IdentityError error) => error.Code.StartsWith("Password", StringComparison.Ordinal);
}

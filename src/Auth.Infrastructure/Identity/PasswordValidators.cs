using Auth.Infrastructure.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Identity;

/// <summary>Tope de longitud (NIST SP 800-63B recomienda aceptar al menos 64; usamos 128 por defecto).</summary>
public sealed class MaxLengthPasswordValidator(IOptions<PasswordPolicyOptions> options) : IPasswordValidator<ApplicationUser>
{
    public const string Code = "PasswordTooLong";

    public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user, string? password)
    {
        var max = options.Value.MaxLength;
        return Task.FromResult(password is not null && password.Length > max
            ? IdentityResult.Failed(new IdentityError { Code = Code, Description = $"Passwords must be at most {max} characters." })
            : IdentityResult.Success);
    }
}

/// <summary>Rechaza contraseñas iguales al email (o a su parte local).</summary>
public sealed class EmailAsPasswordValidator : IPasswordValidator<ApplicationUser>
{
    public const string Code = "PasswordEqualsEmail";

    public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user, string? password)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(user.Email))
        {
            return Task.FromResult(IdentityResult.Success);
        }

        var email = user.Email.Trim();
        var localPart = email.Split('@')[0];
        var candidate = password.Trim();

        var matches = string.Equals(candidate, email, StringComparison.OrdinalIgnoreCase)
            || (localPart.Length >= 4 && string.Equals(candidate, localPart, StringComparison.OrdinalIgnoreCase));

        return Task.FromResult(matches
            ? IdentityResult.Failed(new IdentityError { Code = Code, Description = "Password must not be your email address." })
            : IdentityResult.Success);
    }
}

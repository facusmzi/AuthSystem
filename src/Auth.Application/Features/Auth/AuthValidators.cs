using FluentValidation;

namespace Auth.Application.Features.Auth;

internal static class Rules
{
    /// <summary>RFC 5321: 254 caracteres como máximo para una dirección utilizable.</summary>
    public const int EmailMaxLength = 254;

    /// <summary>
    /// Tope defensivo para cualquier contraseña recibida (antes de hashear). La política real
    /// (12..128) la aplican los validadores de Identity y se informa con mensajes claros.
    /// </summary>
    public const int PasswordInputMaxLength = 1024;

    public const int TokenMaxLength = 2048;

    public static IRuleBuilderOptions<T, string> ValidEmail<T>(this IRuleBuilder<T, string> rule) =>
        rule.NotEmpty().MaximumLength(EmailMaxLength).EmailAddress();

    public static IRuleBuilderOptions<T, string> PasswordInput<T>(this IRuleBuilder<T, string> rule) =>
        rule.NotEmpty().MaximumLength(PasswordInputMaxLength);
}

public sealed class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        RuleFor(x => x.Email).ValidEmail();
        RuleFor(x => x.Password).PasswordInput();
    }
}

public sealed class ConfirmEmailRequestValidator : AbstractValidator<ConfirmEmailRequest>
{
    public ConfirmEmailRequestValidator()
    {
        RuleFor(x => x.UserId).NotEmpty();
        RuleFor(x => x.Token).NotEmpty().MaximumLength(Rules.TokenMaxLength);
    }
}

public sealed class EmailRequestValidator : AbstractValidator<EmailRequest>
{
    public EmailRequestValidator()
    {
        RuleFor(x => x.Email).ValidEmail();
    }
}

public sealed class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Email).ValidEmail();
        RuleFor(x => x.Password).PasswordInput();
    }
}

public sealed class LoginMfaRequestValidator : AbstractValidator<LoginMfaRequest>
{
    public LoginMfaRequestValidator()
    {
        RuleFor(x => x.MfaToken).NotEmpty().MaximumLength(Rules.TokenMaxLength);
        RuleFor(x => x)
            .Must(x => string.IsNullOrWhiteSpace(x.Code) != string.IsNullOrWhiteSpace(x.RecoveryCode))
            .WithName("code")
            .WithMessage("Provide exactly one of 'code' or 'recoveryCode'.");
        RuleFor(x => x.Code!).Matches("^[0-9]{6}$").When(x => !string.IsNullOrWhiteSpace(x.Code))
            .WithMessage("The code must be 6 digits.");
        RuleFor(x => x.RecoveryCode!).MaximumLength(64).When(x => x.RecoveryCode is not null);
    }
}

public sealed class RefreshRequestValidator : AbstractValidator<RefreshRequest>
{
    public RefreshRequestValidator()
    {
        RuleFor(x => x.RefreshToken).NotEmpty().MaximumLength(256);
    }
}

public sealed class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
{
    public ResetPasswordRequestValidator()
    {
        RuleFor(x => x.Email).ValidEmail();
        RuleFor(x => x.Token).NotEmpty().MaximumLength(Rules.TokenMaxLength);
        RuleFor(x => x.NewPassword).PasswordInput();
    }
}

using Auth.Application.Features.Auth;
using FluentValidation;

namespace Auth.Application.Features.Account;

public sealed class ChangePasswordRequestValidator : AbstractValidator<ChangePasswordRequest>
{
    public ChangePasswordRequestValidator()
    {
        RuleFor(x => x.CurrentPassword).PasswordInput();
        RuleFor(x => x.NewPassword).PasswordInput();
    }
}

public sealed class MfaCodeRequestValidator : AbstractValidator<MfaCodeRequest>
{
    public MfaCodeRequestValidator()
    {
        RuleFor(x => x.Code).NotEmpty().Matches("^[0-9]{6}$").WithMessage("The code must be 6 digits.");
    }
}

public sealed class DisableMfaRequestValidator : AbstractValidator<DisableMfaRequest>
{
    public DisableMfaRequestValidator()
    {
        RuleFor(x => x.Password).PasswordInput();
        RuleFor(x => x.Code).NotEmpty().Matches("^[0-9]{6}$").WithMessage("The code must be 6 digits.");
    }
}

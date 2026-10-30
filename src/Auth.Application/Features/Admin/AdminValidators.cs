using Auth.Domain.Authorization;
using FluentValidation;

namespace Auth.Application.Features.Admin;

public sealed class RoleRequestValidator : AbstractValidator<RoleRequest>
{
    public RoleRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().Length(2, 64).Matches("^[A-Za-z0-9][A-Za-z0-9 _.-]*$")
            .WithMessage("Role names may contain letters, digits, spaces, '_', '.' and '-'.");
        RuleFor(x => x.Description).MaximumLength(256);
        RuleFor(x => x.Permissions).NotNull();
        RuleForEach(x => x.Permissions).Must(Permissions.IsKnown).WithMessage("Unknown permission '{PropertyValue}'.");
    }
}

public sealed class SetUserRolesRequestValidator : AbstractValidator<SetUserRolesRequest>
{
    public SetUserRolesRequestValidator()
    {
        RuleFor(x => x.Roles).NotNull().Must(r => r.Count <= 32).WithMessage("Too many roles.");
        RuleForEach(x => x.Roles).NotEmpty().MaximumLength(64);
    }
}

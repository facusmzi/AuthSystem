using Auth.Application.Common;
using Auth.Application.Features.Auth;

namespace Auth.Application.Abstractions;

/// <summary>Flujos anónimos: registro, confirmación, login, refresh y recuperación de contraseña.</summary>
public interface IAuthService
{
    Task<Result> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken);

    Task<Result> ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken);

    Task<Result> ResendConfirmationAsync(EmailRequest request, CancellationToken cancellationToken);
}

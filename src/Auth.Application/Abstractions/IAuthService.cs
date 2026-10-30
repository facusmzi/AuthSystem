using Auth.Application.Common;
using Auth.Application.Features.Auth;
using Auth.Domain.Sessions;

namespace Auth.Application.Abstractions;

/// <summary>Flujos anónimos: registro, confirmación, login, refresh y recuperación de contraseña.</summary>
public interface IAuthService
{
    Task<Result> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken);

    Task<Result> ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken);

    Task<Result> ResendConfirmationAsync(EmailRequest request, CancellationToken cancellationToken);

    Task<Result<LoginResult>> LoginAsync(LoginRequest request, SessionKind kind, CancellationToken cancellationToken);

    Task<Result<LoginResult>> LoginMfaAsync(LoginMfaRequest request, SessionKind kind, CancellationToken cancellationToken);

    Task<Result<TokenResponse>> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken);

    Task<Result> ForgotPasswordAsync(EmailRequest request, CancellationToken cancellationToken);

    Task<Result> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken);
}

using Auth.Application.Features.Account;

namespace Auth.Application.Features.Auth;

public sealed record RegisterRequest(string Email, string Password);

public sealed record ConfirmEmailRequest(Guid UserId, string Token);

/// <summary>Reenvío de confirmación / olvidé mi contraseña.</summary>
public sealed record EmailRequest(string Email);

public sealed record LoginRequest(string Email, string Password);

/// <summary>Exactamente uno de <see cref="Code"/> o <see cref="RecoveryCode"/>.</summary>
public sealed record LoginMfaRequest(string MfaToken, string? Code, string? RecoveryCode);

public sealed record RefreshRequest(string RefreshToken);

public sealed record ResetPasswordRequest(string Email, string Token, string NewPassword);

public sealed record TokenResponse(
    string AccessToken,
    DateTime AccessTokenExpiresAt,
    string RefreshToken,
    DateTime RefreshTokenExpiresAt,
    string TokenType = "Bearer");

public sealed record LoginResponse(bool RequiresMfa, string? MfaToken, TokenResponse? Tokens, MeResponse? User);

public sealed record MessageResponse(string Message);

/// <summary>Resultado interno del login: el host decide cómo materializar la sesión (cookie o tokens).</summary>
public sealed record LoginResult(
    bool RequiresMfa,
    string? MfaToken,
    Guid? UserId,
    Guid? SessionId,
    IReadOnlyList<string> AuthenticationMethods,
    TokenResponse? Tokens,
    MeResponse? User)
{
    public static LoginResult MfaRequired(string mfaToken) => new(true, mfaToken, null, null, [], null, null);
}

using Auth.Application.Common;
using Auth.Application.Features.Account;

namespace Auth.Application.Abstractions;

/// <summary>Gestión de MFA (TOTP) de la cuenta autenticada.</summary>
public interface IMfaService
{
    Task<Result<MfaStatusResponse>> GetStatusAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>Genera una clave nueva. Solo con MFA desactivado (si no, la clave vigente dejaría de servir).</summary>
    Task<Result<MfaSetupResponse>> SetupAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>Activa MFA, devuelve los recovery codes (una sola vez) y revoca las demás sesiones.</summary>
    Task<Result<RecoveryCodesResponse>> EnableAsync(Guid userId, Guid? currentSessionId, string code, CancellationToken cancellationToken);

    /// <summary>Requiere contraseña y código. Revoca las demás sesiones.</summary>
    Task<Result> DisableAsync(Guid userId, Guid? currentSessionId, DisableMfaRequest request, CancellationToken cancellationToken);

    Task<Result<RecoveryCodesResponse>> RegenerateRecoveryCodesAsync(Guid userId, string code, CancellationToken cancellationToken);
}

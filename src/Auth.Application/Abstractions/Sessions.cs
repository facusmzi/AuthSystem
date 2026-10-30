using Auth.Application.Common;
using Auth.Application.Features.Sessions;
using Auth.Domain.Sessions;

namespace Auth.Application.Abstractions;

public interface ISessionService
{
    /// <summary>Sesiones activas del usuario, más recientes primero.</summary>
    Task<IReadOnlyList<SessionDto>> ListActiveAsync(Guid userId, Guid? currentSessionId, CancellationToken cancellationToken);

    /// <summary>Revoca una sesión propia. 404 si no existe o es de otro usuario (no se revela).</summary>
    Task<Result<RevokeSessionResponse>> RevokeOwnAsync(Guid userId, Guid sessionId, Guid? currentSessionId, CancellationToken cancellationToken);

    Task<bool> RevokeAsync(Guid sessionId, RevocationReason reason, CancellationToken cancellationToken);

    /// <summary>Revoca todas las sesiones activas del usuario, salvo <paramref name="exceptSessionId"/>.</summary>
    Task<int> RevokeAllAsync(Guid userId, RevocationReason reason, Guid? exceptSessionId, CancellationToken cancellationToken);

    Task LogoutAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken);

    Task LogoutAllAsync(Guid userId, Guid? currentSessionId, CancellationToken cancellationToken);
}

public enum SessionValidationResult
{
    Valid = 0,
    Invalid = 1,
}

/// <summary>
/// Valida contra la DB (con cache corta) que la sesión de un token/cookie siga activa. Toda revocación
/// invalida la entrada de cache, por lo que la revocación es prácticamente inmediata.
/// </summary>
public interface ISessionValidator
{
    Task<SessionValidationResult> ValidateAsync(Guid sessionId, Guid userId, CancellationToken cancellationToken);

    void Invalidate(Guid sessionId);
}

public sealed record AccessTokenRequest(Guid UserId, Guid SessionId, LoginMethod LoginMethod, bool EmailVerified);

public sealed record AccessToken(string Token, DateTime ExpiresAt);

public interface ITokenService
{
    AccessToken CreateAccessToken(AccessTokenRequest request);
}

public interface IPermissionService
{
    Task<IReadOnlySet<string>> GetPermissionsAsync(Guid userId, CancellationToken cancellationToken);

    Task<IReadOnlyList<string>> GetRolesAsync(Guid userId, CancellationToken cancellationToken);

    void InvalidateUser(Guid userId);

    /// <summary>Invalida el cache de todos los usuarios (cambió la definición de un rol).</summary>
    void InvalidateAll();
}

public interface IAccountService
{
    Task<Result<Features.Account.MeResponse>> GetMeAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>Cambia la contraseña y revoca todas las demás sesiones (la actual sigue).</summary>
    Task<Result> ChangePasswordAsync(Guid userId, Guid? currentSessionId, Features.Account.ChangePasswordRequest request, CancellationToken cancellationToken);
}

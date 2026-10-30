using Auth.Api.Errors;
using Auth.Application.Abstractions;
using Auth.Application.Common;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Authentication;

/// <summary>Firma válida no alcanza: la sesión del claim <c>sid</c> tiene que seguir activa.</summary>
public sealed class SessionRevokedException() : Exception("The session is no longer active.");

/// <summary>
/// Eventos del esquema Bearer: valida la sesión en DB (revocación inmediata) y responde 401/403 como
/// ProblemDetails con códigos estables en lugar del challenge vacío por defecto.
/// </summary>
public sealed class JwtBearerEventsHandler(ISessionValidator sessions) : JwtBearerEvents
{
    public override async Task TokenValidated(TokenValidatedContext context)
    {
        var principal = context.Principal!;
        if (!Guid.TryParse(principal.FindFirst(AuthClaims.Subject)?.Value, out var userId)
            || !Guid.TryParse(principal.FindFirst(AuthClaims.SessionId)?.Value, out var sessionId))
        {
            context.Fail(new SecurityTokenValidationException("Token is missing required claims."));
            return;
        }

        if (await sessions.ValidateAsync(sessionId, userId, context.HttpContext.RequestAborted) != SessionValidationResult.Valid)
        {
            context.Fail(new SessionRevokedException());
        }
    }

    public override async Task Challenge(JwtBearerChallengeContext context)
    {
        context.HandleResponse();

        var hasHeader = context.Request.Headers.Authorization.Count > 0;
        var (code, detail) = context.AuthenticateFailure switch
        {
            SecurityTokenExpiredException => (ErrorCodes.TokenExpired, "The access token has expired."),
            SessionRevokedException => (ErrorCodes.SessionRevoked, "The session has been revoked or has expired."),
            not null => (ErrorCodes.TokenInvalid, "The access token is invalid."),
            null when hasHeader => (ErrorCodes.TokenInvalid, "The Authorization header is malformed."),
            null => (ErrorCodes.AuthHeaderMissing, "Authentication is required."),
        };

        context.Response.Headers.WWWAuthenticate = hasHeader
            ? $"Bearer error=\"invalid_token\", error_description=\"{detail}\""
            : "Bearer";

        await Problems.WriteAsync(context.HttpContext, StatusCodes.Status401Unauthorized, code, "Unauthorized", detail);
    }

    public override Task Forbidden(ForbiddenContext context) =>
        Problems.WriteAsync(context.HttpContext, StatusCodes.Status403Forbidden, ErrorCodes.Forbidden, "Forbidden",
            "You do not have permission to perform this action.");
}

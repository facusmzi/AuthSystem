using Auth.Api.Errors;
using Auth.Application.Abstractions;
using Auth.Application.Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Auth.Api.Authentication;

/// <summary>
/// La cookie es la sesión: en cada request se valida su <c>sid</c> contra la DB (con cache corta). Es una API,
/// así que nunca redirige: responde 401/403 como ProblemDetails.
/// </summary>
public sealed class CookieEventsHandler(ISessionValidator sessions) : CookieAuthenticationEvents
{
    private const string RejectedItem = "auth:cookie-rejected";

    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var principal = context.Principal;
        var valid = Guid.TryParse(principal?.FindFirst(AuthClaims.Subject)?.Value, out var userId)
            && Guid.TryParse(principal?.FindFirst(AuthClaims.SessionId)?.Value, out var sessionId)
            && await sessions.ValidateAsync(sessionId, userId, context.HttpContext.RequestAborted) == SessionValidationResult.Valid;

        if (!valid)
        {
            context.RejectPrincipal();
            context.HttpContext.Items[RejectedItem] = true;
            await context.HttpContext.SignOutAsync(AuthSchemes.Cookie);
        }
    }

    public override async Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context)
    {
        var rejected = context.HttpContext.Items.ContainsKey(RejectedItem);
        if (!rejected)
        {
            context.Response.Headers.WWWAuthenticate = "Bearer";
        }

        await Problems.WriteAsync(context.HttpContext, StatusCodes.Status401Unauthorized,
            rejected ? ErrorCodes.SessionRevoked : ErrorCodes.AuthHeaderMissing,
            "Unauthorized",
            rejected ? "The session has been revoked or has expired." : "Authentication is required.");
    }

    public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context) =>
        Problems.WriteAsync(context.HttpContext, StatusCodes.Status403Forbidden, ErrorCodes.Forbidden, "Forbidden",
            "You do not have permission to perform this action.");

    public override Task RedirectToLogout(RedirectContext<CookieAuthenticationOptions> context)
    {
        context.Response.StatusCode = StatusCodes.Status204NoContent;
        return Task.CompletedTask;
    }

    public override Task RedirectToReturnUrl(RedirectContext<CookieAuthenticationOptions> context) => Task.CompletedTask;
}

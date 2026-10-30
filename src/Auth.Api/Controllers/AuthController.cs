using Auth.Api.Authentication;
using Auth.Api.Errors;
using Auth.Api.Options;
using Auth.Application.Abstractions;
using Auth.Application.Features.Auth;
using Auth.Domain.Sessions;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Auth.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
[Tags("Auth")]
public sealed class AuthController(IAuthService auth, ISessionService sessions, ICurrentUser currentUser) : ControllerBase
{
    private static readonly MessageResponse RegistrationAccepted = new("If the email is valid, you'll receive a confirmation link.");
    private static readonly MessageResponse EmailAccepted = new("If the email is registered, you'll receive an email shortly.");

    [HttpPost("register")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitingOptions.Strict)]
    [ProducesResponseType<MessageResponse>(StatusCodes.Status202Accepted)]
    [ProducesResponseType<HttpValidationProblemDetails>(StatusCodes.Status422UnprocessableEntity)]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken ct) =>
        (await auth.RegisterAsync(request, ct)).ToActionResult(() => Accepted(RegistrationAccepted));

    [HttpPost("confirm-email")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitingOptions.Strict)]
    [ProducesResponseType<MessageResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ConfirmEmail(ConfirmEmailRequest request, CancellationToken ct) =>
        (await auth.ConfirmEmailAsync(request, ct)).ToActionResult(() => Ok(new MessageResponse("Email confirmed.")));

    [HttpPost("resend-confirmation")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitingOptions.Strict)]
    [ProducesResponseType<MessageResponse>(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> ResendConfirmation(EmailRequest request, CancellationToken ct) =>
        (await auth.ResendConfirmationAsync(request, ct)).ToActionResult(() => Accepted(EmailAccepted));

    [HttpPost("login")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitingOptions.Login)]
    [ProducesResponseType<LoginResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> Login(LoginRequest request, [FromQuery] bool useCookies, CancellationToken ct)
    {
        var result = await auth.LoginAsync(request, useCookies ? SessionKind.Cookie : SessionKind.Bearer, ct);
        return result.IsSuccess ? await CompleteLoginAsync(result.Value) : result.Error.ToProblem();
    }

    /// <summary>
    /// Token antiforgery para la SPA (cookie <c>__Host-xsrf</c> + valor para el header <c>X-XSRF-TOKEN</c>).
    /// Está atado a la identidad: pedirlo de nuevo después del login y del logout.
    /// </summary>
    [HttpGet("antiforgery")]
    [AllowAnonymous]
    [ProducesResponseType<AntiforgeryTokenResponse>(StatusCodes.Status200OK)]
    public IActionResult AntiforgeryToken([FromServices] IAntiforgery antiforgery)
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        return Ok(new AntiforgeryTokenResponse(tokens.RequestToken!, tokens.HeaderName!));
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitingOptions.Refresh)]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh(RefreshRequest request, CancellationToken ct) =>
        (await auth.RefreshAsync(request, ct)).ToActionResult(t => Ok(t));

    [HttpPost("logout")]
    [Authorize(Policy = AuthPolicies.Authenticated)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        await sessions.LogoutAsync(currentUser.RequiredUserId, currentUser.RequiredSessionId, ct);
        await SignOutCookieAsync();
        return NoContent();
    }

    [HttpPost("logout-all")]
    [Authorize(Policy = AuthPolicies.Authenticated)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> LogoutAll(CancellationToken ct)
    {
        await sessions.LogoutAllAsync(currentUser.RequiredUserId, currentUser.SessionId, ct);
        await SignOutCookieAsync();
        return NoContent();
    }

    /// <summary>Materializa la sesión: cookie HttpOnly (SPA) o par de tokens (nativas/servicios).</summary>
    private async Task<IActionResult> CompleteLoginAsync(LoginResult result)
    {
        if (result.RequiresMfa)
        {
            return Ok(new LoginResponse(true, result.MfaToken, null, null));
        }

        if (result.Tokens is not null)
        {
            return Ok(new LoginResponse(false, null, result.Tokens, result.User));
        }

        var principal = AuthenticationSetup.CreateCookiePrincipal(result.UserId!.Value, result.SessionId!.Value, result.AuthenticationMethods);
        await HttpContext.SignInAsync(AuthSchemes.Cookie, principal, new AuthenticationProperties { IsPersistent = true });
        return Ok(new LoginResponse(false, null, null, result.User));
    }

    private async Task SignOutCookieAsync()
    {
        if (User.Identity?.AuthenticationType == AuthSchemes.Cookie)
        {
            await HttpContext.SignOutAsync(AuthSchemes.Cookie);
        }
    }
}

public sealed record AntiforgeryTokenResponse(string Token, string HeaderName);

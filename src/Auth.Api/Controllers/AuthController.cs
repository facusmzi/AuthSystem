using Auth.Api.Errors;
using Auth.Api.Options;
using Auth.Application.Abstractions;
using Auth.Application.Features.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Auth.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
[Tags("Auth")]
public sealed class AuthController(IAuthService auth) : ControllerBase
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
}

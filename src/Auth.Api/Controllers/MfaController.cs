using Auth.Api.Errors;
using Auth.Api.Options;
using Auth.Application.Abstractions;
using Auth.Application.Features.Account;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Auth.Api.Controllers;

/// <summary>Gestión de MFA (TOTP). Protegido por la fallback policy (autenticado + email verificado).</summary>
[ApiController]
[Route("api/v1/account/mfa")]
[Tags("Account")]
public sealed class MfaController(IMfaService mfa, ICurrentUser currentUser) : ControllerBase
{
    [HttpGet]
    [ProducesResponseType<MfaStatusResponse>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Status(CancellationToken ct) =>
        (await mfa.GetStatusAsync(currentUser.RequiredUserId, ct)).ToActionResult(s => Ok(s));

    /// <summary>Clave compartida + URI <c>otpauth://</c>; el cliente genera el QR.</summary>
    [HttpPost("setup")]
    [ProducesResponseType<MfaSetupResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Setup(CancellationToken ct) =>
        (await mfa.SetupAsync(currentUser.RequiredUserId, ct)).ToActionResult(s => Ok(s));

    [HttpPost("enable")]
    [EnableRateLimiting(RateLimitingOptions.Mfa)]
    [ProducesResponseType<RecoveryCodesResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Enable(MfaCodeRequest request, CancellationToken ct) =>
        (await mfa.EnableAsync(currentUser.RequiredUserId, currentUser.SessionId, request.Code, ct)).ToActionResult(c => Ok(c));

    [HttpPost("disable")]
    [EnableRateLimiting(RateLimitingOptions.Mfa)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Disable(DisableMfaRequest request, CancellationToken ct) =>
        (await mfa.DisableAsync(currentUser.RequiredUserId, currentUser.SessionId, request, ct)).ToActionResult(NoContent);

    [HttpPost("recovery-codes")]
    [EnableRateLimiting(RateLimitingOptions.Mfa)]
    [ProducesResponseType<RecoveryCodesResponse>(StatusCodes.Status200OK)]
    public async Task<IActionResult> RegenerateRecoveryCodes(MfaCodeRequest request, CancellationToken ct) =>
        (await mfa.RegenerateRecoveryCodesAsync(currentUser.RequiredUserId, request.Code, ct)).ToActionResult(c => Ok(c));
}

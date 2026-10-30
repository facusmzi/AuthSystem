using Auth.Api.Authentication;
using Auth.Api.Errors;
using Auth.Application.Abstractions;
using Auth.Application.Features.Account;
using Auth.Application.Features.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers;

/// <summary>Cuenta del usuario autenticado. Sin atributos: aplica la fallback policy (email verificado).</summary>
[ApiController]
[Route("api/v1/account")]
[Tags("Account")]
public sealed class AccountController(IAccountService account, ISessionService sessions, ICurrentUser currentUser) : ControllerBase
{
    [HttpGet("me")]
    [Authorize(Policy = AuthPolicies.Authenticated)]
    [ProducesResponseType<MeResponse>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Me(CancellationToken ct) =>
        (await account.GetMeAsync(currentUser.RequiredUserId, ct)).ToActionResult(me => Ok(me));

    [HttpGet("sessions")]
    [ProducesResponseType<IReadOnlyList<SessionDto>>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Sessions(CancellationToken ct) =>
        Ok(await sessions.ListActiveAsync(currentUser.RequiredUserId, currentUser.SessionId, ct));

    [HttpDelete("sessions/{id:guid}")]
    [ProducesResponseType<RevokeSessionResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RevokeSession(Guid id, CancellationToken ct) =>
        (await sessions.RevokeOwnAsync(currentUser.RequiredUserId, id, currentUser.SessionId, ct)).ToActionResult(r => Ok(r));
}

using Auth.Api.Authorization;
using Auth.Api.Errors;
using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Admin;
using Auth.Application.Features.Sessions;
using Auth.Domain.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers;

[ApiController]
[Route("api/v1/admin")]
[Tags("Admin")]
public sealed class AdminUsersController(IUserAdminService users, ICurrentUser currentUser) : ControllerBase
{
    [HttpGet("users")]
    [HasPermission(Permissions.UsersRead)]
    [ProducesResponseType<PagedResult<AdminUserDto>>(StatusCodes.Status200OK)]
    public async Task<IActionResult> List([FromQuery] string? search, [FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default) =>
        Ok(await users.ListAsync(search, page, pageSize, ct));

    [HttpGet("users/{id:guid}")]
    [HasPermission(Permissions.UsersRead)]
    [ProducesResponseType<AdminUserDto>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct) =>
        (await users.GetAsync(id, ct)).ToActionResult(u => Ok(u));

    [HttpPost("users/{id:guid}/lock")]
    [HasPermission(Permissions.UsersManage)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Lock(Guid id, CancellationToken ct) =>
        (await users.LockAsync(id, currentUser.RequiredUserId, ct)).ToActionResult(NoContent);

    [HttpPost("users/{id:guid}/unlock")]
    [HasPermission(Permissions.UsersManage)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Unlock(Guid id, CancellationToken ct) =>
        (await users.UnlockAsync(id, currentUser.RequiredUserId, ct)).ToActionResult(NoContent);

    [HttpPut("users/{id:guid}/roles")]
    [HasPermission(Permissions.RolesAssign)]
    [ProducesResponseType<AdminUserDto>(StatusCodes.Status200OK)]
    public async Task<IActionResult> SetRoles(Guid id, SetUserRolesRequest request, CancellationToken ct) =>
        (await users.SetRolesAsync(id, request.Roles, currentUser.RequiredUserId, ct)).ToActionResult(u => Ok(u));

    [HttpGet("users/{id:guid}/sessions")]
    [HasPermission(Permissions.SessionsReadAny)]
    [ProducesResponseType<IReadOnlyList<SessionDto>>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Sessions(Guid id, CancellationToken ct) =>
        (await users.ListSessionsAsync(id, ct)).ToActionResult(s => Ok(s));

    [HttpDelete("sessions/{id:guid}")]
    [HasPermission(Permissions.SessionsRevokeAny)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RevokeSession(Guid id, CancellationToken ct) =>
        (await users.RevokeSessionAsync(id, currentUser.RequiredUserId, ct)).ToActionResult(NoContent);
}

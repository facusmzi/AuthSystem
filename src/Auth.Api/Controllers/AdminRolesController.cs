using Auth.Api.Authorization;
using Auth.Api.Errors;
using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Admin;
using Auth.Domain.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers;

[ApiController]
[Route("api/v1/admin")]
[Tags("Admin")]
public sealed class AdminRolesController(IRoleAdminService roles, ICurrentUser currentUser) : ControllerBase
{
    [HttpGet("roles")]
    [HasPermission(Permissions.RolesRead)]
    [ProducesResponseType<IReadOnlyList<RoleDto>>(StatusCodes.Status200OK)]
    public async Task<IActionResult> List(CancellationToken ct) => Ok(await roles.ListAsync(ct));

    [HttpGet("roles/{id:guid}")]
    [HasPermission(Permissions.RolesRead)]
    [ProducesResponseType<RoleDto>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct) =>
        (await roles.GetAsync(id, ct)).ToActionResult(r => Ok(r));

    [HttpPost("roles")]
    [HasPermission(Permissions.RolesManage)]
    [ProducesResponseType<RoleDto>(StatusCodes.Status201Created)]
    public async Task<IActionResult> Create(RoleRequest request, CancellationToken ct) =>
        (await roles.CreateAsync(request, currentUser.RequiredUserId, ct)).ToActionResult(r => CreatedAtAction(nameof(Get), new { id = r.Id }, r));

    [HttpPut("roles/{id:guid}")]
    [HasPermission(Permissions.RolesManage)]
    [ProducesResponseType<RoleDto>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Update(Guid id, RoleRequest request, CancellationToken ct) =>
        (await roles.UpdateAsync(id, request, currentUser.RequiredUserId, ct)).ToActionResult(r => Ok(r));

    [HttpDelete("roles/{id:guid}")]
    [HasPermission(Permissions.RolesManage)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct) =>
        (await roles.DeleteAsync(id, currentUser.RequiredUserId, ct)).ToActionResult(NoContent);

    [HttpGet("permissions")]
    [HasPermission(Permissions.RolesRead)]
    [ProducesResponseType<IReadOnlyList<string>>(StatusCodes.Status200OK)]
    public IActionResult ListPermissions() => Ok(Permissions.All);
}

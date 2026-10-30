using Auth.Api.Authorization;
using Auth.Api.Errors;
using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Admin;
using Auth.Domain.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers;

[ApiController]
[Route("api/v1/admin/audit")]
[Tags("Admin")]
public sealed class AdminAuditController(IAuditReader auditReader) : ControllerBase
{
    [HttpGet]
    [HasPermission(Permissions.AuditRead)]
    [ProducesResponseType<PagedResult<AuditEventDto>>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Query(
        [FromQuery] Guid? userId, [FromQuery] string? type, [FromQuery] DateTime? from, [FromQuery] DateTime? to,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50, CancellationToken ct = default) =>
        (await auditReader.QueryAsync(new AuditQuery(userId, type, from, to, page, pageSize), ct)).ToActionResult(r => Ok(r));
}

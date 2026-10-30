using Auth.Infrastructure.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers;

[ApiController]
[Route(".well-known")]
[Tags("Discovery")]
public sealed class WellKnownController(EcdsaSigningKeyProvider keys) : ControllerBase
{
    /// <summary>Claves públicas para validar access tokens (solo <c>x</c>/<c>y</c>, nunca la privada).</summary>
    [HttpGet("jwks.json")]
    [AllowAnonymous]
    [ResponseCache(Duration = 300, Location = ResponseCacheLocation.Any)]
    public IActionResult Jwks() => Ok(new
    {
        keys = keys.PublicKeys.Select(k => new { kty = k.Kty, crv = k.Crv, x = k.X, y = k.Y, kid = k.Kid, use = k.Use, alg = k.Alg }),
    });
}

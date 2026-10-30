using Auth.Api.Authentication;
using Auth.Application.Abstractions;

namespace Auth.Api.Services;

internal sealed class CurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    public Guid? UserId => ParseClaim(AuthClaims.Subject);
    public Guid? SessionId => ParseClaim(AuthClaims.SessionId);
    public bool IsAuthenticated => accessor.HttpContext?.User.Identity?.IsAuthenticated == true;

    private Guid? ParseClaim(string type) =>
        IsAuthenticated && Guid.TryParse(accessor.HttpContext!.User.FindFirst(type)?.Value, out var id) ? id : null;
}

/// <summary>IP real (después de ForwardedHeaders, solo si hay proxies de confianza) y User-Agent.</summary>
internal sealed class ClientInfo(IHttpContextAccessor accessor) : IClientInfo
{
    public string? IpAddress => accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();

    public string? UserAgent
    {
        get
        {
            var value = accessor.HttpContext?.Request.Headers.UserAgent.ToString();
            return string.IsNullOrEmpty(value) ? null : value;
        }
    }
}

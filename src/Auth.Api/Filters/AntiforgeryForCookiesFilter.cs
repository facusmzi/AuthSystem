using Auth.Api.Authentication;
using Auth.Api.Errors;
using Auth.Application.Common;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Auth.Api.Filters;

/// <summary>
/// CSRF: en métodos no seguros exige token antiforgery (header <c>X-XSRF-TOKEN</c>) cuando la request se
/// autenticó con cookie o cuando pide crear una sesión cookie (<c>?useCookies=true</c>, evita login CSRF).
/// Las requests Bearer no lo necesitan: el navegador no adjunta el header automáticamente.
/// </summary>
public sealed class AntiforgeryForCookiesFilter(IAntiforgery antiforgery) : IAsyncAuthorizationFilter
{
    public const string HeaderName = "X-XSRF-TOKEN";

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var http = context.HttpContext;
        if (HttpMethods.IsGet(http.Request.Method) || HttpMethods.IsHead(http.Request.Method)
            || HttpMethods.IsOptions(http.Request.Method) || HttpMethods.IsTrace(http.Request.Method))
        {
            return;
        }

        var usesBearer = http.Request.Headers.Authorization.Count > 0;
        var cookieAuthenticated = !usesBearer
            && http.User.Identity is { IsAuthenticated: true, AuthenticationType: AuthSchemes.Cookie };
        var createsCookieSession = !usesBearer
            && bool.TryParse(http.Request.Query["useCookies"], out var useCookies) && useCookies;

        if (!cookieAuthenticated && !createsCookieSession)
        {
            return;
        }

        if (!await antiforgery.IsRequestValidAsync(http))
        {
            context.Result = Error.Forbidden(ErrorCodes.AntiforgeryInvalid, "The antiforgery token is missing or invalid.").ToProblem();
        }
    }
}

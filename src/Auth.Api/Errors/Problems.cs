using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Errors;

/// <summary>Construcción uniforme de ProblemDetails (RFC 9457) con la extensión <c>code</c>.</summary>
public static class Problems
{
    public static ProblemDetails Create(int status, string code, string title, string? detail = null)
    {
        var problem = new ProblemDetails
        {
            Status = status,
            Title = title,
            Detail = detail,
            Type = TypeFor(status),
        };
        problem.Extensions["code"] = code;
        return problem;
    }

    public static string TypeFor(int status) => status switch
    {
        400 => "https://tools.ietf.org/html/rfc9110#section-15.5.1",
        401 => "https://tools.ietf.org/html/rfc9110#section-15.5.2",
        403 => "https://tools.ietf.org/html/rfc9110#section-15.5.4",
        404 => "https://tools.ietf.org/html/rfc9110#section-15.5.5",
        405 => "https://tools.ietf.org/html/rfc9110#section-15.5.6",
        409 => "https://tools.ietf.org/html/rfc9110#section-15.5.10",
        415 => "https://tools.ietf.org/html/rfc9110#section-15.5.16",
        422 => "https://tools.ietf.org/html/rfc9110#section-15.5.21",
        429 => "https://tools.ietf.org/html/rfc6585#section-4",
        _ => "https://tools.ietf.org/html/rfc9110#section-15.6.1",
    };

    /// <summary>Escribe un ProblemDetails fuera del pipeline de endpoints (eventos de auth, rate limiter).</summary>
    public static async Task WriteAsync(HttpContext context, int status, string code, string title, string? detail = null)
    {
        context.Response.StatusCode = status;
        var service = context.RequestServices.GetRequiredService<IProblemDetailsService>();
        await service.WriteAsync(new ProblemDetailsContext
        {
            HttpContext = context,
            ProblemDetails = Create(status, code, title, detail),
        });
    }
}

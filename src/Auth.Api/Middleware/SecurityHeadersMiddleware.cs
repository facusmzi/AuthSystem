namespace Auth.Api.Middleware;

/// <summary>
/// Agrega headers de seguridad a todas las respuestas. La API solo sirve JSON, así que la CSP
/// es lo más restrictiva posible; se relaja únicamente para la UI de documentación en desarrollo.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next, IHostEnvironment environment)
{
    private const string StrictCsp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
    private const string DocsCsp = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";

    public Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path;
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;
            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = "DENY";
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()";
            headers["Cross-Origin-Opener-Policy"] = "same-origin";
            headers["Cross-Origin-Resource-Policy"] = "same-origin";

            var isDocs = environment.IsDevelopment()
                && (path.StartsWithSegments("/scalar") || path.StartsWithSegments("/openapi"));
            headers.ContentSecurityPolicy = isDocs ? DocsCsp : StrictCsp;

            // Las respuestas de la API contienen datos de cuenta/sesión: nunca cachear.
            if (path.StartsWithSegments("/api"))
            {
                headers.CacheControl = "no-store";
                headers.Pragma = "no-cache";
            }

            return Task.CompletedTask;
        });

        return next(context);
    }
}

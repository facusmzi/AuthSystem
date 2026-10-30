using Auth.Api.Middleware;
using Auth.Api.Options;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Auth.Api;

public static class ApiPipelineExtensions
{
    public static WebApplication UseApiPipeline(this WebApplication app)
    {
        // Solo se confía en X-Forwarded-* si está habilitado explícitamente y desde proxies conocidos.
        if (app.Services.GetRequiredService<IOptions<NetworkOptions>>().Value.TrustProxy)
        {
            app.UseForwardedHeaders();
        }

        app.UseExceptionHandler();
        app.UseStatusCodePages();

        if (!app.Environment.IsDevelopment())
        {
            app.UseHsts();
        }
        app.UseHttpsRedirection();

        app.UseMiddleware<SecurityHeadersMiddleware>();
        app.UseCors(CorsOptions.PolicyName);
        app.UseRateLimiter();

        return app;
    }

    public static WebApplication MapApiEndpoints(this WebApplication app)
    {
        app.MapControllers();

        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();
        app.MapHealthChecks("/health/ready").AllowAnonymous();

        return app;
    }
}

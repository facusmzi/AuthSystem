using Auth.Api.Middleware;
using Auth.Api.Options;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

namespace Auth.Api;

public static class ApiPipelineExtensions
{
    public static WebApplication UseApiPipeline(this WebApplication app)
    {
        app.UseExceptionHandler();
        app.UseStatusCodePages();

        if (!app.Environment.IsDevelopment())
        {
            app.UseHsts();
        }
        app.UseHttpsRedirection();

        app.UseMiddleware<SecurityHeadersMiddleware>();
        app.UseCors(CorsOptions.PolicyName);

        return app;
    }

    public static WebApplication MapApiEndpoints(this WebApplication app)
    {
        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
        app.MapHealthChecks("/health/ready");

        return app;
    }
}

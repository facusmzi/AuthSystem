using System.Diagnostics;
using Auth.Api.Errors;
using Auth.Api.Options;
using Auth.Application.Common;

namespace Auth.Api;

public static class ApiServiceCollectionExtensions
{
    public static IServiceCollection AddApi(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddOptions<CorsOptions>()
            .BindConfiguration(CorsOptions.SectionName)
            .ValidateDataAnnotations()
            .Validate(o => o.AllowedOrigins.All(IsExactOrigin), "Cors:AllowedOrigins must contain exact origins (scheme://host[:port]), never '*'.")
            .ValidateOnStart();

        services.AddProblemDetails(options => options.CustomizeProblemDetails = ctx =>
        {
            ctx.ProblemDetails.Extensions.TryAdd("traceId", Activity.Current?.Id ?? ctx.HttpContext.TraceIdentifier);
            ctx.ProblemDetails.Extensions.TryAdd("code", CodeForStatus(ctx.ProblemDetails.Status ?? ctx.HttpContext.Response.StatusCode));
        });
        services.AddExceptionHandler<GlobalExceptionHandler>();

        services.AddCors(options =>
        {
            var origins = configuration.GetSection(CorsOptions.SectionName).Get<CorsOptions>()?.AllowedOrigins ?? [];
            options.AddPolicy(CorsOptions.PolicyName, policy => policy
                .WithOrigins(origins)
                .AllowCredentials()
                .WithHeaders("Content-Type", "Authorization", "X-XSRF-TOKEN")
                .WithMethods("GET", "POST", "PUT", "PATCH", "DELETE")
                .SetPreflightMaxAge(TimeSpan.FromMinutes(10)));
        });

        services.AddHealthChecks();

        _ = environment;
        return services;
    }

    private static bool IsExactOrigin(string origin) =>
        origin != "*"
        && Uri.TryCreate(origin, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
        && uri.AbsolutePath == "/"
        && !origin.EndsWith('/');

    private static string CodeForStatus(int status) => status switch
    {
        401 => ErrorCodes.AuthHeaderMissing,
        403 => ErrorCodes.Forbidden,
        404 => ErrorCodes.NotFound,
        409 => ErrorCodes.Conflict,
        422 => ErrorCodes.ValidationFailed,
        429 => ErrorCodes.RateLimited,
        >= 500 => ErrorCodes.InternalError,
        _ => ErrorCodes.BadRequest,
    };
}

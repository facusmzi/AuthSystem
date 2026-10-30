using System.Diagnostics;
using System.Net;
using Auth.Api.Authentication;
using Auth.Api.Errors;
using Auth.Api.Filters;
using Auth.Api.Middleware;
using Auth.Api.Options;
using Auth.Api.Services;
using Auth.Application;
using Auth.Application.Abstractions;
using Auth.Application.Common;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;

namespace Auth.Api;

public static class ApiServiceCollectionExtensions
{
    public static IServiceCollection AddApi(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddApplication();
        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUser, CurrentUser>();
        services.AddScoped<IClientInfo, ClientInfo>();

        AddControllers(services);
        AddProblemDetails(services);
        AddCors(services);
        AddForwardedHeaders(services, configuration);
        services.AddAuthRateLimiting();
        services.AddAuthSchemes();
        services.AddAuthPolicies();

        services.AddHealthChecks()
            .AddCheck<Infrastructure.Persistence.DatabaseHealthCheck>("database", tags: ["ready"]);

        // La documentación interactiva solo existe en desarrollo.
        if (environment.IsDevelopment())
        {
            services.AddOpenApi();
        }

        return services;
    }

    private static void AddControllers(IServiceCollection services)
    {
        services.AddControllers(options =>
            {
                options.Filters.Add<AntiforgeryForCookiesFilter>();
                options.Filters.Add<ValidationFilter>();
                options.SuppressAsyncSuffixInActionNames = true;
            })
            .ConfigureApiBehaviorOptions(options =>
            {
                // Errores de binding (body ausente, JSON mal formado, tipos inválidos): 400 uniforme.
                // La validación de negocio la hace FluentValidation en ValidationFilter (422).
                options.InvalidModelStateResponseFactory = _ =>
                    Error.BadRequest(ErrorCodes.BadRequest, "The request body is missing or malformed.").ToProblem();
            });
    }

    private static void AddProblemDetails(IServiceCollection services)
    {
        services.AddProblemDetails(options => options.CustomizeProblemDetails = ctx =>
        {
            ctx.ProblemDetails.Extensions.TryAdd("traceId", Activity.Current?.Id ?? ctx.HttpContext.TraceIdentifier);
            ctx.ProblemDetails.Extensions.TryAdd("code", CodeForStatus(ctx.ProblemDetails.Status ?? ctx.HttpContext.Response.StatusCode));
        });
        services.AddExceptionHandler<GlobalExceptionHandler>();
    }

    private static void AddCors(IServiceCollection services)
    {
        services.AddOptions<CorsOptions>()
            .BindConfiguration(CorsOptions.SectionName)
            .ValidateDataAnnotations()
            .Validate(o => o.AllowedOrigins.All(IsExactOrigin), "Cors:AllowedOrigins must contain exact origins (scheme://host[:port]), never '*'.")
            .ValidateOnStart();

        services.AddCors();
        services.AddOptions<Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions>()
            .Configure<IOptions<CorsOptions>>((cors, frontend) => cors.AddPolicy(CorsOptions.PolicyName, policy => policy
                .WithOrigins(frontend.Value.AllowedOrigins)
                .AllowCredentials()
                .WithHeaders("Content-Type", "Authorization", "X-XSRF-TOKEN")
                .WithMethods("GET", "POST", "PUT", "PATCH", "DELETE")
                .SetPreflightMaxAge(TimeSpan.FromMinutes(10))));
    }

    private static void AddForwardedHeaders(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<NetworkOptions>().BindConfiguration(NetworkOptions.SectionName);
        services.Configure<ForwardedHeadersOptions>(options =>
        {
            var network = configuration.GetSection(NetworkOptions.SectionName).Get<NetworkOptions>() ?? new NetworkOptions();
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = 1;
            options.KnownProxies.Clear();
            options.KnownIPNetworks.Clear();
            foreach (var proxy in network.KnownProxies)
            {
                options.KnownProxies.Add(IPAddress.Parse(proxy));
            }

            foreach (var cidr in network.KnownNetworks)
            {
                options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr));
            }
        });
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

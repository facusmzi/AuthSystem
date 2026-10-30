using System.Globalization;
using System.Threading.RateLimiting;
using Auth.Api.Errors;
using Auth.Api.Options;
using Auth.Application.Common;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace Auth.Api.Middleware;

/// <summary>
/// Rate limiting en memoria particionado por IP real (nunca "falla abierto": no depende de un servicio externo).
/// La política <c>strict</c> además particiona por ruta para no penalizar flujos encadenados.
/// </summary>
public static class RateLimiting
{
    public static IServiceCollection AddAuthRateLimiting(this IServiceCollection services)
    {
        services.AddOptions<RateLimitingOptions>()
            .BindConfiguration(RateLimitingOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddRateLimiter(options =>
        {
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
            {
                var o = Options(ctx);
                return o.Enabled
                    ? RateLimitPartition.GetFixedWindowLimiter($"global|{ClientKey(ctx)}", _ => PerMinute(o.GlobalPerMinute))
                    : RateLimitPartition.GetNoLimiter("disabled");
            });

            options.AddPolicy(RateLimitingOptions.Strict, ctx => Partition(ctx, $"strict|{ClientKey(ctx)}|{ctx.Request.Path}", o => o.StrictPerMinute));
            options.AddPolicy(RateLimitingOptions.Login, ctx => Partition(ctx, $"login|{ClientKey(ctx)}", o => o.LoginPerMinute));
            options.AddPolicy(RateLimitingOptions.Mfa, ctx => Partition(ctx, $"mfa|{ClientKey(ctx)}", o => o.MfaPerMinute));
            options.AddPolicy(RateLimitingOptions.Refresh, ctx => Partition(ctx, $"refresh|{ClientKey(ctx)}", o => o.RefreshPerMinute));

            options.OnRejected = async (context, cancellationToken) =>
            {
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter =
                        ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
                }

                await Problems.WriteAsync(context.HttpContext, StatusCodes.Status429TooManyRequests, ErrorCodes.RateLimited,
                    "Too many requests", "Rate limit exceeded. Try again later.");
            };
        });

        return services;
    }

    private static RateLimitPartition<string> Partition(HttpContext ctx, string key, Func<RateLimitingOptions, int> limit)
    {
        var o = Options(ctx);
        return o.Enabled
            ? RateLimitPartition.GetFixedWindowLimiter(key, _ => PerMinute(limit(o)))
            : RateLimitPartition.GetNoLimiter("disabled");
    }

    private static FixedWindowRateLimiterOptions PerMinute(int permits) => new()
    {
        PermitLimit = permits,
        Window = TimeSpan.FromMinutes(1),
        QueueLimit = 0,
        AutoReplenishment = true,
    };

    private static RateLimitingOptions Options(HttpContext ctx) =>
        ctx.RequestServices.GetRequiredService<IOptions<RateLimitingOptions>>().Value;

    private static string ClientKey(HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Auth.Application.Abstractions;
using Auth.Infrastructure.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Security;

/// <summary>
/// Cliente de la API de rangos de Pwned Passwords. Solo se envían los 5 primeros caracteres hex del SHA-1
/// (k-anonymity) y se pide padding para que el tamaño de la respuesta no filtre información.
/// </summary>
public sealed class HibpPasswordBreachChecker(HttpClient http, IOptions<HibpOptions> options, ILogger<HibpPasswordBreachChecker> logger)
    : IPasswordBreachChecker
{
    public async Task<BreachCheckStatus> CheckAsync(string password, CancellationToken cancellationToken)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var prefix = hash[..5];
        var suffix = hash[5..];

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"range/{prefix}");
            request.Headers.Add("Add-Padding", "true");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("HIBP returned status {StatusCode}", (int)response.StatusCode);
                return BreachCheckStatus.Unavailable;
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            return IsBreached(body, suffix, options.Value.MinBreachCount) ? BreachCheckStatus.Breached : BreachCheckStatus.NotBreached;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or TimeoutException or Polly.Timeout.TimeoutRejectedException or Polly.CircuitBreaker.BrokenCircuitException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            logger.LogWarning("HIBP request failed: {ExceptionType}", ex.GetType().Name);
            return BreachCheckStatus.Unavailable;
        }
    }

    internal static bool IsBreached(string body, string suffix, int minCount)
    {
        foreach (var line in body.AsSpan().EnumerateLines())
        {
            var separator = line.IndexOf(':');
            if (separator <= 0 || !line[..separator].Equals(suffix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Las entradas de padding tienen conteo 0.
            return int.TryParse(line[(separator + 1)..].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var count)
                && count >= minCount;
        }

        return false;
    }
}

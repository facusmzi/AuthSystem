using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.IntegrationTests.Infrastructure;

namespace Auth.IntegrationTests.Transversal;

public sealed class SmokeTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    [Fact]
    public async Task Health_live_returns_200_with_security_headers()
    {
        var client = factory.CreateHttpsClient();

        var response = await client.GetAsync("/health/live");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Headers.GetValues("X-Content-Type-Options").ShouldContain("nosniff");
        response.Headers.GetValues("X-Frame-Options").ShouldContain("DENY");
        response.Headers.GetValues("Referrer-Policy").ShouldContain("strict-origin-when-cross-origin");
        response.Headers.GetValues("Content-Security-Policy").Single().ShouldContain("default-src 'none'");
        response.Headers.Contains("Permissions-Policy").ShouldBeTrue();
        response.Headers.Contains("X-XSS-Protection").ShouldBeFalse();
    }

    [Fact]
    public async Task Unknown_route_returns_problem_details_with_code_and_trace_id()
    {
        var client = factory.CreateHttpsClient();

        var response = await client.GetAsync("/api/v1/does-not-exist");

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        response.Content.Headers.ContentType?.MediaType.ShouldBe("application/problem+json");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("status").GetInt32().ShouldBe(404);
        body.GetProperty("code").GetString().ShouldBe("NOT_FOUND");
        body.TryGetProperty("traceId", out _).ShouldBeTrue();
        response.Headers.CacheControl?.NoStore.ShouldBeTrue();
    }

    [Fact]
    public async Task Cors_preflight_allows_configured_origin_only()
    {
        var client = factory.CreateHttpsClient();

        using var allowed = new HttpRequestMessage(HttpMethod.Options, "/health/live");
        allowed.Headers.Add("Origin", "http://localhost:5173");
        allowed.Headers.Add("Access-Control-Request-Method", "POST");
        var allowedResponse = await client.SendAsync(allowed);
        allowedResponse.Headers.GetValues("Access-Control-Allow-Origin").ShouldContain("http://localhost:5173");
        allowedResponse.Headers.GetValues("Access-Control-Allow-Credentials").ShouldContain("true");

        using var denied = new HttpRequestMessage(HttpMethod.Options, "/health/live");
        denied.Headers.Add("Origin", "https://evil.example");
        denied.Headers.Add("Access-Control-Request-Method", "POST");
        var deniedResponse = await client.SendAsync(denied);
        deniedResponse.Headers.Contains("Access-Control-Allow-Origin").ShouldBeFalse();
    }
}

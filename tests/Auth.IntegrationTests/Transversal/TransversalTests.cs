using System.Net;
using System.Net.Http.Json;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using static Auth.IntegrationTests.Infrastructure.ApiTestExtensions;

namespace Auth.IntegrationTests.Transversal;

public sealed class StrictRateLimitFactory : AuthApiFactory
{
    protected override IReadOnlyDictionary<string, string?> ExtraSettings => new Dictionary<string, string?>
    {
        ["RateLimiting:StrictPerMinute"] = "2",
        ["RateLimiting:LoginPerMinute"] = "3",
    };
}

public sealed class RateLimitTests(StrictRateLimitFactory factory) : IClassFixture<StrictRateLimitFactory>
{
    [Fact]
    public async Task Exceeding_the_strict_limit_returns_429_with_retry_after()
    {
        var client = factory.CreateHttpsClient();

        (await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = NewEmail() })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        (await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = NewEmail() })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var limited = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = NewEmail() });

        await limited.ShouldBeProblemAsync(HttpStatusCode.TooManyRequests, "RATE_LIMITED");
        limited.Headers.RetryAfter.ShouldNotBeNull();
        limited.Headers.RetryAfter!.Delta!.Value.ShouldBeGreaterThan(TimeSpan.Zero);
    }

    [Fact]
    public async Task Login_attempts_are_rate_limited()
    {
        var client = factory.CreateHttpsClient();

        for (var i = 0; i < 3; i++)
        {
            (await client.LoginAsync(NewEmail(), "whatever password")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        }

        await (await client.LoginAsync(NewEmail(), "whatever password")).ShouldBeProblemAsync(HttpStatusCode.TooManyRequests, "RATE_LIMITED");
    }
}

public sealed class TransversalTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    [Fact]
    public async Task Readiness_checks_the_database()
    {
        var response = await factory.CreateHttpsClient().GetAsync("/health/ready");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).ShouldBe("Healthy");
    }

    [Fact]
    public async Task Forwarded_for_header_is_ignored_without_a_trusted_proxy()
    {
        var client = factory.CreateHttpsClient();
        var email = NewEmail();
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login") { Content = JsonContent.Create(new { email, password = "whatever password" }) };
        request.Headers.Add("X-Forwarded-For", "203.0.113.66");

        await client.SendAsync(request);

        var ips = await factory.WithDbAsync(db => db.AuditEvents.Where(e => e.Email == email).Select(e => e.IpAddress).ToListAsync());
        ips.ShouldNotBeEmpty();
        ips.ShouldAllBe(ip => ip != "203.0.113.66");
    }

    [Fact]
    public async Task Auth_responses_are_never_cached()
    {
        var response = await factory.CreateHttpsClient().PostAsJsonAsync("/api/v1/auth/login", new { email = NewEmail(), password = "whatever password" });

        response.Headers.CacheControl!.NoStore.ShouldBeTrue();
    }

    [Fact]
    public async Task Openapi_and_scalar_are_not_exposed_outside_development()
    {
        var client = factory.CreateHttpsClient();

        (await client.GetAsync("/openapi/v1.json")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await client.GetAsync("/scalar/v1")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }
}

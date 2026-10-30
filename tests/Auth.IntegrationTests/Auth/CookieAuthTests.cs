using System.Net;
using System.Net.Http.Json;
using Auth.IntegrationTests.Infrastructure;
using static Auth.IntegrationTests.Infrastructure.ApiTestExtensions;

namespace Auth.IntegrationTests.Auth;

public sealed class CookieAuthTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private static async Task<string> GetAntiforgeryTokenAsync(HttpClient client)
    {
        var response = await client.GetAsync("/api/v1/auth/antiforgery");
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var body = await response.ReadJsonAsync();
        body.GetProperty("headerName").GetString().ShouldBe("X-XSRF-TOKEN");
        return body.GetProperty("token").GetString()!;
    }

    private static Task<HttpResponseMessage> PostWithCsrfAsync(HttpClient client, string url, object? body, string? token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = body is null ? null : JsonContent.Create(body) };
        if (token is not null)
        {
            request.Headers.Add("X-XSRF-TOKEN", token);
        }
        return client.SendAsync(request);
    }

    private async Task<(HttpClient Client, string Email, HttpResponseMessage Login)> CookieLoginAsync()
    {
        var email = NewEmail();
        var setup = factory.CreateHttpsClient();
        await factory.RegisterConfirmedAsync(setup, email);

        var client = factory.CreateHttpsClient();
        var csrf = await GetAntiforgeryTokenAsync(client);
        var login = await PostWithCsrfAsync(client, "/api/v1/auth/login?useCookies=true", new { email, password = DefaultPassword }, csrf);
        login.StatusCode.ShouldBe(HttpStatusCode.OK, await login.Content.ReadAsStringAsync());
        return (client, email, login);
    }

    [Fact]
    public async Task Cookie_login_sets_a_hardened_host_cookie_and_returns_no_tokens()
    {
        var (client, email, login) = await CookieLoginAsync();

        var setCookie = login.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("__Host-auth=", StringComparison.Ordinal)).ToLowerInvariant();
        setCookie.ShouldContain("secure");
        setCookie.ShouldContain("httponly");
        setCookie.ShouldContain("samesite=strict");
        setCookie.ShouldContain("path=/");
        setCookie.ShouldNotContain("domain=");

        var body = await login.ReadJsonAsync();
        body.GetProperty("tokens").ValueKind.ShouldBe(System.Text.Json.JsonValueKind.Null);
        body.GetProperty("user").GetProperty("email").GetString().ShouldBe(email);

        var me = await client.GetAsync("/api/v1/account/me");
        me.StatusCode.ShouldBe(HttpStatusCode.OK);
        var sessions = await (await client.GetAsync("/api/v1/account/sessions")).ReadJsonAsync();
        sessions.EnumerateArray().Single().GetProperty("kind").GetString().ShouldBe("Cookie");
    }

    [Fact]
    public async Task Cookie_login_without_antiforgery_token_is_rejected()
    {
        var email = NewEmail();
        var client = factory.CreateHttpsClient();
        await factory.RegisterConfirmedAsync(client, email);

        var response = await PostWithCsrfAsync(client, "/api/v1/auth/login?useCookies=true", new { email, password = DefaultPassword }, token: null);

        await response.ShouldBeProblemAsync(HttpStatusCode.Forbidden, "ANTIFORGERY_INVALID");
    }

    [Fact]
    public async Task Cookie_authenticated_post_requires_antiforgery_and_logout_kills_the_cookie()
    {
        var (client, _, _) = await CookieLoginAsync();

        await (await PostWithCsrfAsync(client, "/api/v1/auth/logout", null, token: null))
            .ShouldBeProblemAsync(HttpStatusCode.Forbidden, "ANTIFORGERY_INVALID");

        // El token está atado a la identidad: se pide uno nuevo después del login.
        var csrf = await GetAntiforgeryTokenAsync(client);
        (await PostWithCsrfAsync(client, "/api/v1/auth/logout", null, csrf)).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        await (await client.GetAsync("/api/v1/account/me")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "AUTH_HEADER_MISSING");
    }

    [Fact]
    public async Task Stolen_cookie_is_useless_after_server_side_revocation()
    {
        var (client, email, login) = await CookieLoginAsync();
        var cookie = login.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("__Host-auth=", StringComparison.Ordinal)).Split(';')[0];

        var bearer = await factory.CreateHttpsClient().LoginBearerAsync(email, Guid.Empty);
        (await factory.BearerClient(bearer.AccessToken).PostAsync("/api/v1/auth/logout-all", null)).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var replay = factory.CreateHttpsClient();
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/account/me");
        request.Headers.Add("Cookie", cookie);
        await (await replay.SendAsync(request)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
        await (await client.GetAsync("/api/v1/account/me")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
    }

    [Fact]
    public async Task Bearer_header_takes_precedence_and_cookie_is_ignored()
    {
        var (client, _, _) = await CookieLoginAsync();

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/account/me");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "not-a-jwt");

        await (await client.SendAsync(request)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "TOKEN_INVALID");
    }

    [Fact]
    public async Task Bearer_requests_do_not_need_antiforgery()
    {
        var session = await factory.CreateUserAndLoginAsync(factory.CreateHttpsClient());

        (await factory.BearerClient(session.AccessToken).PostAsync("/api/v1/auth/logout", null)).StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Auth.IntegrationTests.Infrastructure;

public sealed record BearerSession(string Email, Guid UserId, string AccessToken, string RefreshToken);

public static class ApiTestExtensions
{
    public const string DefaultPassword = "correct horse battery staple";

    public static string NewEmail(string prefix = "user") => $"{prefix}-{Guid.NewGuid():N}@example.com";

    public static async Task<JsonElement> ReadJsonAsync(this HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>();

    /// <summary>Verifica status y formato ProblemDetails con el <c>code</c> esperado.</summary>
    public static async Task<JsonElement> ShouldBeProblemAsync(this HttpResponseMessage response, HttpStatusCode status, string code)
    {
        var body = await response.Content.ReadAsStringAsync();
        response.StatusCode.ShouldBe(status, body);
        response.Content.Headers.ContentType?.MediaType.ShouldBe("application/problem+json");
        var json = JsonDocument.Parse(body).RootElement;
        json.GetProperty("status").GetInt32().ShouldBe((int)status);
        json.GetProperty("code").GetString().ShouldBe(code);
        json.TryGetProperty("traceId", out _).ShouldBeTrue();
        return json;
    }

    public static Task<HttpResponseMessage> RegisterAsync(this HttpClient client, string email, string password = DefaultPassword) =>
        client.PostAsJsonAsync("/api/v1/auth/register", new { email, password });

    public static Task<HttpResponseMessage> LoginAsync(this HttpClient client, string email, string password = DefaultPassword) =>
        client.PostAsJsonAsync("/api/v1/auth/login", new { email, password });

    public static Task<HttpResponseMessage> RefreshAsync(this HttpClient client, string refreshToken) =>
        client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken });

    public static HttpClient BearerClient(this AuthApiFactory factory, string accessToken)
    {
        var client = factory.CreateHttpsClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    /// <summary>Hace login Bearer y devuelve el par de tokens.</summary>
    public static async Task<BearerSession> LoginBearerAsync(this HttpClient client, string email, Guid userId, string password = DefaultPassword)
    {
        var response = await client.LoginAsync(email, password);
        var body = await response.Content.ReadAsStringAsync();
        response.StatusCode.ShouldBe(HttpStatusCode.OK, body);
        var tokens = JsonDocument.Parse(body).RootElement.GetProperty("tokens");
        return new BearerSession(email, userId, tokens.GetProperty("accessToken").GetString()!, tokens.GetProperty("refreshToken").GetString()!);
    }

    /// <summary>Usuario nuevo, confirmado y con sesión Bearer.</summary>
    public static async Task<BearerSession> CreateUserAndLoginAsync(this AuthApiFactory factory, HttpClient client, string? email = null)
    {
        email ??= NewEmail();
        var userId = await factory.RegisterConfirmedAsync(client, email);
        return await client.LoginBearerAsync(email, userId);
    }

    /// <summary>Registra y confirma el email usando el link del mail capturado.</summary>
    public static async Task<Guid> RegisterConfirmedAsync(this AuthApiFactory factory, HttpClient client, string email, string password = DefaultPassword)
    {
        var register = await client.RegisterAsync(email, password);
        register.StatusCode.ShouldBe(HttpStatusCode.Accepted, await register.Content.ReadAsStringAsync());

        var (userId, token) = factory.Emails.LastConfirmationLink(email);
        var confirm = await client.PostAsJsonAsync("/api/v1/auth/confirm-email", new { userId, token });
        confirm.StatusCode.ShouldBe(HttpStatusCode.OK, await confirm.Content.ReadAsStringAsync());
        return userId;
    }
}

using System.Net;
using Auth.Domain.Audit;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using static Auth.IntegrationTests.Infrastructure.ApiTestExtensions;

namespace Auth.IntegrationTests.Auth;

public sealed class LoginTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private readonly HttpClient _client = factory.CreateHttpsClient();

    [Fact]
    public async Task Bearer_login_returns_tokens_and_user()
    {
        var email = NewEmail();
        var userId = await factory.RegisterConfirmedAsync(_client, email);

        var response = await _client.LoginAsync(email);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var body = await response.ReadJsonAsync();
        body.GetProperty("requiresMfa").GetBoolean().ShouldBeFalse();
        var tokens = body.GetProperty("tokens");
        tokens.GetProperty("tokenType").GetString().ShouldBe("Bearer");
        tokens.GetProperty("accessToken").GetString().ShouldNotBeNullOrEmpty();
        tokens.GetProperty("refreshToken").GetString().ShouldNotBeNullOrEmpty();
        var user = body.GetProperty("user");
        user.GetProperty("id").GetGuid().ShouldBe(userId);
        user.GetProperty("roles").EnumerateArray().Select(r => r.GetString()).ShouldBe(["User"]);

        var audit = await factory.WithDbAsync(db => db.AuditEvents.Where(e => e.UserId == userId).Select(e => e.Type).ToListAsync());
        audit.ShouldContain(AuditEventType.LoginSucceeded);
    }

    [Fact]
    public async Task Wrong_password_and_unknown_user_return_the_same_401()
    {
        var email = NewEmail();
        await factory.RegisterConfirmedAsync(_client, email);

        var wrong = await _client.LoginAsync(email, "definitely not the password");
        var unknown = await _client.LoginAsync(NewEmail(), "definitely not the password");

        var a = await wrong.ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS");
        var b = await unknown.ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS");
        a.GetProperty("detail").GetString().ShouldBe(b.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Unconfirmed_email_returns_403_only_with_correct_password()
    {
        var email = NewEmail();
        await _client.RegisterAsync(email);

        await (await _client.LoginAsync(email, "definitely not the password")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS");
        await (await _client.LoginAsync(email)).ShouldBeProblemAsync(HttpStatusCode.Forbidden, "EMAIL_NOT_CONFIRMED");
    }

    [Fact]
    public async Task Account_locks_after_five_failures_and_unlocks_after_fifteen_minutes()
    {
        var email = NewEmail();
        await factory.RegisterConfirmedAsync(_client, email);

        for (var i = 0; i < 5; i++)
        {
            await (await _client.LoginAsync(email, "definitely not the password")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS");
        }

        // Bloqueada: ni la contraseña correcta funciona, con el mismo error genérico.
        await (await _client.LoginAsync(email)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS");

        factory.Clock.Advance(TimeSpan.FromMinutes(16));
        (await _client.LoginAsync(email)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Successful_login_resets_failed_attempt_counter()
    {
        var email = NewEmail();
        await factory.RegisterConfirmedAsync(_client, email);

        for (var i = 0; i < 4; i++)
        {
            await _client.LoginAsync(email, "definitely not the password");
        }
        (await _client.LoginAsync(email)).StatusCode.ShouldBe(HttpStatusCode.OK);
        for (var i = 0; i < 4; i++)
        {
            await _client.LoginAsync(email, "definitely not the password");
        }

        (await _client.LoginAsync(email)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Me_returns_the_current_user()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);

        var response = await factory.BearerClient(session.AccessToken).GetAsync("/api/v1/account/me");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var me = await response.ReadJsonAsync();
        me.GetProperty("id").GetGuid().ShouldBe(session.UserId);
        me.GetProperty("email").GetString().ShouldBe(session.Email);
        me.GetProperty("emailConfirmed").GetBoolean().ShouldBeTrue();
        me.GetProperty("mfaEnabled").GetBoolean().ShouldBeFalse();
        me.GetProperty("permissions").GetArrayLength().ShouldBe(0);
    }
}

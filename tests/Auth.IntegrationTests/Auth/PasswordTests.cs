using System.Net;
using System.Net.Http.Json;
using Auth.Domain.Audit;
using Auth.Domain.Sessions;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using static Auth.IntegrationTests.Infrastructure.ApiTestExtensions;

namespace Auth.IntegrationTests.Auth;

public sealed class PasswordTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private const string NewPassword = "a brand new passphrase";
    private readonly HttpClient _client = factory.CreateHttpsClient();

    [Fact]
    public async Task Change_password_revokes_other_sessions_and_keeps_the_current_one()
    {
        var current = await factory.CreateUserAndLoginAsync(_client);
        var other = await _client.LoginBearerAsync(current.Email, current.UserId);
        var bearer = factory.BearerClient(current.AccessToken);

        var response = await bearer.PostAsJsonAsync("/api/v1/account/change-password", new { currentPassword = DefaultPassword, newPassword = NewPassword });

        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await bearer.GetAsync("/api/v1/account/me")).StatusCode.ShouldBe(HttpStatusCode.OK);
        await (await factory.BearerClient(other.AccessToken).GetAsync("/api/v1/account/me")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
        await (await _client.RefreshAsync(other.RefreshToken)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "REFRESH_INVALID");

        await (await _client.LoginAsync(current.Email)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS");
        (await _client.LoginAsync(current.Email, NewPassword)).StatusCode.ShouldBe(HttpStatusCode.OK);
        factory.Emails.LastTo(current.Email).Subject.ShouldContain("password was changed");

        var reasons = await factory.WithDbAsync(db => db.Sessions.Where(s => s.UserId == current.UserId && s.RevokedAt != null).Select(s => s.RevokedReason).ToListAsync());
        reasons.ShouldBe([RevocationReason.PasswordChanged]);
    }

    [Fact]
    public async Task Change_password_with_wrong_current_password_fails_without_revoking()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var bearer = factory.BearerClient(session.AccessToken);

        await (await bearer.PostAsJsonAsync("/api/v1/account/change-password", new { currentPassword = "not my password at all", newPassword = NewPassword }))
            .ShouldBeProblemAsync(HttpStatusCode.BadRequest, "INVALID_CREDENTIALS");

        (await bearer.GetAsync("/api/v1/account/me")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Change_password_applies_policy_including_breach_check()
    {
        var bearer = factory.BearerClient((await factory.CreateUserAndLoginAsync(_client)).AccessToken);

        var weak = await bearer.PostAsJsonAsync("/api/v1/account/change-password", new { currentPassword = DefaultPassword, newPassword = "short" });
        (await weak.ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "PASSWORD_TOO_WEAK")).GetProperty("errors").TryGetProperty("newPassword", out _).ShouldBeTrue();

        await (await bearer.PostAsJsonAsync("/api/v1/account/change-password", new { currentPassword = DefaultPassword, newPassword = FakeBreachChecker.BreachedPassword }))
            .ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "PASSWORD_BREACHED");
    }

    [Fact]
    public async Task Forgot_password_always_returns_202_and_only_mails_confirmed_accounts()
    {
        var confirmed = NewEmail();
        await factory.RegisterConfirmedAsync(_client, confirmed);
        var unconfirmed = NewEmail();
        await _client.RegisterAsync(unconfirmed);
        var unknown = NewEmail();

        foreach (var email in new[] { confirmed, unconfirmed, unknown })
        {
            var response = await _client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });
            response.StatusCode.ShouldBe(HttpStatusCode.Accepted);
            (await response.ReadJsonAsync()).GetProperty("message").GetString().ShouldBe("If the email is registered, you'll receive an email shortly.");
        }

        factory.Emails.LastTo(confirmed).Subject.ShouldContain("Reset");
        factory.Emails.To(unconfirmed).ShouldAllBe(m => !m.Subject.Contains("Reset"));
        factory.Emails.To(unknown).ShouldBeEmpty();
    }

    [Fact]
    public async Task Reset_password_revokes_all_sessions_unlocks_and_token_is_single_use()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        for (var i = 0; i < 5; i++)
        {
            await _client.LoginAsync(session.Email, "definitely not the password");
        }

        await _client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = session.Email });
        var token = factory.Emails.LastResetToken(session.Email);

        var reset = await _client.PostAsJsonAsync("/api/v1/auth/reset-password", new { email = session.Email, token, newPassword = NewPassword });

        reset.StatusCode.ShouldBe(HttpStatusCode.OK);
        await (await factory.BearerClient(session.AccessToken).GetAsync("/api/v1/account/me")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
        (await _client.LoginAsync(session.Email, NewPassword)).StatusCode.ShouldBe(HttpStatusCode.OK); // el lockout se levantó

        var again = await _client.PostAsJsonAsync("/api/v1/auth/reset-password", new { email = session.Email, token, newPassword = "yet another passphrase" });
        await again.ShouldBeProblemAsync(HttpStatusCode.BadRequest, "INVALID_TOKEN");

        var audit = await factory.WithDbAsync(db => db.AuditEvents.Where(e => e.UserId == session.UserId).Select(e => e.Type).ToListAsync());
        audit.ShouldContain(AuditEventType.PasswordResetRequested);
        audit.ShouldContain(AuditEventType.PasswordResetCompleted);
    }

    [Fact]
    public async Task Reset_token_expires_after_one_hour_and_errors_are_generic()
    {
        var email = NewEmail();
        await factory.RegisterConfirmedAsync(_client, email);
        await _client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });
        var token = factory.Emails.LastResetToken(email);

        await (await _client.PostAsJsonAsync("/api/v1/auth/reset-password", new { email = NewEmail(), token, newPassword = NewPassword }))
            .ShouldBeProblemAsync(HttpStatusCode.BadRequest, "INVALID_TOKEN");

        factory.Clock.Advance(TimeSpan.FromMinutes(61));
        await (await _client.PostAsJsonAsync("/api/v1/auth/reset-password", new { email, token, newPassword = NewPassword }))
            .ShouldBeProblemAsync(HttpStatusCode.BadRequest, "INVALID_TOKEN");
    }

    [Fact]
    public async Task Reset_with_weak_password_returns_422()
    {
        var email = NewEmail();
        await factory.RegisterConfirmedAsync(_client, email);
        await _client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });
        var token = factory.Emails.LastResetToken(email);

        await (await _client.PostAsJsonAsync("/api/v1/auth/reset-password", new { email, token, newPassword = FakeBreachChecker.BreachedPassword }))
            .ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "PASSWORD_BREACHED");
    }
}

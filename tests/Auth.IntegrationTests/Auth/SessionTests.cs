using System.Net;
using Auth.Domain.Sessions;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace Auth.IntegrationTests.Auth;

public sealed class SessionTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private readonly HttpClient _client = factory.CreateHttpsClient();

    [Fact]
    public async Task Lists_active_sessions_newest_first_with_current_flag()
    {
        var first = await factory.CreateUserAndLoginAsync(_client);
        factory.Clock.Advance(TimeSpan.FromSeconds(5));
        var second = await _client.LoginBearerAsync(first.Email, first.UserId);

        var response = await factory.BearerClient(second.AccessToken).GetAsync("/api/v1/account/sessions");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var sessions = (await response.ReadJsonAsync()).EnumerateArray().ToList();
        sessions.Count.ShouldBe(2);
        sessions[0].GetProperty("current").GetBoolean().ShouldBeTrue();
        sessions[1].GetProperty("current").GetBoolean().ShouldBeFalse();
        sessions[0].GetProperty("kind").GetString().ShouldBe("Bearer");
        sessions[0].GetProperty("loginMethod").GetString().ShouldBe("Password");
    }

    [Fact]
    public async Task Revoking_another_own_session_reports_was_current_false_and_kills_it()
    {
        var first = await factory.CreateUserAndLoginAsync(_client);
        var second = await _client.LoginBearerAsync(first.Email, first.UserId);
        var firstSid = SidOf(first.AccessToken);

        var response = await factory.BearerClient(second.AccessToken).DeleteAsync($"/api/v1/account/sessions/{firstSid}");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.ReadJsonAsync()).GetProperty("wasCurrent").GetBoolean().ShouldBeFalse();
        await (await factory.BearerClient(first.AccessToken).GetAsync("/api/v1/account/sessions")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
        (await factory.BearerClient(second.AccessToken).GetAsync("/api/v1/account/sessions")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Revoking_the_current_session_reports_was_current_true()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);

        var response = await factory.BearerClient(session.AccessToken).DeleteAsync($"/api/v1/account/sessions/{SidOf(session.AccessToken)}");

        (await response.ReadJsonAsync()).GetProperty("wasCurrent").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Revoking_someone_elses_session_returns_404_and_leaves_it_alive()
    {
        var mine = await factory.CreateUserAndLoginAsync(_client);
        var theirs = await factory.CreateUserAndLoginAsync(_client);

        var response = await factory.BearerClient(mine.AccessToken).DeleteAsync($"/api/v1/account/sessions/{SidOf(theirs.AccessToken)}");

        await response.ShouldBeProblemAsync(HttpStatusCode.NotFound, "NOT_FOUND");
        (await factory.BearerClient(theirs.AccessToken).GetAsync("/api/v1/account/sessions")).StatusCode.ShouldBe(HttpStatusCode.OK);
        await (await factory.BearerClient(mine.AccessToken).DeleteAsync($"/api/v1/account/sessions/{Guid.NewGuid()}"))
            .ShouldBeProblemAsync(HttpStatusCode.NotFound, "NOT_FOUND");
    }

    [Fact]
    public async Task Logout_all_revokes_every_session_including_current()
    {
        var first = await factory.CreateUserAndLoginAsync(_client);
        var second = await _client.LoginBearerAsync(first.Email, first.UserId);

        (await factory.BearerClient(first.AccessToken).PostAsync("/api/v1/auth/logout-all", null)).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        await (await factory.BearerClient(first.AccessToken).GetAsync("/api/v1/account/sessions")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
        await (await factory.BearerClient(second.AccessToken).GetAsync("/api/v1/account/sessions")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
        await (await _client.RefreshAsync(second.RefreshToken)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "REFRESH_INVALID");

        var reasons = await factory.WithDbAsync(db => db.Sessions.Where(s => s.UserId == first.UserId).Select(s => s.RevokedReason).ToListAsync());
        reasons.ShouldAllBe(r => r == RevocationReason.LogoutAll);
    }

    private static string SidOf(string accessToken) =>
        new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(accessToken).GetClaim("sid").Value;
}

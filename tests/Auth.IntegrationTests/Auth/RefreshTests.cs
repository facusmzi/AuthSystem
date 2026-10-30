using System.Net;
using Auth.Domain.Audit;
using Auth.Domain.Sessions;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace Auth.IntegrationTests.Auth;

public sealed class RefreshTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private readonly HttpClient _client = factory.CreateHttpsClient();

    private async Task<(string Access, string Refresh)> RefreshOkAsync(string refreshToken)
    {
        var response = await _client.RefreshAsync(refreshToken);
        var body = await response.Content.ReadAsStringAsync();
        response.StatusCode.ShouldBe(HttpStatusCode.OK, body);
        var json = await response.ReadJsonAsync();
        return (json.GetProperty("accessToken").GetString()!, json.GetProperty("refreshToken").GetString()!);
    }

    [Fact]
    public async Task Refresh_rotates_the_token_and_keeps_the_session()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);

        var (access, refresh) = await RefreshOkAsync(session.RefreshToken);

        refresh.ShouldNotBe(session.RefreshToken);
        access.ShouldNotBe(session.AccessToken);
        new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(access).GetClaim("sid").Value
            .ShouldBe(new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(session.AccessToken).GetClaim("sid").Value);
        (await factory.BearerClient(access).GetAsync("/api/v1/account/sessions")).StatusCode.ShouldBe(HttpStatusCode.OK);

        var stored = await factory.WithDbAsync(db => db.Sessions.SingleAsync(s => s.UserId == session.UserId));
        stored.RefreshTokenHash.ShouldNotBeNull().Length.ShouldBe(64);
        stored.RefreshTokenHash.ShouldNotContain(refresh);
    }

    [Fact]
    public async Task Old_token_within_grace_returns_the_same_pair()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var first = await RefreshOkAsync(session.RefreshToken);

        factory.Clock.Advance(TimeSpan.FromMinutes(2));
        var again = await RefreshOkAsync(session.RefreshToken);

        again.ShouldBe(first);
    }

    [Fact]
    public async Task Reusing_old_token_after_grace_revokes_the_session()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var (access, refresh) = await RefreshOkAsync(session.RefreshToken);

        factory.Clock.Advance(TimeSpan.FromMinutes(4));
        await (await _client.RefreshAsync(session.RefreshToken)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "REFRESH_INVALID");

        // La sesión entera cae: el token nuevo tampoco sirve y el access token se rechaza.
        await (await _client.RefreshAsync(refresh)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "REFRESH_INVALID");
        await (await factory.BearerClient(access).GetAsync("/api/v1/account/sessions")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");

        var stored = await factory.WithDbAsync(db => db.Sessions.SingleAsync(s => s.UserId == session.UserId));
        stored.RevokedReason.ShouldBe(RevocationReason.RefreshReuse);
        var audit = await factory.WithDbAsync(db => db.AuditEvents.Where(e => e.UserId == session.UserId).Select(e => e.Type).ToListAsync());
        audit.ShouldContain(AuditEventType.RefreshTokenReuseDetected);
    }

    [Fact]
    public async Task Concurrent_refreshes_with_same_token_all_succeed_with_the_same_pair()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => _client.RefreshAsync(session.RefreshToken)));

        results.ShouldAllBe(r => r.StatusCode == HttpStatusCode.OK);
        var refreshTokens = await Task.WhenAll(results.Select(async r => (await r.ReadJsonAsync()).GetProperty("refreshToken").GetString()));
        refreshTokens.Distinct().Count().ShouldBe(1);

        // La sesión sigue sana y el nuevo token rota normalmente.
        await RefreshOkAsync(refreshTokens[0]!);
        (await factory.WithDbAsync(db => db.Sessions.SingleAsync(s => s.UserId == session.UserId))).RevokedAt.ShouldBeNull();
    }

    [Fact]
    public async Task Unknown_refresh_token_returns_401()
    {
        await (await _client.RefreshAsync("this-token-does-not-exist")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "REFRESH_INVALID");
    }

    [Fact]
    public async Task Sliding_expiration_ends_the_session_after_30_idle_days()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);

        factory.Clock.Advance(TimeSpan.FromDays(30) + TimeSpan.FromMinutes(1));

        await (await _client.RefreshAsync(session.RefreshToken)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "REFRESH_INVALID");
    }

    [Fact]
    public async Task Absolute_expiration_caps_the_session_at_90_days_even_with_activity()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var refresh = session.RefreshToken;

        for (var i = 0; i < 3; i++)
        {
            factory.Clock.Advance(TimeSpan.FromDays(29));
            refresh = (await RefreshOkAsync(refresh)).Refresh;
        }

        factory.Clock.Advance(TimeSpan.FromDays(4)); // 91 días desde el login
        await (await _client.RefreshAsync(refresh)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "REFRESH_INVALID");
    }
}

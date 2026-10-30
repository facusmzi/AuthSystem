using System.Net;
using System.Net.Http.Json;
using Auth.Domain.Audit;
using Auth.Infrastructure.Background;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using static Auth.IntegrationTests.Infrastructure.ApiTestExtensions;

namespace Auth.IntegrationTests.Audit;

public sealed class AuditTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    [Fact]
    public async Task Every_flow_is_audited_and_no_event_contains_secrets()
    {
        var client = factory.CreateHttpsClient();
        var email = NewEmail("audit");
        const string firstPassword = "first secret passphrase";
        const string secondPassword = "second secret passphrase";
        const string thirdPassword = "third secret passphrase";

        (await client.RegisterAsync(email, firstPassword)).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var (userId, confirmToken) = factory.Emails.LastConfirmationLink(email);
        await client.PostAsJsonAsync("/api/v1/auth/confirm-email", new { userId, token = confirmToken });
        await client.LoginAsync(email, "a wrong secret passphrase");
        var session = await client.LoginBearerAsync(email, userId, firstPassword);
        var refreshed = await (await client.RefreshAsync(session.RefreshToken)).ReadJsonAsync();
        var access = refreshed.GetProperty("accessToken").GetString()!;
        var bearer = factory.BearerClient(access);
        (await bearer.PostAsJsonAsync("/api/v1/account/change-password", new { currentPassword = firstPassword, newPassword = secondPassword }))
            .StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await bearer.PostAsync("/api/v1/auth/logout", null)).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });
        var resetToken = factory.Emails.LastResetToken(email);
        (await client.PostAsJsonAsync("/api/v1/auth/reset-password", new { email, token = resetToken, newPassword = thirdPassword }))
            .StatusCode.ShouldBe(HttpStatusCode.OK);
        var last = await client.LoginBearerAsync(email, userId, thirdPassword);
        (await factory.BearerClient(last.AccessToken).PostAsync("/api/v1/auth/logout-all", null)).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var events = await factory.WithDbAsync(db => db.AuditEvents.Where(e => e.UserId == userId || e.Email == email).ToListAsync());

        events.Select(e => e.Type).Distinct().ShouldBe(
        [
            AuditEventType.Registered,
            AuditEventType.EmailConfirmed,
            AuditEventType.LoginFailed,
            AuditEventType.LoginSucceeded,
            AuditEventType.TokenRefreshed,
            AuditEventType.PasswordChanged,
            AuditEventType.Logout,
            AuditEventType.PasswordResetRequested,
            AuditEventType.PasswordResetCompleted,
            AuditEventType.LogoutAll,
        ], ignoreOrder: true);
        events.ShouldAllBe(e => e.IpAddress == null || e.IpAddress.Length <= 45);

        string[] secrets =
        [
            firstPassword, secondPassword, thirdPassword, "a wrong secret passphrase",
            confirmToken, resetToken, session.AccessToken, session.RefreshToken, access, last.RefreshToken,
            refreshed.GetProperty("refreshToken").GetString()!,
        ];
        foreach (var ev in events)
        {
            var text = $"{ev.Details}|{ev.Email}|{ev.UserAgent}";
            secrets.ShouldAllBe(secret => !text.Contains(secret, StringComparison.Ordinal));
        }
    }
}

public sealed class MaintenanceTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    [Fact]
    public async Task Cleanup_removes_old_inactive_sessions_and_keeps_active_ones()
    {
        var client = factory.CreateHttpsClient();
        var old = await factory.CreateUserAndLoginAsync(client);
        (await factory.BearerClient(old.AccessToken).PostAsync("/api/v1/auth/logout", null)).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        factory.Clock.Advance(TimeSpan.FromDays(31));
        var fresh = await factory.CreateUserAndLoginAsync(client);

        var removed = await factory.Services.GetRequiredService<SessionCleanupService>().RunOnceAsync(default);

        removed.ShouldBeGreaterThan(0);
        (await factory.WithDbAsync(db => db.Sessions.AnyAsync(s => s.UserId == old.UserId))).ShouldBeFalse();
        (await factory.WithDbAsync(db => db.Sessions.AnyAsync(s => s.UserId == fresh.UserId))).ShouldBeTrue();
        (await factory.BearerClient(fresh.AccessToken).GetAsync("/api/v1/account/me")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Audit_retention_removes_only_events_older_than_the_retention_window()
    {
        var client = factory.CreateHttpsClient();
        var old = await factory.CreateUserAndLoginAsync(client);

        factory.Clock.Advance(TimeSpan.FromDays(181));
        var recent = await factory.CreateUserAndLoginAsync(client);

        var removed = await factory.Services.GetRequiredService<AuditRetentionService>().RunOnceAsync(default);

        removed.ShouldBeGreaterThan(0);
        (await factory.WithDbAsync(db => db.AuditEvents.AnyAsync(e => e.UserId == old.UserId))).ShouldBeFalse();
        (await factory.WithDbAsync(db => db.AuditEvents.AnyAsync(e => e.UserId == recent.UserId))).ShouldBeTrue();
    }
}

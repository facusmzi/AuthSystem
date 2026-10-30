using System.Net;
using System.Net.Http.Json;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using static Auth.IntegrationTests.Infrastructure.ApiTestExtensions;

namespace Auth.IntegrationTests.Auth;

public sealed class EmailConfirmationTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private readonly HttpClient _client = factory.CreateHttpsClient();

    [Fact]
    public async Task Valid_token_confirms_the_email()
    {
        var email = NewEmail();
        await _client.RegisterAsync(email);
        var (userId, token) = factory.Emails.LastConfirmationLink(email);

        var response = await _client.PostAsJsonAsync("/api/v1/auth/confirm-email", new { userId, token });

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await factory.WithDbAsync(db => db.Users.SingleAsync(u => u.Id == userId))).EmailConfirmed.ShouldBeTrue();
    }

    [Fact]
    public async Task Tampered_token_or_unknown_user_return_the_same_generic_error()
    {
        var email = NewEmail();
        await _client.RegisterAsync(email);
        var (userId, token) = factory.Emails.LastConfirmationLink(email);

        var tampered = await _client.PostAsJsonAsync("/api/v1/auth/confirm-email", new { userId, token = token[..^4] + "AAAA" });
        await tampered.ShouldBeProblemAsync(HttpStatusCode.BadRequest, "INVALID_TOKEN");

        var unknown = await _client.PostAsJsonAsync("/api/v1/auth/confirm-email", new { userId = Guid.NewGuid(), token });
        await unknown.ShouldBeProblemAsync(HttpStatusCode.BadRequest, "INVALID_TOKEN");

        var otherUser = NewEmail();
        await _client.RegisterAsync(otherUser);
        var (otherId, _) = factory.Emails.LastConfirmationLink(otherUser);
        var wrongUser = await _client.PostAsJsonAsync("/api/v1/auth/confirm-email", new { userId = otherId, token });
        await wrongUser.ShouldBeProblemAsync(HttpStatusCode.BadRequest, "INVALID_TOKEN");
    }

    [Fact]
    public async Task Token_expires_after_24_hours()
    {
        var email = NewEmail();
        await _client.RegisterAsync(email);
        var (userId, token) = factory.Emails.LastConfirmationLink(email);

        factory.Clock.Advance(TimeSpan.FromHours(24) + TimeSpan.FromMinutes(1));
        var response = await _client.PostAsJsonAsync("/api/v1/auth/confirm-email", new { userId, token });

        await response.ShouldBeProblemAsync(HttpStatusCode.BadRequest, "INVALID_TOKEN");
    }

    [Fact]
    public async Task Resend_enforces_a_per_user_cooldown_and_never_reveals_the_account()
    {
        var email = NewEmail();
        await _client.RegisterAsync(email);
        var before = factory.Emails.To(email).Count;
        factory.Clock.Advance(TimeSpan.FromSeconds(61));

        (await _client.PostAsJsonAsync("/api/v1/auth/resend-confirmation", new { email })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        factory.Emails.To(email).Count.ShouldBe(before + 1);

        (await _client.PostAsJsonAsync("/api/v1/auth/resend-confirmation", new { email })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        factory.Emails.To(email).Count.ShouldBe(before + 1);

        factory.Clock.Advance(TimeSpan.FromSeconds(61));
        (await _client.PostAsJsonAsync("/api/v1/auth/resend-confirmation", new { email })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        factory.Emails.To(email).Count.ShouldBe(before + 2);

        var unknown = NewEmail();
        (await _client.PostAsJsonAsync("/api/v1/auth/resend-confirmation", new { email = unknown })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        factory.Emails.To(unknown).ShouldBeEmpty();
    }

    [Fact]
    public async Task Resend_for_confirmed_account_sends_nothing()
    {
        var email = NewEmail();
        await factory.RegisterConfirmedAsync(_client, email);
        var before = factory.Emails.To(email).Count;
        factory.Clock.Advance(TimeSpan.FromMinutes(2));

        (await _client.PostAsJsonAsync("/api/v1/auth/resend-confirmation", new { email })).StatusCode.ShouldBe(HttpStatusCode.Accepted);

        factory.Emails.To(email).Count.ShouldBe(before);
    }
}

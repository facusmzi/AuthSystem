using System.Net;
using System.Net.Http.Json;
using Auth.Domain.Audit;
using Auth.Domain.Authorization;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using static Auth.IntegrationTests.Infrastructure.ApiTestExtensions;

namespace Auth.IntegrationTests.Auth;

public sealed class RegistrationTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private readonly HttpClient _client = factory.CreateHttpsClient();

    [Fact]
    public async Task Register_returns_202_creates_unconfirmed_user_with_user_role_and_sends_link()
    {
        var email = NewEmail();

        var response = await _client.RegisterAsync(email);

        response.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        (await response.ReadJsonAsync()).GetProperty("message").GetString().ShouldBe("If the email is valid, you'll receive a confirmation link.");
        factory.Emails.LastTo(email).Subject.ShouldContain("Confirm");

        var user = await factory.WithDbAsync(db => db.Users.SingleAsync(u => u.Email == email));
        user.EmailConfirmed.ShouldBeFalse();
        user.PasswordHash.ShouldNotBeNull().ShouldStartWith("$argon2id$");
        var roles = await factory.WithDbAsync(db =>
            db.UserRoles.Where(ur => ur.UserId == user.Id).Join(db.Roles, ur => ur.RoleId, r => r.Id, (_, r) => r.Name).ToListAsync());
        roles.ShouldBe([SystemRoles.User]);
    }

    [Fact]
    public async Task Register_normalizes_email_to_lowercase()
    {
        var email = NewEmail();

        (await _client.RegisterAsync("  " + email.ToUpperInvariant() + " ")).StatusCode.ShouldBe(HttpStatusCode.Accepted);

        (await factory.WithDbAsync(db => db.Users.CountAsync(u => u.Email == email))).ShouldBe(1);
    }

    [Fact]
    public async Task Register_with_existing_email_does_not_reveal_it_and_warns_the_owner()
    {
        var email = NewEmail();
        await _client.RegisterAsync(email);

        var second = await _client.RegisterAsync(email, "another strong passphrase");

        second.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        (await second.ReadJsonAsync()).GetProperty("message").GetString().ShouldBe("If the email is valid, you'll receive a confirmation link.");
        factory.Emails.LastTo(email).Subject.ShouldContain("Sign-up attempt");
        (await factory.WithDbAsync(db => db.Users.CountAsync(u => u.Email == email))).ShouldBe(1);

        var audit = await factory.WithDbAsync(db => db.AuditEvents.Where(e => e.Email == email).Select(e => e.Type).ToListAsync());
        audit.ShouldContain(AuditEventType.Registered);
        audit.ShouldContain(AuditEventType.RegistrationAttemptExistingEmail);
    }

    [Fact]
    public async Task Weak_password_returns_422_even_for_existing_email()
    {
        var email = NewEmail();
        await _client.RegisterAsync(email);

        foreach (var target in new[] { NewEmail(), email })
        {
            var response = await _client.RegisterAsync(target, "short");
            var problem = await response.ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "PASSWORD_TOO_WEAK");
            problem.GetProperty("errors").GetProperty("password").GetArrayLength().ShouldBeGreaterThan(0);
        }
    }

    [Fact]
    public async Task Password_equal_to_email_is_rejected()
    {
        var email = NewEmail();

        var response = await _client.RegisterAsync(email, email);

        await response.ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "PASSWORD_TOO_WEAK");
    }

    [Fact]
    public async Task Breached_password_returns_422_password_breached()
    {
        var response = await _client.RegisterAsync(NewEmail(), FakeBreachChecker.BreachedPassword);

        await response.ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "PASSWORD_BREACHED");
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("")]
    public async Task Invalid_email_returns_422_validation_failed(string email)
    {
        var response = await _client.RegisterAsync(email);

        var problem = await response.ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "VALIDATION_FAILED");
        problem.GetProperty("errors").TryGetProperty("email", out _).ShouldBeTrue();
    }

    [Fact]
    public async Task Missing_body_returns_400_problem()
    {
        var response = await _client.PostAsync("/api/v1/auth/register", JsonContent.Create<object?>(null));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType?.MediaType.ShouldBe("application/problem+json");
    }

    [Fact]
    public async Task Audit_events_never_contain_the_password()
    {
        var email = NewEmail();
        await _client.RegisterAsync(email, "a very unique secret phrase 42");

        var details = await factory.WithDbAsync(db => db.AuditEvents.Where(e => e.Email == email).Select(e => e.Details ?? "").ToListAsync());

        details.ShouldAllBe(d => !d.Contains("unique secret phrase", StringComparison.Ordinal));
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.Domain.Audit;
using Auth.Domain.Sessions;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using static Auth.IntegrationTests.Infrastructure.ApiTestExtensions;

namespace Auth.IntegrationTests.Auth;

public sealed class MfaTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private readonly HttpClient _client = factory.CreateHttpsClient();

    private sealed record MfaUser(BearerSession Session, string Secret, IReadOnlyList<string> RecoveryCodes);

    private async Task<MfaUser> CreateMfaUserAsync()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var bearer = factory.BearerClient(session.AccessToken);

        var setup = await (await bearer.PostAsync("/api/v1/account/mfa/setup", null)).ReadJsonAsync();
        var uri = setup.GetProperty("otpAuthUri").GetString()!;
        uri.ShouldStartWith("otpauth://totp/Auth:");
        var secret = Totp.SecretFromUri(uri);

        // Usa el código del paso anterior para no "gastar" el actual (anti-replay).
        var enable = await bearer.PostAsJsonAsync("/api/v1/account/mfa/enable", new { code = Totp.Code(secret, -1) });
        enable.StatusCode.ShouldBe(HttpStatusCode.OK, await enable.Content.ReadAsStringAsync());
        var codes = (await enable.ReadJsonAsync()).GetProperty("codes").EnumerateArray().Select(c => c.GetString()!).ToList();
        return new MfaUser(session, secret, codes);
    }

    private async Task<string> StartLoginAsync(string email, bool useCookies = false)
    {
        var response = await _client.PostAsJsonAsync($"/api/v1/auth/login?useCookies={useCookies}", new { email, password = DefaultPassword });
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        var body = await response.ReadJsonAsync();
        body.GetProperty("requiresMfa").GetBoolean().ShouldBeTrue();
        body.GetProperty("tokens").ValueKind.ShouldBe(JsonValueKind.Null);
        body.GetProperty("user").ValueKind.ShouldBe(JsonValueKind.Null);
        return body.GetProperty("mfaToken").GetString()!;
    }

    private Task<HttpResponseMessage> CompleteAsync(string mfaToken, string? code = null, string? recoveryCode = null) =>
        _client.PostAsJsonAsync("/api/v1/auth/login/mfa", new { mfaToken, code, recoveryCode });

    [Fact]
    public async Task Full_flow_setup_enable_and_login_with_totp()
    {
        var user = await CreateMfaUserAsync();
        user.RecoveryCodes.Count.ShouldBe(10);
        user.RecoveryCodes.Distinct().Count().ShouldBe(10);

        var mfaToken = await StartLoginAsync(user.Session.Email);
        var response = await CompleteAsync(mfaToken, code: Totp.Code(user.Secret));

        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        var body = await response.ReadJsonAsync();
        var access = body.GetProperty("tokens").GetProperty("accessToken").GetString()!;
        new JsonWebToken(access).Claims.Where(c => c.Type == "amr").Select(c => c.Value).ShouldBe(["pwd", "mfa"]);
        body.GetProperty("user").GetProperty("mfaEnabled").GetBoolean().ShouldBeTrue();

        var status = await (await factory.BearerClient(access).GetAsync("/api/v1/account/mfa")).ReadJsonAsync();
        status.GetProperty("enabled").GetBoolean().ShouldBeTrue();
        status.GetProperty("recoveryCodesLeft").GetInt32().ShouldBe(10);

        var methods = await factory.WithDbAsync(db => db.Sessions.Where(s => s.UserId == user.Session.UserId && s.RevokedAt == null).Select(s => s.LoginMethod).ToListAsync());
        methods.ShouldContain(LoginMethod.PasswordMfa);
        factory.Emails.To(user.Session.Email).ShouldContain(m => m.Subject.Contains("Two-factor authentication enabled"));
    }

    [Fact]
    public async Task Enabling_mfa_revokes_other_sessions_but_keeps_the_current_one()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var other = await _client.LoginBearerAsync(session.Email, session.UserId);
        var bearer = factory.BearerClient(session.AccessToken);
        var secret = Totp.SecretFromUri((await (await bearer.PostAsync("/api/v1/account/mfa/setup", null)).ReadJsonAsync()).GetProperty("otpAuthUri").GetString()!);

        (await bearer.PostAsJsonAsync("/api/v1/account/mfa/enable", new { code = Totp.Code(secret) })).StatusCode.ShouldBe(HttpStatusCode.OK);

        (await bearer.GetAsync("/api/v1/account/me")).StatusCode.ShouldBe(HttpStatusCode.OK);
        await (await factory.BearerClient(other.AccessToken).GetAsync("/api/v1/account/me")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
        await (await bearer.PostAsync("/api/v1/account/mfa/setup", null)).ShouldBeProblemAsync(HttpStatusCode.Conflict, "CONFLICT");
    }

    [Fact]
    public async Task Invalid_codes_count_towards_lockout()
    {
        var user = await CreateMfaUserAsync();

        for (var i = 0; i < 5; i++)
        {
            var token = await StartLoginAsync(user.Session.Email);
            await (await CompleteAsync(token, code: "000000")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "MFA_INVALID");
        }

        await (await _client.LoginAsync(user.Session.Email)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS");
        var audit = await factory.WithDbAsync(db => db.AuditEvents.Where(e => e.UserId == user.Session.UserId).Select(e => e.Type).ToListAsync());
        audit.ShouldContain(AuditEventType.MfaFailed);
        audit.ShouldContain(AuditEventType.LoginLockedOut);
    }

    [Fact]
    public async Task The_same_totp_code_cannot_be_used_twice()
    {
        var user = await CreateMfaUserAsync();
        var code = Totp.Code(user.Secret);

        (await CompleteAsync(await StartLoginAsync(user.Session.Email), code: code)).StatusCode.ShouldBe(HttpStatusCode.OK);

        await (await CompleteAsync(await StartLoginAsync(user.Session.Email), code: code)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "MFA_INVALID");
    }

    [Fact]
    public async Task Recovery_code_works_once_and_notifies_the_user()
    {
        var user = await CreateMfaUserAsync();
        var recovery = user.RecoveryCodes[0];

        var ok = await CompleteAsync(await StartLoginAsync(user.Session.Email), recoveryCode: recovery.ToLowerInvariant());
        ok.StatusCode.ShouldBe(HttpStatusCode.OK, await ok.Content.ReadAsStringAsync());
        factory.Emails.LastTo(user.Session.Email).Subject.ShouldContain("recovery code was used");

        await (await CompleteAsync(await StartLoginAsync(user.Session.Email), recoveryCode: recovery)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "MFA_INVALID");

        var access = (await ok.ReadJsonAsync()).GetProperty("tokens").GetProperty("accessToken").GetString()!;
        (await (await factory.BearerClient(access).GetAsync("/api/v1/account/mfa")).ReadJsonAsync()).GetProperty("recoveryCodesLeft").GetInt32().ShouldBe(9);
        (await factory.WithDbAsync(db => db.AuditEvents.AnyAsync(e => e.UserId == user.Session.UserId && e.Type == AuditEventType.RecoveryCodeUsed))).ShouldBeTrue();
    }

    [Fact]
    public async Task Mfa_token_is_single_use_and_expires()
    {
        var user = await CreateMfaUserAsync();

        var token = await StartLoginAsync(user.Session.Email);
        (await CompleteAsync(token, code: Totp.Code(user.Secret))).StatusCode.ShouldBe(HttpStatusCode.OK);
        await (await CompleteAsync(token, code: Totp.Code(user.Secret, -1))).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "MFA_INVALID");

        var expiring = await StartLoginAsync(user.Session.Email);
        factory.Clock.Advance(TimeSpan.FromMinutes(6));
        await (await CompleteAsync(expiring, code: Totp.Code(user.Secret, 1))).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "MFA_INVALID");

        await (await CompleteAsync("garbage-token", code: "123456")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "MFA_INVALID");
    }

    [Fact]
    public async Task Mfa_token_is_bound_to_the_requested_session_kind()
    {
        var user = await CreateMfaUserAsync();
        var bearerToken = await StartLoginAsync(user.Session.Email);

        var csrf = (await (await _client.GetAsync("/api/v1/auth/antiforgery")).ReadJsonAsync()).GetProperty("token").GetString()!;
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login/mfa?useCookies=true")
        {
            Content = JsonContent.Create(new { mfaToken = bearerToken, code = Totp.Code(user.Secret) }),
        };
        request.Headers.Add("X-XSRF-TOKEN", csrf);

        await (await _client.SendAsync(request)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "MFA_INVALID");
    }

    [Fact]
    public async Task Validation_requires_exactly_one_of_code_or_recovery_code()
    {
        var user = await CreateMfaUserAsync();
        var token = await StartLoginAsync(user.Session.Email);

        await (await CompleteAsync(token)).ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "VALIDATION_FAILED");
        await (await CompleteAsync(token, code: "123456", recoveryCode: "ABCDE-FGHIJ")).ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "VALIDATION_FAILED");
    }

    [Fact]
    public async Task Disabling_requires_password_and_code()
    {
        var user = await CreateMfaUserAsync();
        var bearer = factory.BearerClient(user.Session.AccessToken);

        await (await bearer.PostAsJsonAsync("/api/v1/account/mfa/disable", new { password = "not the password!!", code = Totp.Code(user.Secret) }))
            .ShouldBeProblemAsync(HttpStatusCode.BadRequest, "INVALID_CREDENTIALS");
        await (await bearer.PostAsJsonAsync("/api/v1/account/mfa/disable", new { password = DefaultPassword, code = "000000" }))
            .ShouldBeProblemAsync(HttpStatusCode.BadRequest, "MFA_INVALID");

        (await bearer.PostAsJsonAsync("/api/v1/account/mfa/disable", new { password = DefaultPassword, code = Totp.Code(user.Secret) }))
            .StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var login = await (await _client.LoginAsync(user.Session.Email)).ReadJsonAsync();
        login.GetProperty("requiresMfa").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task Recovery_codes_and_authenticator_key_are_not_stored_in_plain_text()
    {
        var user = await CreateMfaUserAsync();

        var tokens = await factory.WithDbAsync(db => db.UserTokens.Where(t => t.UserId == user.Session.UserId).Select(t => t.Value ?? "").ToListAsync());

        tokens.ShouldNotBeEmpty();
        foreach (var value in tokens)
        {
            value.ShouldNotContain(user.Secret);
            user.RecoveryCodes.ShouldAllBe(code => !value.Contains(code, StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public async Task Regenerating_recovery_codes_invalidates_the_old_ones()
    {
        var user = await CreateMfaUserAsync();
        var bearer = factory.BearerClient(user.Session.AccessToken);

        var regenerated = await bearer.PostAsJsonAsync("/api/v1/account/mfa/recovery-codes", new { code = Totp.Code(user.Secret) });
        regenerated.StatusCode.ShouldBe(HttpStatusCode.OK);
        var fresh = (await regenerated.ReadJsonAsync()).GetProperty("codes").EnumerateArray().Select(c => c.GetString()!).ToList();

        await (await CompleteAsync(await StartLoginAsync(user.Session.Email), recoveryCode: user.RecoveryCodes[0])).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "MFA_INVALID");
        (await CompleteAsync(await StartLoginAsync(user.Session.Email), recoveryCode: fresh[0])).StatusCode.ShouldBe(HttpStatusCode.OK);
    }
}

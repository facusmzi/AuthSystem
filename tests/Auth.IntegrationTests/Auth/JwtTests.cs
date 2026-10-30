using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Auth.Infrastructure.Tokens;
using Auth.IntegrationTests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Auth.IntegrationTests.Auth;

public sealed class JwtTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private const string Protected = "/api/v1/account/sessions";
    private readonly HttpClient _client = factory.CreateHttpsClient();

    private Task<HttpResponseMessage> GetWithAuthorization(string? scheme, string? value)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, Protected);
        if (scheme is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(scheme, value);
        }
        return _client.SendAsync(request);
    }

    [Fact]
    public async Task Missing_header_returns_401_auth_header_missing()
    {
        var response = await GetWithAuthorization(null, null);

        await response.ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "AUTH_HEADER_MISSING");
        response.Headers.WwwAuthenticate.ToString().ShouldStartWith("Bearer");
    }

    [Theory]
    [InlineData("Basic", "dXNlcjpwYXNz")]
    [InlineData("Bearer", "not-a-jwt")]
    [InlineData("Bearer", "eyJhbGciOiJFUzI1NiJ9.e30.AAAA")]
    public async Task Malformed_header_or_token_returns_401_token_invalid(string scheme, string value)
    {
        await (await GetWithAuthorization(scheme, value)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "TOKEN_INVALID");
    }

    [Fact]
    public async Task Access_token_has_expected_header_and_claims()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);

        var jwt = new JsonWebToken(session.AccessToken);

        jwt.Alg.ShouldBe("ES256");
        jwt.Typ.ShouldBe("at+jwt");
        jwt.Kid.ShouldBe("test-1");
        jwt.Issuer.ShouldBe("https://auth.local");
        jwt.Audiences.ShouldBe(["auth-api"]);
        jwt.Subject.ShouldBe(session.UserId.ToString());
        jwt.GetClaim("sid").Value.ShouldNotBeNullOrEmpty();
        jwt.Id.ShouldNotBeNullOrEmpty();
        jwt.GetClaim("email_verified").Value.ShouldBe("true");
        jwt.GetClaim("amr").Value.ShouldBe("pwd");
        (jwt.ValidTo - jwt.IssuedAt).ShouldBe(TimeSpan.FromMinutes(10));
        jwt.Claims.ShouldNotContain(c => c.Type == "role");
    }

    [Fact]
    public async Task Expired_token_returns_401_token_expired()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        factory.Clock.Advance(TimeSpan.FromMinutes(11));

        await (await GetWithAuthorization("Bearer", session.AccessToken)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "TOKEN_EXPIRED");
    }

    [Fact]
    public async Task Tampered_signature_is_rejected()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var parts = session.AccessToken.Split('.');
        var signature = parts[2].ToCharArray();
        signature[5] = signature[5] == 'A' ? 'B' : 'A';
        var tampered = $"{parts[0]}.{parts[1]}.{new string(signature)}";

        await (await GetWithAuthorization("Bearer", tampered)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "TOKEN_INVALID");
    }

    [Fact]
    public async Task Tampered_payload_is_rejected()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var other = await factory.CreateUserAndLoginAsync(_client);
        var parts = session.AccessToken.Split('.');
        var otherPayload = other.AccessToken.Split('.')[1];

        await (await GetWithAuthorization("Bearer", $"{parts[0]}.{otherPayload}.{parts[2]}")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "TOKEN_INVALID");
    }

    [Fact]
    public async Task Hs256_and_none_algorithms_are_rejected()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var source = new JsonWebToken(session.AccessToken);
        var claims = new Dictionary<string, object>
        {
            ["sub"] = source.Subject,
            ["sid"] = source.GetClaim("sid").Value,
            ["email_verified"] = true,
        };
        var handler = new JsonWebTokenHandler();
        var now = DateTime.UtcNow;

        var hs256 = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://auth.local",
            Audience = "auth-api",
            Claims = claims,
            TokenType = "at+jwt",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), SecurityAlgorithms.HmacSha256),
        });
        await (await GetWithAuthorization("Bearer", hs256)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "TOKEN_INVALID");

        static string B64(string json) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));
        var payload = new JsonWebToken(session.AccessToken).EncodedPayload;
        var none = $"{B64("{\"alg\":\"none\",\"typ\":\"at+jwt\"}")}.{payload}.";
        await (await GetWithAuthorization("Bearer", none)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "TOKEN_INVALID");
    }

    [Theory]
    [InlineData("https://evil.example", "auth-api", "at+jwt")]
    [InlineData("https://auth.local", "other-api", "at+jwt")]
    [InlineData("https://auth.local", "auth-api", "JWT")]
    public async Task Wrong_issuer_audience_or_type_is_rejected_even_with_a_valid_signature(string issuer, string audience, string type)
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var source = new JsonWebToken(session.AccessToken);
        var keys = factory.Services.GetRequiredService<EcdsaSigningKeyProvider>();
        var now = factory.Clock.GetUtcNow().UtcDateTime;

        var forged = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            TokenType = type,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            SigningCredentials = keys.SigningCredentials,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = source.Subject,
                ["sid"] = source.GetClaim("sid").Value,
                ["email_verified"] = true,
            },
        });

        await (await GetWithAuthorization("Bearer", forged)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "TOKEN_INVALID");
    }

    [Fact]
    public async Task Refresh_token_cannot_be_used_as_access_token()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);

        await (await GetWithAuthorization("Bearer", session.RefreshToken)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "TOKEN_INVALID");
    }

    [Fact]
    public async Task Revoked_session_is_rejected_immediately()
    {
        var session = await factory.CreateUserAndLoginAsync(_client);
        var bearer = factory.BearerClient(session.AccessToken);
        (await bearer.GetAsync(Protected)).StatusCode.ShouldBe(HttpStatusCode.OK);

        (await bearer.PostAsync("/api/v1/auth/logout", null)).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        await (await bearer.GetAsync(Protected)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
    }

    [Fact]
    public async Task Jwks_publishes_only_public_key_matching_token_kid()
    {
        var response = await _client.GetAsync("/.well-known/jwks.json");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var raw = await response.Content.ReadAsStringAsync();
        raw.ShouldNotContain("\"d\"");
        var jwks = new JsonWebKeySet(raw);
        var key = jwks.Keys.ShouldHaveSingleItem();
        key.Kid.ShouldBe("test-1");
        key.Kty.ShouldBe("EC");
        key.Crv.ShouldBe("P-256");
        key.Alg.ShouldBe("ES256");
        key.HasPrivateKey.ShouldBeFalse();

        // Un tercero puede validar el token solo con el JWKS.
        var session = await factory.CreateUserAndLoginAsync(_client);
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(session.AccessToken, new TokenValidationParameters
        {
            ValidIssuer = "https://auth.local",
            ValidAudience = "auth-api",
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidTypes = ["at+jwt"],
            ValidateLifetime = false,
        });
        result.IsValid.ShouldBeTrue(result.Exception?.Message);
    }
}

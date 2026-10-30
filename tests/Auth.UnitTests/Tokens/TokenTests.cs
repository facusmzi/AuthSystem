using System.Buffers.Text;
using Auth.Application.Abstractions;
using Auth.Domain.Sessions;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Tokens;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using NSubstitute;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace Auth.UnitTests.Tokens;

public sealed class RefreshTokenGeneratorTests
{
    [Fact]
    public void Generates_32_random_bytes_as_base64url()
    {
        var token = RefreshTokenGenerator.Generate();

        Base64Url.DecodeFromChars(token).Length.ShouldBe(32);
        token.ShouldNotContain("+");
        token.ShouldNotContain("/");
        token.ShouldNotContain("=");
    }

    [Fact]
    public void Tokens_are_unique()
    {
        Enumerable.Range(0, 1000).Select(_ => RefreshTokenGenerator.Generate()).Distinct().Count().ShouldBe(1000);
    }

    [Fact]
    public void Hash_is_deterministic_lowercase_sha256_hex()
    {
        var hash = RefreshTokenGenerator.Hash("abc");

        hash.ShouldBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        RefreshTokenGenerator.Hash("abc").ShouldBe(hash);
    }
}

public sealed class JwtTokenServiceTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "auth-unit", Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    private readonly EcdsaSigningKeyProvider _keys;
    private readonly JwtTokenService _service;

    public JwtTokenServiceTests()
    {
        var environment = Substitute.For<IHostEnvironment>();
        environment.ContentRootPath.Returns(_directory);
        var options = MsOptions.Create(new JwtOptions
        {
            Issuer = "https://issuer.test",
            Audience = "aud-test",
            AccessTokenMinutes = 10,
            GenerateMissingKeys = true,
            SigningKeys =
            [
                new SigningKeyOptions { Kid = "old", Path = "old.pem", Active = false },
                new SigningKeyOptions { Kid = "new", Path = "new.pem", Active = true },
            ],
        });
        _keys = new EcdsaSigningKeyProvider(options, environment, NullLogger<EcdsaSigningKeyProvider>.Instance);
        _service = new JwtTokenService(_keys, options, _clock);
    }

    [Fact]
    public void Token_contains_required_claims_and_header()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        var token = _service.CreateAccessToken(new AccessTokenRequest(userId, sessionId, LoginMethod.PasswordMfa, true));
        var jwt = new JsonWebToken(token.Token);

        jwt.Alg.ShouldBe("ES256");
        jwt.Typ.ShouldBe("at+jwt");
        jwt.Kid.ShouldBe("new");
        jwt.Issuer.ShouldBe("https://issuer.test");
        jwt.Audiences.ShouldBe(["aud-test"]);
        jwt.Subject.ShouldBe(userId.ToString());
        jwt.GetClaim("sid").Value.ShouldBe(sessionId.ToString());
        jwt.Claims.Where(c => c.Type == "amr").Select(c => c.Value).ShouldBe(["pwd", "mfa"]);
        jwt.GetClaim("email_verified").Value.ShouldBe("true");
        jwt.Id.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void Lifetime_comes_from_the_injected_clock()
    {
        var token = _service.CreateAccessToken(new AccessTokenRequest(Guid.NewGuid(), Guid.NewGuid(), LoginMethod.Password, true));
        var jwt = new JsonWebToken(token.Token);

        jwt.IssuedAt.ShouldBe(_clock.GetUtcNow().UtcDateTime);
        jwt.ValidFrom.ShouldBe(_clock.GetUtcNow().UtcDateTime);
        jwt.ValidTo.ShouldBe(_clock.GetUtcNow().UtcDateTime.AddMinutes(10));
        token.ExpiresAt.ShouldBe(jwt.ValidTo);
    }

    [Fact]
    public void Each_token_has_a_unique_jti()
    {
        var request = new AccessTokenRequest(Guid.NewGuid(), Guid.NewGuid(), LoginMethod.Password, true);

        new JsonWebToken(_service.CreateAccessToken(request).Token).Id
            .ShouldNotBe(new JsonWebToken(_service.CreateAccessToken(request).Token).Id);
    }

    [Fact]
    public void Rotation_keeps_old_keys_for_validation_and_publishes_only_public_parts()
    {
        _keys.ValidationKeys.Select(k => k.KeyId).ShouldBe(["old", "new"]);
        _keys.PublicKeys.Select(k => k.Kid).ShouldBe(["old", "new"]);
        _keys.PublicKeys.ShouldAllBe(k => k.Kty == "EC" && k.Crv == "P-256" && k.Alg == "ES256");
        File.ReadAllText(Path.Combine(_directory, "new.pem")).ShouldContain("BEGIN PRIVATE KEY");
    }

    public void Dispose()
    {
        _keys.Dispose();
        Directory.Delete(_directory, recursive: true);
    }
}

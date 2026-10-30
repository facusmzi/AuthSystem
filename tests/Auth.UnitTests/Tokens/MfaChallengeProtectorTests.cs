using Auth.Infrastructure.Caching;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Tokens;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Time.Testing;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace Auth.UnitTests.Tokens;

public sealed class MfaChallengeProtectorTests : IDisposable
{
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.UtcNow);
    private readonly MemoryCache _memory = new(new MemoryCacheOptions());
    private readonly MfaChallengeProtector _protector;

    public MfaChallengeProtectorTests() =>
        _protector = new MfaChallengeProtector(
            new EphemeralDataProtectionProvider(),
            new TimedCache(_memory, _clock),
            _clock,
            MsOptions.Create(new MfaOptions { ChallengeMinutes = 5 }));

    [Fact]
    public void Round_trips_user_stamp_and_session_kind()
    {
        var userId = Guid.NewGuid();

        var challenge = _protector.Unprotect(_protector.Protect(userId, "stamp-1", useCookies: true)).ShouldNotBeNull();

        challenge.UserId.ShouldBe(userId);
        challenge.SecurityStamp.ShouldBe("stamp-1");
        challenge.UseCookies.ShouldBeTrue();
        challenge.Jti.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void Expires_after_the_configured_lifetime()
    {
        var token = _protector.Protect(Guid.NewGuid(), "stamp", useCookies: false);

        _clock.Advance(TimeSpan.FromMinutes(4));
        _protector.Unprotect(token).ShouldNotBeNull();

        _clock.Advance(TimeSpan.FromMinutes(2));
        _protector.Unprotect(token).ShouldBeNull();
    }

    [Fact]
    public void Is_single_use()
    {
        var token = _protector.Protect(Guid.NewGuid(), "stamp", useCookies: false);
        var challenge = _protector.Unprotect(token).ShouldNotBeNull();

        _protector.TryConsume(challenge).ShouldBeTrue();

        _protector.TryConsume(challenge).ShouldBeFalse();
        _protector.Unprotect(token).ShouldBeNull();
    }

    [Fact]
    public void Rejects_tampered_or_foreign_tokens()
    {
        var token = _protector.Protect(Guid.NewGuid(), "stamp", useCookies: false);

        _protector.Unprotect(token[..^3] + "abc").ShouldBeNull();
        _protector.Unprotect("not-a-token").ShouldBeNull();
    }

    public void Dispose() => _memory.Dispose();
}

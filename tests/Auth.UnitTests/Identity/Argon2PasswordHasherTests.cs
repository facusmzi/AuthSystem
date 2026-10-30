using System.Text;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Security;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace Auth.UnitTests.Identity;

public sealed class Argon2PasswordHasherTests : IDisposable
{
    private readonly HashingConcurrencyLimiter _limiter;
    private readonly Argon2PasswordHasher _hasher;
    private readonly ApplicationUser _user = new();

    public Argon2PasswordHasherTests()
    {
        var options = Microsoft.Extensions.Options.Options.Create(Fast());
        _limiter = new HashingConcurrencyLimiter(options);
        _hasher = new Argon2PasswordHasher(options, _limiter);
    }

    private static PasswordHashingOptions Fast(int memory = 8192, int iterations = 1, int parallelism = 1) =>
        new() { MemoryKiB = memory, Iterations = iterations, Parallelism = parallelism, MaxConcurrentHashes = 2 };

    [Fact]
    public void Hash_uses_phc_format_with_configured_parameters()
    {
        var hash = _hasher.HashPassword(_user, "correct horse battery staple");

        hash.ShouldStartWith("$argon2id$v=19$m=8192,t=1,p=1$");
        var parts = hash.Split('$');
        parts.Length.ShouldBe(6);
        Convert.FromBase64String(parts[4] + "==").Length.ShouldBe(16);
        parts[5].ShouldNotContain("=");
    }

    [Fact]
    public void Same_password_produces_different_hashes_due_to_random_salt()
    {
        _hasher.HashPassword(_user, "same password!!").ShouldNotBe(_hasher.HashPassword(_user, "same password!!"));
    }

    [Fact]
    public void Verify_succeeds_for_correct_password_and_fails_for_wrong_one()
    {
        var hash = _hasher.HashPassword(_user, "correct horse battery staple");

        _hasher.VerifyHashedPassword(_user, hash, "correct horse battery staple").ShouldBe(PasswordVerificationResult.Success);
        _hasher.VerifyHashedPassword(_user, hash, "Correct horse battery staple").ShouldBe(PasswordVerificationResult.Failed);
        _hasher.VerifyHashedPassword(_user, hash, string.Empty).ShouldBe(PasswordVerificationResult.Failed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("$argon2i$v=19$m=8192,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA")]
    [InlineData("$argon2id$v=16$m=8192,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA")]
    [InlineData("$argon2id$v=19$m=999999999,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA")]
    [InlineData("AQAAAAIAAYagAAAAEJ...")] // hash PBKDF2 de Identity
    public void Verify_fails_for_malformed_or_foreign_hashes(string stored)
    {
        _hasher.VerifyHashedPassword(_user, stored, "whatever").ShouldBe(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void Verify_requests_rehash_when_parameters_changed()
    {
        var oldOptions = Microsoft.Extensions.Options.Options.Create(Fast(memory: 8192, iterations: 2));
        using var oldLimiter = new HashingConcurrencyLimiter(oldOptions);
        var oldHash = new Argon2PasswordHasher(oldOptions, oldLimiter).HashPassword(_user, "a long enough password");

        _hasher.VerifyHashedPassword(_user, oldHash, "a long enough password").ShouldBe(PasswordVerificationResult.SuccessRehashNeeded);
    }

    [Fact]
    public void Verifies_phc_hash_without_version_segment_and_with_foreign_parameters()
    {
        // Hash PHC construido con otra parametrización (como lo haría node-argon2 con valores distintos).
        var salt = Encoding.ASCII.GetBytes("staroverlaysalt!");
        using var argon = new Argon2id(Encoding.UTF8.GetBytes("Password123"))
        {
            Salt = salt,
            MemorySize = 8192,
            Iterations = 2,
            DegreeOfParallelism = 2,
        };
        var raw = argon.GetBytes(32);
        var b64 = (byte[] b) => Convert.ToBase64String(b).TrimEnd('=');

        var withVersion = $"$argon2id$v=19$m=8192,t=2,p=2${b64(salt)}${b64(raw)}";
        var withoutVersion = $"$argon2id$m=8192,t=2,p=2${b64(salt)}${b64(raw)}";

        _hasher.VerifyHashedPassword(_user, withVersion, "Password123").ShouldBe(PasswordVerificationResult.SuccessRehashNeeded);
        _hasher.VerifyHashedPassword(_user, withoutVersion, "Password123").ShouldBe(PasswordVerificationResult.SuccessRehashNeeded);
    }

    [Fact]
    public void Argon2id_implementation_matches_rfc9106_test_vector()
    {
        // RFC 9106 §5.3: garantiza interoperabilidad con cualquier implementación conforme (incluida node-argon2).
        using var argon = new Argon2id(Enumerable.Repeat((byte)0x01, 32).ToArray())
        {
            Salt = Enumerable.Repeat((byte)0x02, 16).ToArray(),
            KnownSecret = Enumerable.Repeat((byte)0x03, 8).ToArray(),
            AssociatedData = Enumerable.Repeat((byte)0x04, 12).ToArray(),
            MemorySize = 32,
            Iterations = 3,
            DegreeOfParallelism = 4,
        };

        Convert.ToHexStringLower(argon.GetBytes(32))
            .ShouldBe("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }

    public void Dispose() => _limiter.Dispose();
}

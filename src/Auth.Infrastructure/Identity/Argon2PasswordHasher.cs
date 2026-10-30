using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Security;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Identity;

/// <summary>
/// Hasher Argon2id en formato PHC (<c>$argon2id$v=19$m=65536,t=3,p=4$salt$hash</c>), compatible con los hashes
/// generados por la librería <c>argon2</c> de Node del sistema original.
/// </summary>
public sealed class Argon2PasswordHasher(IOptions<PasswordHashingOptions> options, HashingConcurrencyLimiter limiter)
    : IPasswordHasher<ApplicationUser>
{
    private const int SaltLength = 16;
    private const int HashLength = 32;
    private const int Version = 19;

    public string HashPassword(ApplicationUser user, string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        var o = options.Value;
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Compute(password, salt, o.MemoryKiB, o.Iterations, o.Parallelism, HashLength);
        return Format(salt, hash, o.MemoryKiB, o.Iterations, o.Parallelism);
    }

    public PasswordVerificationResult VerifyHashedPassword(ApplicationUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(providedPassword);
        if (providedPassword.Length == 0 || !TryParse(hashedPassword, out var parsed))
        {
            return PasswordVerificationResult.Failed;
        }

        var actual = Compute(providedPassword, parsed.Salt, parsed.MemoryKiB, parsed.Iterations, parsed.Parallelism, parsed.Hash.Length);
        if (!CryptographicOperations.FixedTimeEquals(actual, parsed.Hash))
        {
            return PasswordVerificationResult.Failed;
        }

        var o = options.Value;
        var outdated = parsed.MemoryKiB != o.MemoryKiB
            || parsed.Iterations != o.Iterations
            || parsed.Parallelism != o.Parallelism
            || parsed.Hash.Length != HashLength
            || parsed.Salt.Length < SaltLength;

        return outdated ? PasswordVerificationResult.SuccessRehashNeeded : PasswordVerificationResult.Success;
    }

    internal static string Format(byte[] salt, byte[] hash, int memoryKiB, int iterations, int parallelism) =>
        string.Create(CultureInfo.InvariantCulture, $"$argon2id$v={Version}$m={memoryKiB},t={iterations},p={parallelism}${ToB64(salt)}${ToB64(hash)}");

    internal static bool TryParse(string? phc, out ParsedHash parsed)
    {
        parsed = default;
        if (string.IsNullOrEmpty(phc))
        {
            return false;
        }

        // $argon2id$v=19$m=..,t=..,p=..$salt$hash  (v= es opcional en hashes antiguos)
        var parts = phc.Split('$');
        if (parts.Length is not (5 or 6) || parts[0].Length != 0 || parts[1] != "argon2id")
        {
            return false;
        }

        var index = 2;
        if (parts.Length == 6)
        {
            if (parts[2] != $"v={Version}")
            {
                return false;
            }
            index = 3;
        }

        int m = 0, t = 0, p = 0;
        foreach (var kv in parts[index].Split(','))
        {
            var pair = kv.Split('=');
            if (pair.Length != 2 || !int.TryParse(pair[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                return false;
            }

            switch (pair[0])
            {
                case "m": m = value; break;
                case "t": t = value; break;
                case "p": p = value; break;
                default: return false;
            }
        }

        // Límites defensivos: un hash manipulado en la DB no debe poder pedir parámetros absurdos.
        if (m is < 8 or > 4 * 1024 * 1024 || t is < 1 or > 100 || p is < 1 or > 255)
        {
            return false;
        }

        var salt = FromB64(parts[index + 1]);
        var hash = FromB64(parts[index + 2]);
        if (salt is null || hash is null || salt.Length < 8 || hash.Length < 16)
        {
            return false;
        }

        parsed = new ParsedHash(m, t, p, salt, hash);
        return true;
    }

    private byte[] Compute(string password, byte[] salt, int memoryKiB, int iterations, int parallelism, int length) =>
        limiter.Run(() =>
        {
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            try
            {
                using var argon = new Argon2id(passwordBytes)
                {
                    Salt = salt,
                    MemorySize = memoryKiB,
                    Iterations = iterations,
                    DegreeOfParallelism = parallelism,
                };
                return argon.GetBytes(length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        });

    private static string ToB64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static byte[]? FromB64(string value)
    {
        var padded = (value.Length % 4) switch
        {
            2 => value + "==",
            3 => value + "=",
            _ => value,
        };

        try
        {
            return Convert.FromBase64String(padded);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    internal readonly record struct ParsedHash(int MemoryKiB, int Iterations, int Parallelism, byte[] Salt, byte[] Hash);
}

using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace Auth.IntegrationTests.Infrastructure;

/// <summary>Generador TOTP (RFC 6238: HMAC-SHA1, 30 s, 6 dígitos) para simular la app autenticadora.</summary>
public static class Totp
{
    public static string Code(string base32Secret, int stepOffset = 0)
    {
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30 + stepOffset;
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);

        var hash = HMACSHA1.HashData(FromBase32(base32Secret), counter);
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    public static string SecretFromUri(string otpAuthUri)
    {
        var query = new Uri(otpAuthUri).Query.TrimStart('?').Split('&');
        return query.Single(p => p.StartsWith("secret=", StringComparison.Ordinal))["secret=".Length..];
    }

    private static byte[] FromBase32(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var clean = input.Replace(" ", string.Empty, StringComparison.Ordinal).TrimEnd('=').ToUpperInvariant();
        var output = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var c in clean)
        {
            buffer = (buffer << 5) | alphabet.IndexOf(c, StringComparison.Ordinal);
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return [.. output];
    }
}

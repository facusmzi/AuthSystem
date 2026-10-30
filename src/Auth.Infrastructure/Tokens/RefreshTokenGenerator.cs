using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Infrastructure.Tokens;

/// <summary>Refresh tokens opacos: 32 bytes aleatorios (base64url). En la DB solo se guarda su SHA-256.</summary>
public static class RefreshTokenGenerator
{
    public const int ByteLength = 32;

    public static string Generate() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(ByteLength));

    /// <summary>SHA-256 en hex minúscula. El token tiene 256 bits de entropía: no necesita salt ni KDF.</summary>
    public static string Hash(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}

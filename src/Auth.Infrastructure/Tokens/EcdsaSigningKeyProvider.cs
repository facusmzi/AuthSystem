using System.Buffers.Text;
using System.Security.Cryptography;
using Auth.Infrastructure.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Infrastructure.Tokens;

/// <summary>Clave pública publicada en <c>/.well-known/jwks.json</c> (nunca incluye <c>d</c>).</summary>
public sealed record PublicJsonWebKey(string Kty, string Crv, string X, string Y, string Kid, string Use, string Alg);

/// <summary>
/// Claves ECDSA P-256 para firmar (ES256) y validar access tokens. Una clave activa firma; las demás solo
/// validan, lo que permite rotar sin invalidar tokens emitidos. Singleton.
/// </summary>
public sealed class EcdsaSigningKeyProvider : IDisposable
{
    private readonly List<ECDsa> _keys = [];

    public EcdsaSigningKeyProvider(IOptions<JwtOptions> options, IHostEnvironment environment, ILogger<EcdsaSigningKeyProvider> logger)
    {
        var jwt = options.Value;
        var validation = new List<SecurityKey>();
        var jwks = new List<PublicJsonWebKey>();

        foreach (var configured in jwt.SigningKeys)
        {
            var path = Path.GetFullPath(Path.Combine(environment.ContentRootPath, configured.Path));
            var ecdsa = LoadOrCreate(path, jwt.GenerateMissingKeys, logger);
            _keys.Add(ecdsa);

            var key = new ECDsaSecurityKey(ecdsa) { KeyId = configured.Kid };
            validation.Add(key);
            jwks.Add(ToJwk(ecdsa, configured.Kid));

            if (configured.Active)
            {
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
            }
        }

        ValidationKeys = validation;
        PublicKeys = jwks;
        if (SigningCredentials is null)
        {
            throw new InvalidOperationException("Exactly one Jwt:SigningKeys entry must be Active.");
        }
    }

    public SigningCredentials SigningCredentials { get; } = null!;

    public IReadOnlyList<SecurityKey> ValidationKeys { get; }

    public IReadOnlyList<PublicJsonWebKey> PublicKeys { get; }

    private static ECDsa LoadOrCreate(string path, bool generateIfMissing, ILogger logger)
    {
        var ecdsa = ECDsa.Create();
        if (File.Exists(path))
        {
            ecdsa.ImportFromPem(File.ReadAllText(path));
        }
        else if (generateIfMissing)
        {
            ecdsa.Dispose();
            ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, ecdsa.ExportPkcs8PrivateKeyPem());
            logger.LogWarning("Generated a new JWT signing key at {Path}. Do not use generated keys in production.", path);
        }
        else
        {
            ecdsa.Dispose();
            throw new InvalidOperationException($"JWT signing key not found: {path}");
        }

        if (ecdsa.KeySize != 256 || ecdsa.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            ecdsa.Dispose();
            throw new InvalidOperationException($"JWT signing key must be an EC P-256 key: {path}");
        }

        return ecdsa;
    }

    private static PublicJsonWebKey ToJwk(ECDsa ecdsa, string kid)
    {
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        return new PublicJsonWebKey(
            Kty: "EC",
            Crv: "P-256",
            X: Base64Url.EncodeToString(parameters.Q.X),
            Y: Base64Url.EncodeToString(parameters.Q.Y),
            Kid: kid,
            Use: "sig",
            Alg: SecurityAlgorithms.EcdsaSha256);
    }

    public void Dispose()
    {
        foreach (var key in _keys)
        {
            key.Dispose();
        }
    }
}

using System.ComponentModel.DataAnnotations;

namespace Auth.Api.Options;

public sealed class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    public const string Strict = "strict";
    public const string Login = "login";
    public const string Mfa = "mfa";
    public const string Refresh = "refresh";

    public bool Enabled { get; set; } = true;

    [Range(1, 1_000_000)]
    public int StrictPerMinute { get; set; } = 5;

    [Range(1, 1_000_000)]
    public int LoginPerMinute { get; set; } = 10;

    [Range(1, 1_000_000)]
    public int MfaPerMinute { get; set; } = 5;

    [Range(1, 1_000_000)]
    public int RefreshPerMinute { get; set; } = 10;

    [Range(1, 10_000_000)]
    public int GlobalPerMinute { get; set; } = 100;
}

public sealed class NetworkOptions
{
    public const string SectionName = "Network";

    /// <summary>Solo con <c>true</c> se procesa <c>X-Forwarded-For</c>, y solo desde proxies conocidos.</summary>
    public bool TrustProxy { get; set; }

    public string[] KnownProxies { get; set; } = [];

    /// <summary>Redes en notación CIDR, p.ej. <c>10.0.0.0/8</c>.</summary>
    public string[] KnownNetworks { get; set; } = [];
}

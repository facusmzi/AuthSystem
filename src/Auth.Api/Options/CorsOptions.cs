using System.ComponentModel.DataAnnotations;

namespace Auth.Api.Options;

public sealed class CorsOptions
{
    public const string SectionName = "Cors";
    public const string PolicyName = "Frontend";

    /// <summary>Orígenes exactos permitidos (esquema + host + puerto). Nunca "*".</summary>
    [Required]
    public string[] AllowedOrigins { get; set; } = [];
}

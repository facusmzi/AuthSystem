using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;

namespace Auth.IntegrationTests.Infrastructure;

/// <summary>
/// Host de pruebas: SQLite en un archivo temporal propio (permite requests concurrentes reales),
/// reloj falso, Argon2 barato y servicios externos reemplazados.
/// </summary>
public class AuthApiFactory : WebApplicationFactory<Program>
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "auth-tests", Guid.NewGuid().ToString("N"));

    public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);

    /// <summary>Overrides de configuración adicionales para fixtures especializados.</summary>
    protected virtual IReadOnlyDictionary<string, string?> ExtraSettings => new Dictionary<string, string?>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(_directory);
        builder.UseEnvironment("Testing");

        var settings = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Default"] = $"Data Source={Path.Combine(_directory, "auth.db")}",
            ["DataProtection:KeysPath"] = Path.Combine(_directory, "dp"),
            ["Jwt:GenerateMissingKeys"] = "true",
            ["Jwt:SigningKeys:0:Kid"] = "test-1",
            ["Jwt:SigningKeys:0:Path"] = Path.Combine(_directory, "jwt-test-1.pem"),
            ["Jwt:SigningKeys:0:Active"] = "true",
            ["PasswordHashing:MemoryKiB"] = "8192",
            ["PasswordHashing:Iterations"] = "1",
            ["PasswordHashing:Parallelism"] = "1",
            ["RateLimiting:StrictPerMinute"] = "10000",
            ["RateLimiting:LoginPerMinute"] = "10000",
            ["RateLimiting:MfaPerMinute"] = "10000",
            ["RateLimiting:RefreshPerMinute"] = "10000",
            ["RateLimiting:GlobalPerMinute"] = "100000",
            ["Email:Provider"] = "Logging",
            ["Hibp:Enabled"] = "false",
            ["Maintenance:Enabled"] = "false",
        };

        foreach (var (key, value) in ExtraSettings)
        {
            settings[key] = value;
        }

        foreach (var (key, value) in settings)
        {
            builder.UseSetting(key, value);
        }

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
            ConfigureServices(services);
        });
    }

    protected virtual void ConfigureServices(IServiceCollection services)
    {
    }

    public HttpClient CreateHttpsClient() => CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
                // Best effort: el directorio temporal se limpia en la próxima ejecución del SO.
            }
        }
    }
}

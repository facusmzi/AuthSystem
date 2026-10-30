using Auth.Infrastructure.Persistence;

namespace Auth.Api;

public static class DatabaseInitializationExtensions
{
    /// <summary>Aplica migraciones y siembra roles/permisos antes de aceptar tráfico.</summary>
    public static async Task InitializeDatabaseAsync(this WebApplication app)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var seeder = scope.ServiceProvider.GetRequiredService<DbSeeder>();
        await seeder.SeedAsync(app.Lifetime.ApplicationStopping);
    }
}

using Auth.Api;
using Auth.Infrastructure;
using Auth.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddApi(builder.Configuration, builder.Environment);

var app = builder.Build();

await app.InitializeDatabaseAsync();

// dotnet run --project src/Auth.Api -- seed-admin --email admin@example.com
if (args is ["seed-admin", "--email", var adminEmail, ..])
{
    await using var scope = app.Services.CreateAsyncScope();
    var assigned = await scope.ServiceProvider.GetRequiredService<DbSeeder>().AssignAdminAsync(adminEmail);
    Console.WriteLine(assigned
        ? "Admin role assigned."
        : "The user does not exist or has not confirmed the email. Register and confirm it first.");
    return assigned ? 0 : 1;
}

app.UseApiPipeline();
app.MapApiEndpoints();

await app.RunAsync();
return 0;

public partial class Program;

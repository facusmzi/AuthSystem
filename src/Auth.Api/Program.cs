using Auth.Api;
using Auth.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddApi(builder.Configuration, builder.Environment);

var app = builder.Build();

await app.InitializeDatabaseAsync();

app.UseApiPipeline();
app.MapApiEndpoints();

await app.RunAsync();

public partial class Program;

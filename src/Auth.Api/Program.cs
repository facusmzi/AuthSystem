using Auth.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddApi(builder.Configuration, builder.Environment);

var app = builder.Build();

app.UseApiPipeline();
app.MapApiEndpoints();

await app.RunAsync();

public partial class Program;

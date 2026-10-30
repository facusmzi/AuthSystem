using Auth.Api.Errors;
using Auth.Api.Filters;
using Auth.Api.Options;
using Auth.Application.Abstractions;
using Auth.Application.Features.Auth;

namespace Auth.Api.Endpoints;

public static class AuthEndpoints
{
    private static readonly MessageResponse RegistrationAccepted = new("If the email is valid, you'll receive a confirmation link.");
    private static readonly MessageResponse EmailAccepted = new("If the email is registered, you'll receive an email shortly.");

    public static RouteGroupBuilder MapAuthEndpoints(this RouteGroupBuilder api)
    {
        var auth = api.MapGroup("/auth").WithTags("Auth");

        auth.MapPost("/register", async (RegisterRequest request, IAuthService service, CancellationToken ct) =>
                (await service.RegisterAsync(request, ct)).ToHttpResult(() => TypedResults.Accepted((string?)null, RegistrationAccepted)))
            .Validate<RegisterRequest>()
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitingOptions.Strict)
            .WithName("Register");

        auth.MapPost("/confirm-email", async (ConfirmEmailRequest request, IAuthService service, CancellationToken ct) =>
                (await service.ConfirmEmailAsync(request, ct)).ToHttpResult(() => TypedResults.Ok(new MessageResponse("Email confirmed."))))
            .Validate<ConfirmEmailRequest>()
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitingOptions.Strict)
            .WithName("ConfirmEmail");

        auth.MapPost("/resend-confirmation", async (EmailRequest request, IAuthService service, CancellationToken ct) =>
                (await service.ResendConfirmationAsync(request, ct)).ToHttpResult(() => TypedResults.Accepted((string?)null, EmailAccepted)))
            .Validate<EmailRequest>()
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitingOptions.Strict)
            .WithName("ResendConfirmation");

        return auth;
    }
}

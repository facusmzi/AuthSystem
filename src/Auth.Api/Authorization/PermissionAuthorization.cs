using Auth.Api.Authentication;
using Auth.Application.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Auth.Api.Authorization;

public sealed class PermissionRequirement(string permission) : IAuthorizationRequirement
{
    public string Permission { get; } = permission;
}

/// <summary>
/// Evalúa el permiso contra los roles actuales del usuario (resueltos en servidor, con cache invalidable):
/// un cambio de roles aplica sin volver a iniciar sesión.
/// </summary>
public sealed class PermissionHandler(IPermissionService permissions) : AuthorizationHandler<PermissionRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        if (!Guid.TryParse(context.User.FindFirst(AuthClaims.Subject)?.Value, out var userId))
        {
            return;
        }

        var granted = await permissions.GetPermissionsAsync(userId, CancellationToken.None);
        if (granted.Contains(requirement.Permission))
        {
            context.Succeed(requirement);
        }
    }
}

/// <summary>Genera on-demand las políticas <c>perm:{permiso}</c>; el resto lo resuelve el provider por defecto.</summary>
public sealed class PermissionPolicyProvider(IOptions<AuthorizationOptions> options) : IAuthorizationPolicyProvider
{
    public const string Prefix = "perm:";

    private readonly DefaultAuthorizationPolicyProvider _fallback = new(options);

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (!policyName.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return _fallback.GetPolicyAsync(policyName);
        }

        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .RequireClaim(AuthClaims.EmailVerified, "true")
            .AddRequirements(new PermissionRequirement(policyName[Prefix.Length..]))
            .Build();
        return Task.FromResult<AuthorizationPolicy?>(policy);
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _fallback.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallback.GetFallbackPolicyAsync();
}

/// <summary><c>[HasPermission(Permissions.UsersRead)]</c> — equivalente MVC de <c>.RequirePermission(..)</c>.</summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class HasPermissionAttribute(string permission) : AuthorizeAttribute(PermissionPolicyProvider.Prefix + permission)
{
    public string Permission { get; } = permission;
}

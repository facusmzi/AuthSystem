using Auth.Application.Abstractions;
using Auth.Application.Common;
using Auth.Application.Features.Account;
using Auth.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;

namespace Auth.Infrastructure.Services;

internal sealed class AccountService(UserManager<ApplicationUser> users, IPermissionService permissions) : IAccountService
{
    public async Task<Result<MeResponse>> GetMeAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Error.NotFound("User not found.");
        }

        return await BuildMeAsync(user, permissions, cancellationToken);
    }

    internal static async Task<MeResponse> BuildMeAsync(ApplicationUser user, IPermissionService permissions, CancellationToken cancellationToken)
    {
        var roles = await permissions.GetRolesAsync(user.Id, cancellationToken);
        var perms = await permissions.GetPermissionsAsync(user.Id, cancellationToken);
        return new MeResponse(
            user.Id,
            user.Email!,
            user.EmailConfirmed,
            user.TwoFactorEnabled,
            roles,
            perms.Order(StringComparer.Ordinal).ToList(),
            user.CreatedAt);
    }
}

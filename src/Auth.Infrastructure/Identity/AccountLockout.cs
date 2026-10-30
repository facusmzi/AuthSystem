using Auth.Infrastructure.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Identity;

/// <summary>
/// Lockout de Identity con reloj inyectable. Los fallos de contraseña y de MFA comparten contador.
/// Un bloqueo por administrador usa <see cref="AdminLockEnd"/> como centinela.
/// </summary>
public sealed class AccountLockout(UserManager<ApplicationUser> users, IOptions<AccountLockoutOptions> options, TimeProvider time)
{
    public static readonly DateTimeOffset AdminLockEnd = DateTimeOffset.MaxValue;

    public bool IsLockedOut(ApplicationUser user) =>
        user.LockoutEnabled && user.LockoutEnd is { } end && end > time.GetUtcNow();

    public static bool IsAdminLocked(ApplicationUser user) => IsAdminLocked(user.LockoutEnd);

    public static bool IsAdminLocked(DateTimeOffset? lockoutEnd) => lockoutEnd == AdminLockEnd;

    /// <summary>Registra un fallo; devuelve true si este fallo bloqueó la cuenta.</summary>
    public async Task<bool> RecordFailureAsync(ApplicationUser user)
    {
        if (!user.LockoutEnabled)
        {
            return false;
        }

        var o = options.Value;
        user.AccessFailedCount++;
        var locked = false;
        if (user.AccessFailedCount >= o.MaxFailedAttempts)
        {
            user.LockoutEnd = time.GetUtcNow().AddMinutes(o.LockoutMinutes);
            user.AccessFailedCount = 0;
            locked = true;
        }

        await users.UpdateAsync(user);
        return locked;
    }

    public async Task ResetAsync(ApplicationUser user)
    {
        if (user.AccessFailedCount == 0 && (user.LockoutEnd is null || IsAdminLocked(user)))
        {
            return;
        }

        user.AccessFailedCount = 0;
        if (!IsAdminLocked(user))
        {
            user.LockoutEnd = null;
        }

        await users.UpdateAsync(user);
    }
}

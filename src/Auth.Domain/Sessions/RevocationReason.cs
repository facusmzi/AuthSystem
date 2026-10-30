namespace Auth.Domain.Sessions;

public enum RevocationReason
{
    Logout = 1,
    LogoutAll = 2,
    PasswordChanged = 3,
    PasswordReset = 4,
    MfaChanged = 5,
    RefreshReuse = 6,
    Admin = 7,
    UserLocked = 8,
}

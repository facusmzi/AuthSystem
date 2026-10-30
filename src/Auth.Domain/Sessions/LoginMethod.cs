namespace Auth.Domain.Sessions;

/// <summary>Cómo se autenticó el usuario al crear la sesión. Extensible (p.ej. <c>External</c> en v2).</summary>
public enum LoginMethod
{
    Password = 1,
    PasswordMfa = 2,
    RecoveryCode = 3,
}

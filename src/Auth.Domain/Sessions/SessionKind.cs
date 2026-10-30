namespace Auth.Domain.Sessions;

/// <summary>Cómo se transporta la sesión al cliente.</summary>
public enum SessionKind
{
    /// <summary>SPA web: cookie HttpOnly, sin tokens accesibles desde JavaScript.</summary>
    Cookie = 1,

    /// <summary>Apps nativas / servicios: access token JWT + refresh token opaco.</summary>
    Bearer = 2,
}

namespace Auth.Api.Authentication;

public static class AuthSchemes
{
    /// <summary>Esquema por defecto: elige Bearer si hay header <c>Authorization</c>, si no Cookie.</summary>
    public const string Smart = "Smart";
    public const string Bearer = "Bearer";
    public const string Cookie = "Cookie";
}

public static class AuthClaims
{
    public const string Subject = "sub";
    public const string SessionId = "sid";
    public const string AuthenticationMethod = "amr";
    public const string EmailVerified = "email_verified";
    public const string JwtId = "jti";
}

public static class AuthPolicies
{
    /// <summary>Autenticado, sin exigir email verificado (logout, /account/me).</summary>
    public const string Authenticated = "Authenticated";
}

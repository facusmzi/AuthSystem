namespace Auth.Application.Common;

/// <summary>Códigos de error estables expuestos en la extensión <c>code</c> de ProblemDetails.</summary>
public static class ErrorCodes
{
    public const string ValidationFailed = "VALIDATION_FAILED";
    public const string BadRequest = "BAD_REQUEST";
    public const string InvalidCredentials = "INVALID_CREDENTIALS";
    public const string EmailNotConfirmed = "EMAIL_NOT_CONFIRMED";
    public const string MfaRequired = "MFA_REQUIRED";
    public const string MfaInvalid = "MFA_INVALID";
    public const string AuthHeaderMissing = "AUTH_HEADER_MISSING";
    public const string TokenInvalid = "TOKEN_INVALID";
    public const string TokenExpired = "TOKEN_EXPIRED";
    public const string SessionRevoked = "SESSION_REVOKED";
    public const string RefreshInvalid = "REFRESH_INVALID";
    public const string InvalidToken = "INVALID_TOKEN";
    public const string PasswordBreached = "PASSWORD_BREACHED";
    public const string PasswordTooWeak = "PASSWORD_TOO_WEAK";
    public const string Forbidden = "FORBIDDEN";
    public const string NotFound = "NOT_FOUND";
    public const string RateLimited = "RATE_LIMITED";
    public const string AntiforgeryInvalid = "ANTIFORGERY_INVALID";
    public const string Conflict = "CONFLICT";
    public const string InternalError = "INTERNAL_ERROR";
}

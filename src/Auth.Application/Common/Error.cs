namespace Auth.Application.Common;

/// <summary>
/// Error esperado de la capa de aplicación. <see cref="Status"/> usa la semántica de códigos HTTP
/// sin depender de ASP.NET Core.
/// </summary>
public sealed record Error(string Code, string Message, int Status)
{
    /// <summary>Errores de validación por campo (solo para <see cref="ErrorCodes.ValidationFailed"/> y afines).</summary>
    public IReadOnlyDictionary<string, string[]>? FieldErrors { get; init; }

    public static Error Validation(IReadOnlyDictionary<string, string[]> errors, string code = ErrorCodes.ValidationFailed, string message = "One or more validation errors occurred.")
        => new(code, message, 422) { FieldErrors = errors };

    public static Error Unauthorized(string code, string message) => new(code, message, 401);
    public static Error Forbidden(string code, string message) => new(code, message, 403);
    public static Error NotFound(string message = "The resource was not found.") => new(ErrorCodes.NotFound, message, 404);
    public static Error Conflict(string message) => new(ErrorCodes.Conflict, message, 409);
    public static Error BadRequest(string code, string message) => new(code, message, 400);
}

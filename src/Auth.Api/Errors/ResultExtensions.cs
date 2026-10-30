using System.Diagnostics;
using Auth.Application.Common;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Errors;

public static class ResultExtensions
{
    public static ProblemResult ToProblem(this Error error)
    {
        if (error.FieldErrors is not null)
        {
            var validation = new ValidationProblemDetails(error.FieldErrors.ToDictionary(kv => kv.Key, kv => kv.Value))
            {
                Status = error.Status,
                Title = error.Message,
                Type = Problems.TypeFor(error.Status),
            };
            validation.Extensions["code"] = error.Code;
            return new ProblemResult(validation);
        }

        return new ProblemResult(Problems.Create(error.Status, error.Code, TitleFor(error.Status), error.Message));
    }

    public static IActionResult ToActionResult(this Result result, Func<IActionResult> onSuccess) =>
        result.IsSuccess ? onSuccess() : result.Error.ToProblem();

    public static IActionResult ToActionResult<T>(this Result<T> result, Func<T, IActionResult> onSuccess) =>
        result.IsSuccess ? onSuccess(result.Value) : result.Error!.ToProblem();

    private static string TitleFor(int status) => status switch
    {
        400 => "Bad request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not found",
        409 => "Conflict",
        422 => "Validation failed",
        429 => "Too many requests",
        _ => "Error",
    };
}

/// <summary>
/// Resultado MVC para ProblemDetails (RFC 9457) con las extensiones <c>code</c> y <c>traceId</c>.
/// Se serializa con el tipo concreto para no perder <c>errors</c> en los 422.
/// </summary>
public sealed class ProblemResult(ProblemDetails problem) : IActionResult
{
    public ProblemDetails Problem => problem;

    public Task ExecuteResultAsync(ActionContext context)
    {
        problem.Extensions.TryAdd("traceId", Activity.Current?.Id ?? context.HttpContext.TraceIdentifier);
        var result = new ObjectResult(problem)
        {
            StatusCode = problem.Status ?? StatusCodes.Status500InternalServerError,
            DeclaredType = problem.GetType(),
            ContentTypes = { "application/problem+json" },
        };
        return result.ExecuteResultAsync(context);
    }
}

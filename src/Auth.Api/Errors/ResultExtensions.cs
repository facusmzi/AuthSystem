using Auth.Application.Common;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Errors;

public static class ResultExtensions
{
    public static IResult ToProblem(this Error error)
    {
        if (error.FieldErrors is not null)
        {
            var validation = new HttpValidationProblemDetails(error.FieldErrors.ToDictionary(kv => kv.Key, kv => kv.Value))
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

    public static IResult ToHttpResult(this Result result, Func<IResult> onSuccess) =>
        result.IsSuccess ? onSuccess() : result.Error.ToProblem();

    public static IResult ToHttpResult<T>(this Result<T> result, Func<T, IResult> onSuccess) =>
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
/// Escribe ProblemDetails a través de <see cref="IProblemDetailsService"/> para que todas las respuestas de
/// error compartan la misma personalización (<c>traceId</c>, <c>code</c>).
/// </summary>
public sealed class ProblemResult(ProblemDetails problem) : IResult, IStatusCodeHttpResult
{
    public int? StatusCode => problem.Status;

    public async Task ExecuteAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = problem.Status ?? StatusCodes.Status500InternalServerError;
        var service = httpContext.RequestServices.GetRequiredService<IProblemDetailsService>();
        await service.WriteAsync(new ProblemDetailsContext { HttpContext = httpContext, ProblemDetails = problem });
    }
}

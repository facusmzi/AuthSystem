using Auth.Api.Errors;
using Auth.Application.Common;
using FluentValidation;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Auth.Api.Filters;

/// <summary>
/// Filtro global: ejecuta el <see cref="IValidator{T}"/> registrado para cada argumento de la acción y
/// responde 422 con errores por campo (camelCase) si alguno falla.
/// </summary>
public sealed class ValidationFilter(IServiceProvider services) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var errors = new Dictionary<string, List<string>>();
        foreach (var argument in context.ActionArguments.Values)
        {
            if (argument is null)
            {
                continue;
            }

            var validatorType = typeof(IValidator<>).MakeGenericType(argument.GetType());
            if (services.GetService(validatorType) is not IValidator validator)
            {
                continue;
            }

            var result = await validator.ValidateAsync(new ValidationContext<object>(argument), context.HttpContext.RequestAborted);
            foreach (var failure in result.Errors)
            {
                var key = CamelCase(failure.PropertyName);
                if (!errors.TryGetValue(key, out var list))
                {
                    errors[key] = list = [];
                }

                if (!list.Contains(failure.ErrorMessage))
                {
                    list.Add(failure.ErrorMessage);
                }
            }
        }

        if (errors.Count > 0)
        {
            context.Result = Error.Validation(errors.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray())).ToProblem();
            return;
        }

        await next();
    }

    private static string CamelCase(string name) =>
        string.IsNullOrEmpty(name) ? name : char.ToLowerInvariant(name[0]) + name[1..];
}

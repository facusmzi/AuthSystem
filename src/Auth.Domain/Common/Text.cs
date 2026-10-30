namespace Auth.Domain.Common;

public static class Text
{
    public static string? Truncate(string? value, int maxLength) =>
        value is null ? null : value.Length <= maxLength ? value : value[..maxLength];
}

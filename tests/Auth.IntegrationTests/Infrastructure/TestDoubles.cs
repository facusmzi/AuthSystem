using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Auth.Application.Abstractions;

namespace Auth.IntegrationTests.Infrastructure;

/// <summary>Captura los emails en memoria (síncrono, sin cola) para inspeccionarlos en los tests.</summary>
public sealed partial class InMemoryEmailSender : IEmailSender
{
    private readonly ConcurrentQueue<EmailMessage> _sent = new();

    public IReadOnlyList<EmailMessage> Sent => [.. _sent];

    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        _sent.Enqueue(message);
        return Task.CompletedTask;
    }

    public IReadOnlyList<EmailMessage> To(string email) =>
        Sent.Where(m => string.Equals(m.To, email, StringComparison.OrdinalIgnoreCase)).ToList();

    public EmailMessage LastTo(string email) =>
        To(email).LastOrDefault() ?? throw new InvalidOperationException($"No email was sent to {email}.");

    public (Guid UserId, string Token) LastConfirmationLink(string email)
    {
        var match = ConfirmLink().Match(LastTo(email).TextBody);
        if (!match.Success)
        {
            throw new InvalidOperationException("The last email does not contain a confirmation link.");
        }

        return (Guid.Parse(match.Groups["id"].Value), Uri.UnescapeDataString(match.Groups["token"].Value));
    }

    public string LastResetToken(string email)
    {
        var match = ResetLink().Match(LastTo(email).TextBody);
        if (!match.Success)
        {
            throw new InvalidOperationException("The last email does not contain a reset link.");
        }

        return Uri.UnescapeDataString(match.Groups["token"].Value);
    }

    [GeneratedRegex(@"confirm-email\?userId=(?<id>[0-9a-fA-F-]+)&token=(?<token>[^\s""<&]+)")]
    private static partial Regex ConfirmLink();

    [GeneratedRegex(@"reset-password\?email=[^&\s]+&token=(?<token>[^\s""<&]+)")]
    private static partial Regex ResetLink();
}

/// <summary>HIBP falso: contraseñas filtradas conocidas y modo "no disponible".</summary>
public sealed class FakeBreachChecker : IPasswordBreachChecker
{
    public const string BreachedPassword = "password1234567";

    public bool Unavailable { get; set; }

    public Task<BreachCheckStatus> CheckAsync(string password, CancellationToken cancellationToken)
    {
        if (Unavailable)
        {
            return Task.FromResult(BreachCheckStatus.Unavailable);
        }

        return Task.FromResult(password == BreachedPassword ? BreachCheckStatus.Breached : BreachCheckStatus.NotBreached);
    }
}

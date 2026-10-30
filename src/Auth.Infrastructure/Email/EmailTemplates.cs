using System.Net;
using Auth.Application.Abstractions;
using Auth.Infrastructure.Options;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Email;

/// <summary>Plantillas de email (texto + HTML mínimo). Los valores interpolados en HTML se codifican.</summary>
public sealed class EmailTemplates(IOptions<FrontendOptions> frontend, IOptions<MfaOptions> mfa)
{
    private string Product => mfa.Value.Issuer;
    private string BaseUrl => frontend.Value.BaseUrl.TrimEnd('/');

    public string ConfirmEmailLink(Guid userId, string token) =>
        $"{BaseUrl}/confirm-email?userId={userId}&token={Uri.EscapeDataString(token)}";

    public string ResetPasswordLink(string email, string token) =>
        $"{BaseUrl}/reset-password?email={Uri.EscapeDataString(email)}&token={Uri.EscapeDataString(token)}";

    public EmailMessage ConfirmEmail(string to, Guid userId, string token, int validHours)
    {
        var link = ConfirmEmailLink(userId, token);
        return Build(to, $"Confirm your {Product} account",
            $"Welcome! Confirm your email address by opening this link (valid for {validHours} hours):",
            link,
            "If you did not create an account, you can ignore this email.");
    }

    public EmailMessage RegistrationAttempt(string to) => Build(to, $"Sign-up attempt on {Product}",
        "Someone tried to create an account with this email address, but you already have one.",
        null,
        "If it was you, sign in or reset your password instead. Otherwise, you can ignore this email.");

    public EmailMessage PasswordReset(string to, string token, int validMinutes)
    {
        var link = ResetPasswordLink(to, token);
        return Build(to, $"Reset your {Product} password",
            $"We received a request to reset your password. Open this link to choose a new one (valid for {validMinutes} minutes):",
            link,
            "If you did not request this, you can ignore this email; your password will not change.");
    }

    public EmailMessage PasswordChanged(string to) => Build(to, $"Your {Product} password was changed",
        "The password for your account was just changed and your other sessions were signed out.",
        null,
        "If this was not you, reset your password immediately and contact support.");

    public EmailMessage PasswordResetCompleted(string to) => Build(to, $"Your {Product} password was reset",
        "Your password was reset and all your sessions were signed out.",
        null,
        "If this was not you, contact support immediately.");

    public EmailMessage MfaEnabled(string to) => Build(to, $"Two-factor authentication enabled on {Product}",
        "Two-factor authentication is now enabled for your account. Keep your recovery codes in a safe place.",
        null,
        "If this was not you, reset your password immediately and contact support.");

    public EmailMessage MfaDisabled(string to) => Build(to, $"Two-factor authentication disabled on {Product}",
        "Two-factor authentication was disabled for your account.",
        null,
        "If this was not you, reset your password immediately and contact support.");

    public EmailMessage RecoveryCodeUsed(string to, int remaining) => Build(to, $"A recovery code was used on {Product}",
        $"A recovery code was used to sign in to your account. You have {remaining} recovery codes left.",
        null,
        "If this was not you, reset your password and regenerate your recovery codes immediately.");

    private static EmailMessage Build(string to, string subject, string intro, string? link, string footer)
    {
        var text = link is null ? $"{intro}\n\n{footer}\n" : $"{intro}\n\n{link}\n\n{footer}\n";
        var encodedLink = link is null ? null : WebUtility.HtmlEncode(link);
        var html = $"<!doctype html><html><body style=\"font-family:sans-serif\"><p>{WebUtility.HtmlEncode(intro)}</p>"
            + (encodedLink is null ? string.Empty : $"<p><a href=\"{encodedLink}\">{encodedLink}</a></p>")
            + $"<p style=\"color:#666\">{WebUtility.HtmlEncode(footer)}</p></body></html>";
        return new EmailMessage(to, subject, text, html);
    }
}

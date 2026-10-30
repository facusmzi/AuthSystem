using System.Threading.Channels;
using Auth.Application.Abstractions;
using Auth.Infrastructure.Options;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Auth.Infrastructure.Email;

/// <summary>Transporte real de emails (Logging, Pickup o SMTP).</summary>
public interface IEmailTransport
{
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken);
}

/// <summary>
/// <see cref="IEmailSender"/> que encola y vuelve enseguida: el tiempo de respuesta de los endpoints no
/// depende de si se envió un mail (evita enumerar cuentas por latencia) ni de la latencia del SMTP.
/// </summary>
internal sealed class QueuedEmailSender(EmailQueue queue) : IEmailSender
{
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken) =>
        queue.Writer.WriteAsync(message, cancellationToken).AsTask();
}

internal sealed class EmailQueue
{
    private readonly Channel<EmailMessage> _channel = Channel.CreateBounded<EmailMessage>(new BoundedChannelOptions(1000)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
    });

    public ChannelWriter<EmailMessage> Writer => _channel.Writer;
    public ChannelReader<EmailMessage> Reader => _channel.Reader;
}

internal sealed class EmailDispatcher(EmailQueue queue, IEmailTransport transport, ILogger<EmailDispatcher> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var message in queue.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                await transport.SendAsync(message, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Failed to send email with subject {Subject}", message.Subject);
            }
        }
    }
}

/// <summary>Solo registra destinatario y asunto: el cuerpo contiene tokens y nunca se loguea.</summary>
internal sealed class LoggingEmailTransport(ILogger<LoggingEmailTransport> logger) : IEmailTransport
{
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        logger.LogInformation("Email (not sent, Logging provider) to {To}: {Subject}", message.To, message.Subject);
        return Task.CompletedTask;
    }
}

/// <summary>Desarrollo: guarda cada mail como .eml en un directorio (ignorado por git).</summary>
internal sealed class PickupEmailTransport(IOptions<EmailOptions> options, IHostEnvironment environment, ILogger<PickupEmailTransport> logger) : IEmailTransport
{
    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        var directory = Path.GetFullPath(Path.Combine(environment.ContentRootPath, options.Value.PickupDirectory));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.eml");

        using var mime = MimeMessageFactory.Create(options.Value, message);
        await mime.WriteToAsync(path, cancellationToken);
        logger.LogInformation("Email to {To} written to pickup directory: {Subject}", message.To, message.Subject);
    }
}

internal sealed class SmtpEmailTransport(IOptions<EmailOptions> options, ILogger<SmtpEmailTransport> logger) : IEmailTransport
{
    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        var o = options.Value;
        using var mime = MimeMessageFactory.Create(o, message);
        using var client = new SmtpClient();
        await client.ConnectAsync(o.Smtp.Host, o.Smtp.Port, o.Smtp.UseStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.SslOnConnect, cancellationToken);
        if (!string.IsNullOrEmpty(o.Smtp.User))
        {
            await client.AuthenticateAsync(o.Smtp.User, o.Smtp.Password ?? string.Empty, cancellationToken);
        }

        await client.SendAsync(mime, cancellationToken);
        await client.DisconnectAsync(quit: true, cancellationToken);
        logger.LogInformation("Email sent to {To}: {Subject}", message.To, message.Subject);
    }
}

internal static class MimeMessageFactory
{
    public static MimeMessage Create(EmailOptions options, EmailMessage message)
    {
        var mime = new MimeMessage();
        mime.From.Add(new MailboxAddress(options.FromName, options.From));
        mime.To.Add(MailboxAddress.Parse(message.To));
        mime.Subject = message.Subject;
        mime.Body = new BodyBuilder { TextBody = message.TextBody, HtmlBody = message.HtmlBody }.ToMessageBody();
        return mime;
    }
}

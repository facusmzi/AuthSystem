using Auth.Infrastructure.Options;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Security;

/// <summary>
/// Limita los hashes Argon2 simultáneos: cada uno reserva <c>MemoryKiB</c> de RAM, así que una ráfaga de
/// logins podría agotar la memoria del proceso. Singleton.
/// </summary>
public sealed class HashingConcurrencyLimiter(IOptions<PasswordHashingOptions> options) : IDisposable
{
    private readonly SemaphoreSlim _semaphore = new(options.Value.MaxConcurrentHashes, options.Value.MaxConcurrentHashes);

    public T Run<T>(Func<T> work)
    {
        _semaphore.Wait();
        try
        {
            return work();
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public void Dispose() => _semaphore.Dispose();
}

using Microsoft.Extensions.Caching.Memory;

namespace Auth.Infrastructure.Caching;

/// <summary>
/// Envoltorio de <see cref="IMemoryCache"/> cuya expiración lógica usa <see cref="TimeProvider"/>
/// (testeable con <c>FakeTimeProvider</c>). La expiración física del cache es solo para liberar memoria.
/// Una sola instancia del servicio: ver DECISIONS (multi-instancia requiere cache distribuida).
/// </summary>
public sealed class TimedCache(IMemoryCache cache, TimeProvider time)
{
    private static readonly TimeSpan PhysicalSlack = TimeSpan.FromMinutes(1);
    private readonly Lock _gate = new();

    public void Set<T>(string key, T value, TimeSpan ttl)
    {
        var expiresAt = time.GetUtcNow() + ttl;
        cache.Set(key, new Entry<T>(value, expiresAt), ttl + PhysicalSlack);
    }

    public bool TryGet<T>(string key, out T value)
    {
        if (cache.TryGetValue(key, out var raw) && raw is Entry<T> entry && entry.ExpiresAt > time.GetUtcNow())
        {
            value = entry.Value;
            return true;
        }

        value = default!;
        return false;
    }

    /// <summary>Agrega la clave solo si no existe (o expiró). Atómico dentro del proceso.</summary>
    public bool TryAdd(string key, TimeSpan ttl)
    {
        lock (_gate)
        {
            if (TryGet<bool>(key, out _))
            {
                return false;
            }

            Set(key, true, ttl);
            return true;
        }
    }

    public void Remove(string key) => cache.Remove(key);

    private sealed record Entry<T>(T Value, DateTimeOffset ExpiresAt);
}

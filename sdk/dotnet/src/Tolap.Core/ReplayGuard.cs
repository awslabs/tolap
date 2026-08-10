using System.Collections.Concurrent;

namespace Tolap.Core;

/// <summary>
/// Records which security-context identifiers have been seen (spec section 13).
/// </summary>
/// <remarks>
/// <para>A signed context is otherwise a bearer credential replayable until it expires.
/// Single-use enforcement needs state the SDK deliberately does not assume, so this is
/// the seam: implement it over whatever store the deployment already has (Redis,
/// DynamoDB, a database table) and pass it to
/// <see cref="SecurityContextSigner.Deserialize(string, string, IReplayGuard?)"/>.</para>
///
/// <para>Implementations MUST be safe to call concurrently and MUST be atomic —
/// check-then-register as two separate steps lets two concurrent replays of the same
/// context both succeed, which defeats the guard under exactly the load an attacker
/// would generate.</para>
/// </remarks>
public interface IReplayGuard
{
    /// <summary>
    /// Atomically records <paramref name="jti"/>; returns false if it was already present.
    /// </summary>
    /// <param name="jti">The context identifier to record.</param>
    /// <param name="expiresAt">
    /// The context's expiry, supplied so implementations can expire their own entries: an
    /// id can be forgotten once the context carrying it would be rejected on expiry anyway.
    /// </param>
    bool CheckAndRegister(string jti, DateTimeOffset? expiresAt);
}

/// <summary>
/// Process-local <see cref="IReplayGuard"/>, suitable for a single-process tool.
/// </summary>
/// <remarks>
/// <para>Not shared across processes or hosts: two instances behind a load balancer each
/// keep their own set, so a context replayed against a <b>different</b> instance is not
/// detected. Use a shared store for anything multi-process — this class exists so that
/// single-process deployments and tests have a working guard rather than none.</para>
///
/// <para>Entries are dropped once their context has expired, so memory is bounded by the
/// number of contexts issued within one TTL rather than growing without limit.</para>
/// </remarks>
public sealed class InMemoryReplayGuard : IReplayGuard
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public bool CheckAndRegister(string jti, DateTimeOffset? expiresAt)
    {
        var now = DateTimeOffset.UtcNow;

        // Opportunistic sweep: an id is only worth remembering while a context bearing
        // it could still pass the expiry check.
        foreach (var entry in _seen)
        {
            if (entry.Value <= now)
                _seen.TryRemove(entry.Key, out _);
        }

        // Fall back to a bounded retention only when expiry is absent, so a missing value
        // cannot pin an entry in memory indefinitely. An already-past expiry is stored as
        // given rather than clamped forward: the entry becomes immediately sweepable,
        // which is harmless because a context carrying that expiry would fail the expiry
        // check anyway. Clamping here would also diverge from the Python and TypeScript
        // guards, and cross-language parity is the property this SDK holds to.
        var expiry = expiresAt ?? now.AddHours(1);

        // TryAdd is the atomic step: exactly one caller can win for a given jti, so
        // concurrent replays cannot both succeed.
        return _seen.TryAdd(jti, expiry);
    }
}

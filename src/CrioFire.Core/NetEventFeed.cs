namespace CrioFire.Core;

/// <summary>
/// The connections Windows reports as they happen, held for the service's next round and, for
/// a while, for the app's alerts.
///
/// Why not ask Windows for "the events since" every round: every FwpmNetEventEnum call leaks
/// the events it returns. Windows frees only the array of pointers, not what they point to
/// (a defect in fwpuclnt.dll, in every version of the call). On a busy PC that was about a
/// megabyte every two seconds, for as long as the service ran. Events delivered through a
/// subscription are Windows' own to free, and it does.
///
/// Everything here is bounded: when nobody collects, the oldest are dropped.
/// </summary>
public sealed class NetEventFeed
{
    /// <summary>The most events kept between two rounds of the service (one round is two seconds).</summary>
    public const int MaxWaiting = 20_000;

    /// <summary>The most blocked connections kept for questions about the last minutes.</summary>
    public const int MaxRecent = 10_000;

    /// <summary>How long a blocked connection can be asked for.</summary>
    public static readonly TimeSpan RecentFor = TimeSpan.FromMinutes(60);

    private readonly Lock _gate = new();
    private readonly Queue<BlockedConnection> _blocked = new();
    private readonly Queue<AllowedConnection> _allowed = new();
    private readonly Queue<BlockedConnection> _recent = new();
    private long _received;

    /// <summary>True while Windows delivers events here. False: the service asks for them each round instead (the old way).</summary>
    public bool Active { get; set; }

    /// <summary>False while allowed connections are not recorded: they are not kept either.</summary>
    public bool KeepAllowed { get; set; } = true;

    /// <summary>Events received since the service started.</summary>
    public long Received
    {
        get
        {
            lock (_gate)
            {
                return _received;
            }
        }
    }

    public void Add(BlockedConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        lock (_gate)
        {
            _received++;
            _blocked.Enqueue(connection);
            while (_blocked.Count > MaxWaiting)
            {
                _blocked.Dequeue();
            }

            _recent.Enqueue(connection);
            var oldest = connection.TimeUtc - RecentFor;
            while (_recent.Count > MaxRecent || (_recent.Count > 0 && _recent.Peek().TimeUtc < oldest))
            {
                _recent.Dequeue();
            }
        }
    }

    public void Add(AllowedConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        lock (_gate)
        {
            _received++;
            if (!KeepAllowed)
            {
                return;
            }

            _allowed.Enqueue(connection);
            while (_allowed.Count > MaxWaiting)
            {
                _allowed.Dequeue();
            }
        }
    }

    /// <summary>The blocked connections since the last call, oldest first.</summary>
    public List<BlockedConnection> TakeBlocked()
    {
        lock (_gate)
        {
            var taken = new List<BlockedConnection>(_blocked);
            _blocked.Clear();
            return taken;
        }
    }

    /// <summary>The allowed connections since the last call, oldest first.</summary>
    public List<AllowedConnection> TakeAllowed()
    {
        lock (_gate)
        {
            var taken = new List<AllowedConnection>(_allowed);
            _allowed.Clear();
            return taken;
        }
    }

    /// <summary>Blocked connections at or after <paramref name="fromUtc"/> that are still kept, oldest first.</summary>
    public List<BlockedConnection> Recent(DateTime fromUtc)
    {
        lock (_gate)
        {
            return [.. _recent.Where(e => e.TimeUtc >= fromUtc)];
        }
    }
}

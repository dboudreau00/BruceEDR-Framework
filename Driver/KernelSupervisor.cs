namespace BruceEDR.Driver;

/// <summary>How a connect to the driver ended.</summary>
internal enum KernelConnect
{
    Connected,
    /// <summary>No port: the driver is not loaded.</summary>
    NotLoaded,
    /// <summary>Anything else: refused, another protocol, a failed call.</summary>
    Failed
}

/// <summary>The part of <see cref="MinifilterClient"/> the supervisor drives, so its decisions run without a driver.</summary>
internal interface IKernelPort : IDisposable
{
    KernelConnect Connect();
}

/// <summary>The reconnect schedule: 5 s, doubling, never more than 5 min.</summary>
internal static class KernelBackoff
{
    internal static readonly TimeSpan First = TimeSpan.FromSeconds(5);
    internal static readonly TimeSpan Longest = TimeSpan.FromMinutes(5);

    /// <summary>The wait before attempt <paramref name="attempt"/> (0 is the first after a loss).</summary>
    internal static TimeSpan Delay(int attempt)
    {
        if (attempt < 0) attempt = 0;
        double seconds = First.TotalSeconds * Math.Pow(2, Math.Min(attempt, 16));
        return TimeSpan.FromSeconds(Math.Min(seconds, Longest.TotalSeconds));
    }
}

/// <summary>
/// Keeps the agent's link to the driver alive. A driver that is unloaded, detached or loses its
/// port leaves the agent without refusal reports or control, and nothing in the agent said so:
/// this warns once, plainly, and reconnects with <see cref="KernelBackoff"/> until it succeeds or
/// the agent shuts down. A reconnect runs <c>arm</c> again, which is where the caller restarts the
/// reader and re-pushes the policy and the blocking state, because a reloaded driver starts empty
/// and with blocking off.
///
/// Port, delay and logging are injected, so the decisions (when to warn, the schedule, a re-push on
/// reconnect, a stop on dispose) are tested without a driver or a clock.
/// </summary>
internal sealed class KernelSupervisor<TPort> : IDisposable where TPort : class, IKernelPort
{
    private readonly Func<TPort> _create;
    private readonly Func<TPort, Action<string>, bool> _arm;
    private readonly Action<string> _warn;
    private readonly Action<string> _info;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly CancellationTokenSource _cancel = new();
    private readonly object _gate = new();
    private TPort? _current;
    private Task? _loop;
    private bool _looping;      // a reconnect loop owns the link until it arms a port
    private bool _disposed;

    /// <param name="create">A fresh, unconnected port.</param>
    /// <param name="arm">
    /// Called on a connected port with a callback for the reader to report its end. Starts the
    /// reader, pushes the policy, sets blocking; false when any of that was refused.
    /// </param>
    public KernelSupervisor(Func<TPort> create, Func<TPort, Action<string>, bool> arm,
        Action<string> warn, Action<string> info, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _create = create;
        _arm = arm;
        _warn = warn;
        _info = info;
        _delay = delay ?? Task.Delay;
    }

    /// <summary>The armed port, or null while the link is lost or was never made.</summary>
    public TPort? Current
    {
        get { lock (_gate) return _disposed ? null : _current; }
    }

    /// <summary>The reconnect loop while one runs; for tests to wait on.</summary>
    internal Task? Loop
    {
        get { lock (_gate) return _loop; }
    }

    /// <summary>
    /// The first connection. False when the driver is not there or refuses this agent, which is
    /// ordinary (no driver installed) and starts no loop. A driver that connects but cannot be
    /// armed is treated as lost.
    /// </summary>
    public bool Start()
    {
        var port = _create();
        if (port.Connect() != KernelConnect.Connected) { port.Dispose(); return false; }
        lock (_gate)
        {
            if (_disposed) { port.Dispose(); return false; }
            _current = port;
        }
        bool armed = false;
        try { armed = _arm(port, reason => Lost(port, reason)); }
        catch (Exception) { }
        if (!armed) Lost(port, "the driver was connected but could not be set up");
        return true;
    }

    // The reader of an armed port ended, or arming it failed.
    private void Lost(TPort port, string reason)
    {
        lock (_gate)
        {
            if (_disposed || !ReferenceEquals(_current, port)) return;
            _current = null;
        }
        _warn("kernel enforcement is OFF: the connection to the BruceFilter driver was lost (" + reason + "). " +
              "If the driver was unloaded or detached nothing guards the credential stores now; if only the port closed, " +
              "the driver keeps its last policy but its refusals are no longer reported and it cannot be updated. " +
              $"The agent will reconnect, trying again every {Format(KernelBackoff.First)} up to {Format(KernelBackoff.Longest)}.");
        lock (_gate)
        {
            if (_disposed || _looping) return;
            _looping = true;
            _loop = Task.Run(() => Reconnect(port, _cancel.Token));
        }
    }

    private async Task Reconnect(TPort lost, CancellationToken stop)
    {
        try { lost.Dispose(); } catch (Exception) { }   // the driver admits one client: free the port first
        bool warnedNotLoaded = false;
        int attempt = 0;
        var started = DateTime.UtcNow;
        while (!stop.IsCancellationRequested)
        {
            try { await _delay(KernelBackoff.Delay(attempt), stop).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            attempt++;

            TPort port = _create();
            KernelConnect result;
            try { result = port.Connect(); }
            catch (Exception) { result = KernelConnect.Failed; }
            if (result != KernelConnect.Connected)
            {
                port.Dispose();
                if (result == KernelConnect.NotLoaded && !warnedNotLoaded)
                {
                    warnedNotLoaded = true;
                    _warn("kernel enforcement is OFF: the BruceFilter driver is not loaded. Nothing guards the credential stores " +
                          "until it is loaded again (fltmc load BruceFilter); the agent keeps looking for it.");
                }
                continue;
            }

            // Current is set before arming so a reader that stops at once is seen as a loss.
            lock (_gate)
            {
                if (_disposed) { port.Dispose(); return; }
                _current = port;
            }
            bool armed = false;
            try { armed = _arm(port, reason => Lost(port, reason)); }
            catch (Exception) { }

            bool keep;
            lock (_gate)
            {
                if (!armed && ReferenceEquals(_current, port)) _current = null;
                keep = armed && ReferenceEquals(_current, port) && !_disposed;
                if (keep) _looping = false;   // a loss from here on starts a new loop
            }
            if (!keep)
            {
                port.Dispose();
                continue;
            }
            _info($"kernel enforcement RESTORED: reconnected to the BruceFilter driver after {Format(DateTime.UtcNow - started)} " +
                  $"and {attempt} attempt(s); the policy and the blocking state were pushed again");
            return;
        }
    }

    private static string Format(TimeSpan t) =>
        t.TotalMinutes >= 1 && t.TotalSeconds % 60 == 0 ? $"{(int)t.TotalMinutes} min" : $"{(int)t.TotalSeconds} s";

    public void Dispose()
    {
        TPort? port;
        Task? loop;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            port = _current;
            _current = null;
            loop = _loop;
        }
        try { _cancel.Cancel(); } catch (Exception) { }
        try { port?.Dispose(); } catch (Exception) { }
        try { loop?.Wait(TimeSpan.FromSeconds(10)); } catch (Exception) { }
        if (loop is null || loop.IsCompleted) _cancel.Dispose();
    }
}

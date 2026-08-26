namespace BruceEDR.Core;

/// <summary>
/// Immutable snapshot of one process as the tree knows it. Handed out by every query so
/// a caller can hold on to it without observing later mutation of the tree.
/// </summary>
public sealed record ProcessNode
{
    public required int Pid { get; init; }

    /// <summary>Parent pid as the monitor reported it. May be 0, unknown, stale or hostile.</summary>
    public required int ParentPid { get; init; }

    /// <summary>Image file name, e.g. <c>powershell.exe</c>. Derived from the path when not supplied.</summary>
    public required string Name { get; init; }

    public required string ImagePath { get; init; }

    public required string CommandLine { get; init; }

    public required DateTime StartUtc { get; init; }

    /// <summary>Null while the process is believed to be alive.</summary>
    public DateTime? ExitUtc { get; init; }

    /// <summary>
    /// Derived from <see cref="ExitUtc"/> rather than stored separately, so the two can
    /// never disagree — a node that claims to be exited with no exit time would break the
    /// retention arithmetic in <see cref="ProcessTree.Prune"/>.
    /// </summary>
    public bool Exited => ExitUtc.HasValue;
}

/// <summary>
/// Parent/child lineage for live and recently-exited processes, so an alert can show
/// <c>winword.exe -&gt; cmd.exe -&gt; powershell.exe</c> and a rule can match on an ancestor
/// rather than only on the process in front of it.
///
/// THREADING: not thread-safe, by deliberate design. Like <c>DetectionEngine</c>'s profile
/// store, this is owned by the single detection thread; adding locks would buy nothing and
/// cost on the hottest path in the sensor. Callers on other threads must go through the
/// owner thread or work from copies.
///
/// WHAT LINEAGE CANNOT TELL YOU. Parentage is a claim made by whichever monitor produced
/// the event, and an attacker can control it. <c>PPID spoofing</c> via
/// <c>PROC_THREAD_ATTRIBUTE_PARENT_PROCESS</c> lets a process choose any parent it can open,
/// so a real <c>winword.exe -&gt; powershell.exe</c> chain can be made to read
/// <c>explorer.exe -&gt; powershell.exe</c>. Process hollowing keeps a benign name and path on
/// a node whose contents are anything at all. And an EDR that starts mid-boot never sees
/// the start events for processes that were already running, so their ancestry is simply
/// absent, not false. Lineage is corroborating context, never proof.
/// </summary>
public sealed class ProcessTree
{
    private readonly IClock _clock;
    private readonly int _maxNodes;
    private readonly Dictionary<int, Entry> _nodes = new();
    private long _seq;

    /// <param name="clock">Time source. Used by <see cref="Prune"/>; all other timing is caller-supplied.</param>
    /// <param name="maxNodes">
    /// Hard ceiling on retained nodes. A sensor that never forgets is a memory leak with a
    /// security label on it: process churn on a build server is thousands per minute.
    /// Floored at 4 so tests can exercise eviction without allocating a realistic tree.
    /// </param>
    public ProcessTree(IClock clock, int maxNodes = 8192)
    {
        _clock = clock;
        _maxNodes = Math.Max(4, maxNodes);
    }

    /// <summary>Number of nodes currently retained, live and exited.</summary>
    public int Count => _nodes.Count;

    /// <summary>
    /// Record a process start.
    ///
    /// PID REUSE is the important case. Windows recycles pids aggressively, and a second
    /// start for a pid that is already present means the old process is gone. The old node
    /// is therefore replaced ENTIRELY — new parent, new children list, new start time — and
    /// detached from its previous parent's child list. It must not inherit the previous
    /// occupant's ancestry, because that is a fail-open hole: a benign chain would launder a
    /// malicious process, or a stale malicious chain would incriminate an innocent one.
    ///
    /// Non-positive pids are dropped: pid 0 is the system idle process and negative pids do
    /// not exist, so either indicates a monitor that failed to attribute the event.
    /// </summary>
    public void OnStart(int pid, int parentPid, string name, string imagePath, string commandLine, DateTime whenUtc)
    {
        if (pid <= 0) return;

        var startUtc = ToUtc(whenUtc);
        string path = imagePath ?? "";
        string resolvedName = string.IsNullOrWhiteSpace(name)
            ? SafeFileName(path)
            : name.Trim();

        // Replace, never merge. See the PID-reuse note above.
        if (_nodes.TryGetValue(pid, out var existing))
        {
            DetachFromParent(pid, existing.Node.ParentPid);
            _nodes.Remove(pid);
        }

        while (_nodes.Count >= _maxNodes) EvictOne();

        var entry = new Entry
        {
            Node = new ProcessNode
            {
                Pid = pid,
                ParentPid = parentPid,
                Name = resolvedName,
                ImagePath = path,
                CommandLine = commandLine ?? "",
                StartUtc = startUtc,
                ExitUtc = null
            },
            Seq = _seq++
        };
        _nodes[pid] = entry;

        // Attach to the parent only when the parent plausibly predates the child. A parent
        // whose recorded start is LATER than the child's is a recycled pid, not the real
        // parent, and linking them would fabricate a lineage. Orphans (parent not yet known)
        // are deliberately NOT adopted if the parent starts later: retroactive adoption is
        // the same pid-reuse hole in reverse. An orphan simply has no recorded child link;
        // Ancestors still walks by ParentPid, so a genuinely out-of-order pair still resolves
        // as long as the timestamps are consistent.
        if (parentPid > 0 && parentPid != pid &&
            _nodes.TryGetValue(parentPid, out var parent) &&
            parent.Node.StartUtc <= startUtc)
        {
            if (!parent.Children.Contains(pid)) parent.Children.Add(pid);
        }
    }

    /// <summary>
    /// Record a process exit. Exited nodes are retained (they are the interesting half of a
    /// post-mortem lineage) until <see cref="Prune"/> or eviction removes them.
    ///
    /// An exit for a pid that was never started is dropped rather than synthesised: a node
    /// with no name, no path and no start time is worse than no node, and it would occupy a
    /// slot that a real process needs.
    ///
    /// A duplicate exit keeps the FIRST timestamp. ETW can deliver the same stop event twice
    /// across providers, and letting the later copy win would silently extend retention.
    /// </summary>
    public void OnExit(int pid, DateTime whenUtc)
    {
        if (pid <= 0) return;
        if (!_nodes.TryGetValue(pid, out var entry)) return;
        if (entry.Node.ExitUtc.HasValue) return;
        entry.Node = entry.Node with { ExitUtc = ToUtc(whenUtc) };
    }

    /// <summary>The node for a pid, or null when it is unknown or has been evicted.</summary>
    public ProcessNode? Get(int pid) => _nodes.TryGetValue(pid, out var e) ? e.Node : null;

    /// <summary>
    /// Ancestry, nearest parent first. Returns an empty list — never null, never an
    /// exception — for an unknown pid, a pid with no parent, or a pid whose parent has
    /// already been evicted.
    ///
    /// TERMINATION is guaranteed three ways, because a parent chain is attacker-influenced
    /// data and a hang in the detection thread is a denial of service on the whole sensor:
    ///   1. a visited set, so a-parents-b / b-parents-a and self-parenting both stop;
    ///   2. <paramref name="maxDepth"/>, so even a long legitimate chain is bounded;
    ///   3. the start-time guard, which stops the walk at a recycled pid.
    /// </summary>
    public IReadOnlyList<ProcessNode> Ancestors(int pid, int maxDepth = 16)
    {
        if (!_nodes.TryGetValue(pid, out var entry)) return Array.Empty<ProcessNode>();

        int limit = ClampDepth(maxDepth);
        var result = new List<ProcessNode>(Math.Min(limit, 8));
        var visited = new HashSet<int> { pid };
        var current = entry.Node;

        while (result.Count < limit)
        {
            int parentPid = current.ParentPid;
            if (parentPid <= 0 || parentPid == current.Pid) break;
            if (!visited.Add(parentPid)) break;                             // cycle
            if (!_nodes.TryGetValue(parentPid, out var parent)) break;      // unknown or evicted
            if (parent.Node.StartUtc > current.StartUtc) break;             // recycled pid, not the real parent

            result.Add(parent.Node);
            current = parent.Node;
        }
        return result;
    }

    /// <summary>
    /// Direct children only, in the order they were attached. Empty for an unknown pid.
    /// Entries whose <c>ParentPid</c> no longer points back at <paramref name="pid"/> are
    /// filtered out defensively, so a missed detach can never surface a bogus child.
    /// </summary>
    public IReadOnlyList<ProcessNode> Children(int pid)
    {
        if (!_nodes.TryGetValue(pid, out var entry) || entry.Children.Count == 0)
            return Array.Empty<ProcessNode>();

        var list = new List<ProcessNode>(entry.Children.Count);
        foreach (int childPid in entry.Children)
        {
            if (!_nodes.TryGetValue(childPid, out var child)) continue;
            if (child.Node.ParentPid != pid) continue;
            if (child.Node.StartUtc < entry.Node.StartUtc) continue;
            list.Add(child.Node);
        }
        return list;
    }

    /// <summary>
    /// All descendants in breadth-first order, so the closest generation is reported first
    /// — that is the order an analyst reads a spawn tree in. Cycle-safe and depth-limited
    /// for the same reasons as <see cref="Ancestors"/>.
    /// </summary>
    public IReadOnlyList<ProcessNode> Descendants(int pid, int maxDepth = 16)
    {
        if (!_nodes.TryGetValue(pid, out _)) return Array.Empty<ProcessNode>();

        int limit = ClampDepth(maxDepth);
        var result = new List<ProcessNode>();
        var visited = new HashSet<int> { pid };
        var frontier = new List<int> { pid };

        for (int depth = 0; depth < limit && frontier.Count > 0; depth++)
        {
            var next = new List<int>();
            foreach (int parentPid in frontier)
            {
                foreach (var child in Children(parentPid))
                {
                    if (!visited.Add(child.Pid)) continue;   // cycle or diamond
                    result.Add(child);
                    next.Add(child.Pid);
                    // Cannot exceed the node count: visited guarantees each pid once.
                }
            }
            frontier = next;
        }
        return result;
    }

    /// <summary>
    /// Renders the chain root-most first and ending with the process itself, e.g.
    /// <c>winword.exe -&gt; cmd.exe -&gt; powershell.exe</c>. Returns an empty string for an
    /// unknown pid. Nodes with no recorded name render as <c>pid:1234</c> so a gap in
    /// telemetry is visible in the alert instead of collapsing into an empty segment.
    /// </summary>
    public string Lineage(int pid)
    {
        if (!_nodes.TryGetValue(pid, out var entry)) return "";

        var ancestors = Ancestors(pid);
        var parts = new List<string>(ancestors.Count + 1);
        for (int i = ancestors.Count - 1; i >= 0; i--) parts.Add(Label(ancestors[i]));
        parts.Add(Label(entry.Node));
        return string.Join(" -> ", parts);
    }

    /// <summary>
    /// Drop exited nodes whose exit is older than <paramref name="retainExitedFor"/>,
    /// measured against the injected clock.
    ///
    /// Live nodes are never time-pruned however old they are: a service that started at boot
    /// is exactly the ancestor an alert most needs to name, and dropping it would silently
    /// truncate every lineage beneath it. Live nodes are bounded only by <c>maxNodes</c>.
    /// </summary>
    public void Prune(TimeSpan retainExitedFor)
    {
        if (retainExitedFor < TimeSpan.Zero) retainExitedFor = TimeSpan.Zero;
        var cutoff = _clock.UtcNow - retainExitedFor;

        List<int>? dead = null;
        foreach (var (pid, entry) in _nodes)
        {
            var exit = entry.Node.ExitUtc;
            if (exit.HasValue && exit.Value < cutoff) (dead ??= new List<int>()).Add(pid);
        }
        if (dead is null) return;

        foreach (int pid in dead) Remove(pid);
    }

    // ---------------------------------------------------------------- internals

    /// <summary>
    /// Free one slot. Exited nodes go first because they can never gain new children or new
    /// relevance, and only then the oldest node overall.
    ///
    /// "Oldest" means least recently ADDED, not lowest StartUtc. A monitor that backfills the
    /// running process list delivers nodes with old start times in arbitrary order, and using
    /// StartUtc would make eviction depend on that order; insertion sequence is monotonic and
    /// therefore deterministic. This is an O(n) scan per eviction, which is chosen for
    /// clarity: it only runs once the tree is full, and n is bounded by maxNodes.
    /// </summary>
    private void EvictOne()
    {
        int victim = 0;
        long bestSeq = long.MaxValue;
        bool foundExited = false;

        foreach (var (pid, entry) in _nodes)
        {
            bool exited = entry.Node.ExitUtc.HasValue;
            if (foundExited && !exited) continue;

            if (exited && !foundExited)
            {
                foundExited = true;
                victim = pid;
                bestSeq = entry.Seq;
                continue;
            }
            if (entry.Seq < bestSeq)
            {
                victim = pid;
                bestSeq = entry.Seq;
            }
        }

        if (victim != 0) Remove(victim);
        else _nodes.Clear();   // unreachable while Count > 0; a hard floor against a stuck loop
    }

    private void Remove(int pid)
    {
        if (!_nodes.TryGetValue(pid, out var entry)) return;
        DetachFromParent(pid, entry.Node.ParentPid);
        _nodes.Remove(pid);
        // The removed node's own children are left in place. They become roots whose
        // ancestry walk simply stops at the missing pid, which is the honest outcome:
        // we no longer know their lineage, and inventing one would be worse.
    }

    private void DetachFromParent(int pid, int parentPid)
    {
        if (parentPid <= 0 || parentPid == pid) return;
        if (_nodes.TryGetValue(parentPid, out var parent)) parent.Children.Remove(pid);
    }

    private static int ClampDepth(int maxDepth) => Math.Clamp(maxDepth, 1, 4096);

    private static string Label(ProcessNode n)
        => string.IsNullOrEmpty(n.Name) ? "pid:" + n.Pid.ToString() : n.Name;

    /// <summary>
    /// Coerce to UTC. Unspecified is treated as already-UTC because every BruceEDR
    /// monitor emits UTC; a Local value is converted so a caller passing wall-clock time
    /// does not shift the whole tree by the machine's offset and break retention.
    /// </summary>
    private static DateTime ToUtc(DateTime when) => when.Kind switch
    {
        DateTimeKind.Utc => when,
        DateTimeKind.Local => when.ToUniversalTime(),
        _ => DateTime.SpecifyKind(when, DateTimeKind.Utc)
    };

    /// <summary>
    /// File name from a path without throwing on the malformed paths that real telemetry
    /// carries (device paths, truncated strings, embedded nulls).
    /// </summary>
    private static string SafeFileName(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        try
        {
            string f = Path.GetFileName(path);
            return string.IsNullOrEmpty(f) ? path : f;
        }
        catch (ArgumentException)
        {
            return path;
        }
    }

    /// <summary>
    /// Mutable holder. The public <see cref="ProcessNode"/> stays an immutable record while
    /// the child list and the insertion sequence, which are tree bookkeeping rather than
    /// process facts, live here and are never handed out.
    /// </summary>
    private sealed class Entry
    {
        public required ProcessNode Node { get; set; }
        public required long Seq { get; init; }
        public List<int> Children { get; } = new();
    }
}

using System.Diagnostics;
using System.Globalization;
using System.Net;
using BruceEDR.Core;

namespace BruceEDR.Response;

/// <summary>Current isolation posture as this agent believes it to be.</summary>
public sealed record IsolationState
{
    /// <summary>
    /// True when THIS agent instance applied isolation and has not released it.
    /// It is a belief, not ground truth: the firewall policy lives in Windows and
    /// survives an agent restart, so a fresh process reports Active=false even on a
    /// host that is still isolated. <see cref="NetworkIsolation.Release"/> is therefore
    /// callable at any time and does not require Active to be true.
    /// </summary>
    public bool Active { get; init; }
    public DateTime? AppliedUtc { get; init; }
    /// <summary>The allowlist that was in force when isolation was applied.</summary>
    public string[] AllowedRemoteAddresses { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Full-host network containment via the Windows Firewall.
///
/// READ THIS BEFORE CHANGING ANYTHING HERE. Isolation is the single most dangerous
/// action in the product. Applied to a production server it severs RDP, WinRM, SSH,
/// backup agents, monitoring and the EDR's own SIEM uplink. If the allowlist is wrong
/// or the allow rules fail to install, the administrator is locked out of the box and
/// the only remedy is console/iLO/hypervisor access. Three invariants exist to prevent
/// that and must be preserved:
///
///  1. ALLOW RULES ARE INSTALLED BEFORE ANYTHING IS BLOCKED. The command list from
///     <see cref="BuildIsolateCommands"/> is ordered, and <see cref="Isolate"/> aborts
///     on the first failure, so a failed allow rule means the block never happens.
///  2. AN EMPTY ALLOWLIST IS REFUSED unless the caller explicitly opts into a total
///     blackout via the <c>confirmTotalBlackout</c> overload. The bare
///     <see cref="Isolate(IReadOnlyList{string})"/> overload always refuses.
///  3. EVERY ADDRESS IS VALIDATED before use, and every netsh invocation goes through
///     ProcessStartInfo.ArgumentList — never a concatenated command string — so a
///     hostile value cannot smuggle in extra netsh arguments.
///
/// HOW IT WORKS, AND WHAT IT CANNOT DO. Windows Firewall evaluates explicit BLOCK
/// rules ahead of explicit ALLOW rules, so a blanket "block all" rule would override
/// the allowlist and cause exactly the lockout described above. Isolation therefore
/// changes the DEFAULT policy to block inbound and outbound, and relies on explicit
/// allow rules beating the default. The honest consequence: pre-existing explicit
/// allow rules survive isolation. Anything that already had an allow rule — including
/// one an attacker installed earlier in the intrusion — keeps its connectivity. This
/// materially reduces the blast radius of an intrusion; it is not a hermetic seal, and
/// it should not be described as one to an operator.
///
/// Also note: isolation needs administrator rights, it does not affect loopback, and
/// it does not tear down connections that are already established (Windows Firewall is
/// stateful and existing flows may persist until they idle out).
/// </summary>
public sealed class NetworkIsolation
{
    /// <summary>Every rule this class creates starts with this, so cleanup is unambiguous.</summary>
    public const string RuleNamePrefix = "BruceEDR Isolation";

    internal const string AllowOutRuleName = RuleNamePrefix + " Allow Out";
    internal const string AllowInRuleName = RuleNamePrefix + " Allow In";

    /// <summary>
    /// netsh accepts a comma-separated remoteip list, so the entire allowlist becomes
    /// one rule per direction. That keeps <see cref="Release"/> able to delete by exact
    /// name (netsh cannot delete by wildcard) instead of guessing what to clean up.
    /// The cap keeps the argument well clear of the command-line length limit.
    /// </summary>
    public const int MaxAllowlistEntries = 64;

    private const int NetshTimeoutMs = 15000;

    /// <summary>netsh keywords that are legal in a remoteip list.</summary>
    private static readonly string[] AddressKeywords =
    {
        "LocalSubnet", "DNS", "DHCP", "WINS", "DefaultGateway"
    };

    private readonly object _gate = new();
    private readonly Logger _log;
    private readonly IClock _clock;
    private IsolationState _state = new();

    public NetworkIsolation(Logger log, IClock? clock = null)
    {
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _clock = clock ?? SystemClock.Instance;
    }

    /// <summary>What this agent last did. See <see cref="IsolationState.Active"/> for the caveat.</summary>
    public IsolationState State
    {
        get { lock (_gate) return _state; }
    }

    /// <summary>
    /// Isolates the host, permitting traffic only to <paramref name="allowedRemoteAddresses"/>.
    /// Refuses an empty allowlist — see the type remarks for why.
    /// </summary>
    public ActionResult Isolate(IReadOnlyList<string> allowedRemoteAddresses)
        => Isolate(allowedRemoteAddresses, confirmTotalBlackout: false);

    /// <summary>
    /// Isolates the host.
    ///
    /// <paramref name="confirmTotalBlackout"/> is the only way to isolate with an empty
    /// allowlist. It is a separate, explicitly named parameter rather than a config flag
    /// so that "cut this machine off from absolutely everything, including my own
    /// session" is a decision someone had to write down at the call site.
    /// </summary>
    public ActionResult Isolate(IReadOnlyList<string> allowedRemoteAddresses, bool confirmTotalBlackout)
    {
        var allowed = Normalize(allowedRemoteAddresses);

        if (allowed.Count == 0 && !confirmTotalBlackout)
            return ActionResult.Fail(
                "refusing to isolate with an empty allowlist: this would sever every remote session, " +
                "including the operator's. Supply at least one management address, or call the " +
                "confirmTotalBlackout overload if a complete blackout is genuinely intended.");

        if (allowed.Count > MaxAllowlistEntries)
            return ActionResult.Fail(
                $"allowlist has {allowed.Count} entries, above the {MaxAllowlistEntries} supported");

        var invalid = allowed.Where(a => !IsValidRemoteAddress(a)).ToArray();
        if (invalid.Length > 0)
            return ActionResult.Fail(
                "refusing to isolate: allowlist contains entries that are not an IP address, CIDR, " +
                "address range or netsh keyword: " + string.Join(", ", invalid.Select(Quote)));

        var commands = BuildIsolateCommands(allowed);

        // Ordered, fail-fast. Because the allow rules come first in the list, an abort
        // here can never leave the host blocked without its allowlist in place.
        for (int i = 0; i < commands.Count; i++)
        {
            if (RunNetsh(commands[i], out string detail, out _)) continue;

            string what = string.Join(" ", commands[i]);
            _log.Action($"isolation aborted at step {i + 1}/{commands.Count}: {detail}");
            return ActionResult.Fail(
                $"isolation aborted at step {i + 1}/{commands.Count} ('{what}'): {detail}. " +
                "Network access was NOT blocked; any allow rules already added are harmless " +
                "and are removed by Release().");
        }

        lock (_gate)
        {
            _state = new IsolationState
            {
                Active = true,
                AppliedUtc = _clock.UtcNow,
                AllowedRemoteAddresses = allowed.ToArray()
            };
        }

        _log.Action($"host isolated; allowlist: {(allowed.Count == 0 ? "(none)" : string.Join(", ", allowed))}");
        return ActionResult.Success(
            $"host isolated (allowlist: {(allowed.Count == 0 ? "none" : string.Join(", ", allowed))})");
    }

    /// <summary>
    /// Restores the default firewall policy and removes the isolation allow rules.
    ///
    /// Callable at any time, including on a fresh agent that never called Isolate — the
    /// firewall policy outlives the process, so blind cleanup has to work. The policy is
    /// restored FIRST so connectivity comes back even if deleting the allow rules then
    /// fails; leftover allow rules are a far smaller problem than a still-isolated host.
    ///
    /// Because blind cleanup is the normal case, a delete step that netsh answers with a
    /// non-zero exit code — which is what it does for "No rules match the specified
    /// criteria" — is treated as success. Otherwise every release on a host that was
    /// never isolated would report failure. A delete that could not run AT ALL (netsh
    /// missing, or timed out) is still reported, as is any failure of the policy restore.
    ///
    /// Two honest limitations: the restored policy is the Windows default
    /// (block inbound / allow outbound), not whatever the host had before — this class
    /// does not snapshot the prior policy — and the firewall is left ENABLED even if
    /// isolation had to turn it on, because silently disabling a host firewall is not
    /// something an EDR should do.
    /// </summary>
    public ActionResult Release()
    {
        var commands = BuildReleaseCommands();
        var failures = new List<string>();

        for (int i = 0; i < commands.Count; i++)
        {
            if (RunNetsh(commands[i], out string detail, out int exitCode)) continue;

            // netsh cannot be asked "delete this rule if it exists"; it reports the empty
            // case as an error. exitCode > 0 means netsh ran and declined, which for a
            // cleanup delete is indistinguishable from, and usually is, "nothing to do".
            if (IsCleanupDelete(commands[i]) && exitCode > 0) continue;

            failures.Add($"step {i + 1} ('{string.Join(" ", commands[i])}'): {detail}");
        }

        // Step 0 is the policy restore. If that one worked the host has connectivity
        // again, which is what "released" means; the rule deletes are cleanup.
        bool policyRestored = failures.Count == 0 || !failures[0].StartsWith("step 1 ", StringComparison.Ordinal);

        if (policyRestored)
        {
            lock (_gate)
            {
                _state = new IsolationState { Active = false, AppliedUtc = _state.AppliedUtc };
            }
        }

        if (failures.Count == 0)
        {
            _log.Action("host isolation released");
            return ActionResult.Success("host isolation released");
        }

        string message = string.Join("; ", failures);
        _log.Action("isolation release problems: " + message);
        return policyRestored
            ? ActionResult.Fail("firewall policy restored, but cleanup was incomplete: " + message)
            : ActionResult.Fail("FAILED TO RESTORE the firewall policy; the host may still be isolated: " + message);
    }

    // ------------------------------------------------------- pure construction

    /// <summary>
    /// Builds the exact netsh argument vectors for isolation, in the order they must
    /// run. Each element is the argument list only — "netsh" itself is the executable
    /// and is not included.
    ///
    /// Pure and side-effect free so tests can assert the precise argv (and the ordering
    /// invariant that allow rules precede the block) without touching the firewall.
    /// The caller is responsible for validating the addresses; this function does not
    /// re-check them.
    /// </summary>
    internal static IReadOnlyList<string[]> BuildIsolateCommands(IReadOnlyList<string> allowed)
    {
        var list = new List<string[]>();
        var distinct = Normalize(allowed);

        if (distinct.Count > 0)
        {
            string csv = string.Join(",", distinct);

            list.Add(new[]
            {
                "advfirewall", "firewall", "add", "rule",
                "name=" + AllowOutRuleName,
                "dir=out", "action=allow", "remoteip=" + csv, "enable=yes", "profile=any"
            });

            list.Add(new[]
            {
                "advfirewall", "firewall", "add", "rule",
                "name=" + AllowInRuleName,
                "dir=in", "action=allow", "remoteip=" + csv, "enable=yes", "profile=any"
            });
        }

        // A disabled firewall would make the policy change a no-op, so isolation has to
        // enable it. This runs AFTER the allow rules for the same reason as everything
        // else here: nothing that can cut traffic happens before the exceptions exist.
        list.Add(new[] { "advfirewall", "set", "allprofiles", "state", "on" });

        // Default-deny both directions. Deliberately NOT an explicit block rule: an
        // explicit block outranks an explicit allow in Windows Firewall and would
        // override the allowlist above.
        list.Add(new[] { "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound" });

        return list;
    }

    /// <summary>
    /// Builds the release argument vectors, in order. The policy restore is first so a
    /// later failure still leaves the host reachable.
    /// </summary>
    internal static IReadOnlyList<string[]> BuildReleaseCommands() => new List<string[]>
    {
        new[] { "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound" },
        new[] { "advfirewall", "firewall", "delete", "rule", "name=" + AllowOutRuleName },
        new[] { "advfirewall", "firewall", "delete", "rule", "name=" + AllowInRuleName }
    };

    /// <summary>
    /// True for the "delete rule" steps of a release, whose failure is tolerated because
    /// netsh reports "nothing matched" as an error. Kept as a pure predicate over the
    /// argument vector so <see cref="BuildReleaseCommands"/> stays data, not policy.
    /// </summary>
    internal static bool IsCleanupDelete(IReadOnlyList<string> args)
        => args.Count >= 4 && args[0] == "advfirewall" && args[1] == "firewall" && args[2] == "delete";

    /// <summary>
    /// Accepts a single IPv4/IPv6 address, a CIDR block, an <c>a-b</c> range, or one of
    /// netsh's remoteip keywords.
    ///
    /// Everything else is rejected, and three rejections are deliberate rather than
    /// incidental:
    ///  - anything containing a comma, quote, equals sign or whitespace, which could
    ///    split the remoteip list or smuggle in another netsh setting;
    ///  - the keyword <c>any</c>;
    ///  - a wildcard address specification — <c>0.0.0.0</c>, <c>::</c>, or any <c>/0</c>
    ///    prefix. Those mean "allow everything", which would quietly turn isolation into
    ///    a no-op while still reporting success. An operator reading "host isolated" has
    ///    to be able to believe it.
    /// </summary>
    internal static bool IsValidRemoteAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;

        string v = value.Trim();
        if (v.Length > 64) return false;

        foreach (char c in v)
        {
            bool ok = char.IsAsciiLetterOrDigit(c) || c is '.' or ':' or '/' or '-';
            if (!ok) return false;
        }

        foreach (var keyword in AddressKeywords)
        {
            if (string.Equals(v, keyword, StringComparison.OrdinalIgnoreCase)) return true;
        }

        int slash = v.IndexOf('/');
        if (slash > 0)
        {
            if (!IPAddress.TryParse(v[..slash], out var network)) return false;
            if (!int.TryParse(v[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out int prefix))
                return false;
            int max = network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
            return prefix >= 1 && prefix <= max;      // /0 is "everything"; see remarks
        }

        if (IPAddress.TryParse(v, out var single)) return !IsUnspecified(single);

        // Range form. Only meaningful for IPv4 in practice, but parse both endpoints
        // generically and require a matching family.
        int dash = v.IndexOf('-');
        if (dash > 0 && dash < v.Length - 1)
        {
            if (!IPAddress.TryParse(v[..dash], out var lo)) return false;
            if (!IPAddress.TryParse(v[(dash + 1)..], out var hi)) return false;
            return lo.AddressFamily == hi.AddressFamily;
        }

        return false;
    }

    /// <summary>True for 0.0.0.0 or ::, both of which mean "any address" in a rule.</summary>
    private static bool IsUnspecified(IPAddress address)
        => address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

    /// <summary>Trims, drops blanks and removes case-insensitive duplicates, preserving order.</summary>
    private static List<string> Normalize(IReadOnlyList<string>? values)
    {
        var result = new List<string>();
        if (values is null) return result;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in values)
        {
            if (string.IsNullOrWhiteSpace(v)) continue;
            string t = v.Trim();
            if (seen.Add(t)) result.Add(t);
        }
        return result;
    }

    private static string Quote(string s) => "'" + s + "'";

    // ------------------------------------------------------------- invocation

    /// <summary>
    /// Runs one netsh command. Arguments go through ArgumentList so each element is
    /// quoted by the runtime and a rule name containing spaces stays one argument;
    /// building a command string by concatenation here would be an injection bug.
    ///
    /// <paramref name="exitCode"/> is -1 when netsh could not be started, timed out, or
    /// threw. That lets a caller distinguish "netsh ran and refused" (which for a delete
    /// usually just means the rule was not there) from "netsh never ran".
    /// </summary>
    private bool RunNetsh(string[] args, out string detail, out int exitCode)
    {
        detail = "";
        exitCode = -1;
        try
        {
            var psi = new ProcessStartInfo("netsh")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var proc = Process.Start(psi);
            if (proc is null) { detail = "failed to launch netsh"; return false; }

            // Drain both pipes concurrently with the wait. netsh output is small, but a
            // full pipe buffer would otherwise deadlock the wait against the child.
            var stdout = proc.StandardOutput.ReadToEndAsync();
            var stderr = proc.StandardError.ReadToEndAsync();

            if (!proc.WaitForExit(NetshTimeoutMs))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                detail = $"netsh timed out after {NetshTimeoutMs} ms";
                return false;
            }

            exitCode = proc.ExitCode;
            if (exitCode == 0) return true;

            string text = (Result(stdout) + " " + Result(stderr)).Trim();
            detail = $"netsh exit code {exitCode}" + (text.Length == 0 ? "" : ": " + Collapse(text));
            return false;
        }
        catch (Exception ex)
        {
            detail = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private static string Result(Task<string> t)
    {
        try { return t.GetAwaiter().GetResult(); }
        catch { return ""; }
    }

    /// <summary>
    /// Squashes netsh's multi-line output into one log-friendly line. The separators go
    /// in as an explicit array: passing them as two char arguments binds to the
    /// Split(char, int, StringSplitOptions) overload, because the options enum converts
    /// to int, which would split on '\r' only and cap the result at 10 parts.
    /// </summary>
    private static string Collapse(string text)
    {
        string one = string.Join(" ", text.Split(new[] { '\r', '\n' },
                                                 StringSplitOptions.RemoveEmptyEntries |
                                                 StringSplitOptions.TrimEntries));
        return one.Length <= 300 ? one : one[..300] + "...";
    }
}

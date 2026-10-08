using System.Runtime.InteropServices;
using BruceEDR.Core;

namespace BruceEDR.Response;

/// <summary>The few firewall operations cleanup needs, so the logic can be tested without a firewall.</summary>
internal interface IFirewallRuleStore
{
    IReadOnlyList<string> RuleNames();
    void Remove(string name);
}

/// <summary>
/// Removes every Windows Firewall block rule BruceEDR created, and lifts host isolation if
/// BruceEDR applied it. Outbound blocks are keyed to an image path and outlive the agent,
/// so without this an app could stay offline after BruceEDR exits or is uninstalled. Used by
/// <c>BruceEDR.exe --cleanup</c>, the MSI uninstaller and the GUI. Needs administrator rights.
///
/// It never weakens a firewall BruceEDR did not change. Rules are matched on BruceEDR's own
/// exact names (and the ProcessShield names it used before the rename). The default policy
/// is restored only when <see cref="NetworkIsolation.WasAppliedByBruceEdr"/> proves BruceEDR
/// changed it: isolation installs its allow rules before the policy, and a host can block
/// outbound by design, so neither the rules nor the policy are proof. Without that proof the
/// isolation allow rules are left alone too: removing them could lock out a host an older
/// build isolated, and keeping them only ever allows traffic.
/// </summary>
public static class FirewallCleanup
{
    // Rule names are "<prefix> <file> <pid>", or exactly the prefix when the sanitiser
    // strips everything else. Matching the bare prefix would also take "BruceEDR Blocklist".
    private static readonly string[] BlockPrefixes = { "BruceEDR Block", "ProcessShield Block" };

    /// <summary>A rule store whose Remove never takes effect must not spin forever.</summary>
    internal const int MaxPasses = 20;

    public static bool IsBlockRule(string? name)
        => name is not null && BlockPrefixes.Any(p => name == p || name.StartsWith(p + " ", StringComparison.Ordinal));

    /// <summary>Allow rules of BruceEDR's host isolation.</summary>
    public static bool IsIsolationRule(string? name)
        => name is not null && name.StartsWith(NetworkIsolation.RuleNamePrefix + " ", StringComparison.Ordinal);

    /// <summary>Runs the cleanup against the real firewall.</summary>
    public static ActionResult RemoveAll(Logger log)
    {
        IFirewallRuleStore store;
        try { store = new ComFirewallRuleStore(); }
        catch (Exception ex) { return ActionResult.Fail("the Windows Firewall API is unavailable: " + ex.Message); }
        return RemoveAll(store, NetworkIsolation.WasAppliedByBruceEdr, () => new NetworkIsolation(log).Release());
    }

    internal static ActionResult RemoveAll(IFirewallRuleStore store, Func<bool> isolationApplied, Func<ActionResult> releaseIsolation)
    {
        try
        {
            var notes = new List<string>();
            bool ok = true;

            // Isolation first: restoring connectivity matters more than tidying rules.
            if (isolationApplied())
            {
                var released = releaseIsolation();
                notes.Add(released.Ok ? "host isolation lifted" : released.Message);
                ok &= released.Ok;
            }
            else if (store.RuleNames().Any(IsIsolationRule))
            {
                notes.Add("isolation allow rules left in place: nothing shows BruceEDR changed the firewall " +
                          "policy, and they only allow traffic (if this host is isolated, run " +
                          "BruceEDR.exe --console and 'isolate off')");
            }

            int before = store.RuleNames().Count(IsBlockRule);
            for (int pass = 0; pass < MaxPasses; pass++)
            {
                var names = store.RuleNames().Where(IsBlockRule).Distinct(StringComparer.Ordinal).ToList();
                if (names.Count == 0) break;
                // Remove's behaviour with duplicate names is unspecified, so re-enumerate
                // until nothing of ours is left instead of trusting one call per name.
                foreach (var name in names) store.Remove(name);
            }
            int left = store.RuleNames().Count(IsBlockRule);

            notes.Insert(0, $"removed {before - left} BruceEDR firewall block(s)");
            if (left > 0)
            {
                ok = false;
                notes.Add($"{left} block(s) could not be removed");
            }
            string message = string.Join("; ", notes);
            return ok ? ActionResult.Success(message) : ActionResult.Fail(message);
        }
        catch (UnauthorizedAccessException)
        {
            return ActionResult.Fail("removing firewall rules needs administrator rights");
        }
        catch (COMException ex) when ((uint)ex.HResult == 0x80070005)
        {
            return ActionResult.Fail("removing firewall rules needs administrator rights");
        }
        catch (Exception ex)
        {
            return ActionResult.Fail("firewall cleanup failed: " + ex.Message);
        }
    }
}

/// <summary>INetFwPolicy2 through late-bound COM: locale-independent, unlike parsing netsh output.</summary>
internal sealed class ComFirewallRuleStore : IFirewallRuleStore
{
    private readonly dynamic _policy;

    public ComFirewallRuleStore()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        _policy = Activator.CreateInstance(type)!;
    }

    public IReadOnlyList<string> RuleNames()
    {
        var names = new List<string>();
        foreach (dynamic rule in _policy.Rules)
        {
            string? name = rule.Name;
            if (!string.IsNullOrEmpty(name)) names.Add(name);
        }
        return names;
    }

    public void Remove(string name) => _policy.Rules.Remove(name);
}

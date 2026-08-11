using System.Text.Json;
using ProcessShield.Api;
using ProcessShield.Core;
using ProcessShield.Detection;
using ProcessShield.Telemetry;

namespace ProcessShield.Hosting;

/// <summary>
/// Bridges the HTTP control plane to the running agent. Every method returns
/// already-serialised JSON, which keeps <see cref="ControlServer"/> responsible for
/// transport and authorisation only and makes the whole routing table testable against a
/// fake backend.
///
/// Reads that touch engine-owned state go through ShieldHost's owner-thread query
/// mechanism, so an HTTP handler thread never races the detection loop.
/// </summary>
internal sealed class ControlBackend : IControlBackend
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly Composition _composition;
    private readonly DateTime _startedUtc = DateTime.UtcNow;

    public ControlBackend(Composition composition) => _composition = composition;

    public string AgentVersion => EventFormatters.AgentVersion;

    public string Status()
    {
        var host = _composition.Host;
        var m = host.Metrics.Snapshot();
        return JsonSerializer.Serialize(new
        {
            product = "ProcessShield",
            version = AgentVersion,
            startedUtc = _startedUtc,
            uptimeSeconds = (int)(DateTime.UtcNow - _startedUtc).TotalSeconds,
            machine = Environment.MachineName,
            monitors = host.ActiveMonitors,
            trackedProcesses = host.TrackedProcesses(),
            detectionRules = _composition.Rules.Rules.Count,
            ruleErrors = _composition.Rules.Errors.Count(e => e.IsBlocking),
            indicators = _composition.Intel.Count,
            surfaceEndpoints = _composition.Surface.Count,
            vaultEnabled = _composition.Vault is not null,
            isolationActive = _composition.Isolation.State.Active,
            signals = m.Signals,
            dropped = m.Dropped,
            warns = m.Warns,
            quarantines = m.Quarantines
        }, Json);
    }

    public string Profiles(bool onlyContained)
        => JsonSerializer.Serialize(_composition.Host.ListProfiles(onlyContained), Json);

    public string Profile(int pid)
    {
        var match = _composition.Host.ListProfiles(onlyContained: false).FirstOrDefault(p => p.Pid == pid);
        if (match is null) return JsonSerializer.Serialize(new { error = "no tracked process", pid }, Json);
        return JsonSerializer.Serialize(new
        {
            profile = match,
            lineage = _composition.Host.Lineage(pid)
        }, Json);
    }

    public string Surface()
        => JsonSerializer.Serialize(_composition.Host.SurfaceEndpoints(), Json);

    public string Metrics() => _composition.Host.Metrics.ToPrometheusText();

    public string Events(int limit) => _composition.Events.RecentJson(limit);

    public string Rules()
    {
        var set = _composition.Rules;
        return JsonSerializer.Serialize(new
        {
            count = set.Rules.Count,
            errors = set.Errors.Select(e => new { e.RuleId, e.Message, blocking = e.IsBlocking }),
            rules = set.Rules.Select(r => new
            {
                r.Id, r.Title, r.Severity, r.Score, r.Enabled,
                r.Techniques, r.Kinds, r.FalsePositives
            })
        }, Json);
    }

    public string AttackCoverage()
    {
        var fromRules = new RuleEngine(_composition.Rules).TechniqueCoverage();
        var observed = _composition.Host.ObservedTechniques();

        // Union of what the rules can detect and what has actually been seen, so a
        // dashboard can render coverage and activity in one matrix.
        var ids = new SortedSet<string>(fromRules.Keys, StringComparer.OrdinalIgnoreCase);
        foreach (var id in observed.Keys) ids.Add(id);

        return JsonSerializer.Serialize(new
        {
            framework = "MITRE ATT&CK",
            techniques = ids.Select(id =>
            {
                var t = AttackCatalog.Lookup(id);
                return new
                {
                    id = t.Id,
                    name = t.Name,
                    tactic = t.Tactic,
                    url = t.Url,
                    rules = fromRules.TryGetValue(id, out var n) ? n : 0,
                    observedProcesses = observed.TryGetValue(id, out var o) ? o : 0
                };
            })
        }, Json);
    }

    public (bool ok, string message) Action(string verb, int pid)
    {
        var host = _composition.Host;
        var result = verb.ToLowerInvariant() switch
        {
            "resume" or "release" => host.Resume(pid),
            "suspend" => host.Suspend(pid),
            "kill" or "terminate" => host.Kill(pid),
            _ => ActionResult.Fail($"unknown action '{verb}'")
        };
        return (result.Ok, result.Message);
    }

    public (bool ok, string message) VerifyAudit()
    {
        string message = _composition.VerifyAudit();
        return (!message.StartsWith("AUDIT LOG", StringComparison.Ordinal), message);
    }
}

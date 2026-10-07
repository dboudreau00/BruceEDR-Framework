using System.Text.Json;
using BruceEDR.Core;
using BruceEDR.Hosting;
using BruceEDR.Response;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// Host-level tests for the two settings that guard operator-visible safety behaviour:
/// playbook-driven host isolation and the Authenticode revocation notice. They build the
/// real <see cref="Composition"/> and cross the seam the engine-only tests stop short of.
/// No test here can touch the firewall: with the gate open the allowlist is still empty,
/// and <see cref="NetworkIsolation"/> refuses that before it runs a single netsh command.
/// </summary>
public sealed class CompositionGateTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bruce-gate-" + Guid.NewGuid().ToString("N"));

    public CompositionGateTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private sealed class CaptureSink : IEventSink
    {
        private readonly object _gate = new();
        private readonly List<BruceEvent> _events = new();

        public void Emit(BruceEvent e) { lock (_gate) _events.Add(e); }

        public BruceEvent[] Snapshot() { lock (_gate) return _events.ToArray(); }

        public void Dispose() { }
    }

    private Composition Build(CaptureSink sink, bool allowPlaybookIsolation = false, bool checkRevocation = false)
    {
        var config = new
        {
            detection = new { enableRuleEngine = false },
            allowlist = new { checkRevocation },
            intel = new { enabled = false },
            response = new
            {
                useEncryptedVault = false,
                isolationAllowlist = Array.Empty<string>(),
                allowPlaybookIsolation,
            },
            watchlist = new { enabled = false },
            telemetry = new
            {
                jsonlPath = Path.Combine(_dir, "incidents.jsonl"),
                auditPath = Path.Combine(_dir, "audit.log"),
            },
        };
        string path = Path.Combine(_dir, "bruce.config.json");
        File.WriteAllText(path, JsonSerializer.Serialize(config));
        return Composition.Build(path, sink);
    }

    private static ProfileSnapshot Snapshot() => new()
    {
        Pid = 4242,
        ProcessName = "evil.exe",
        ImagePath = @"C:\t\evil.exe",
        Score = 90,
        Trusted = false,
        Contained = true,
        SuspendedByAnalyst = false,
        Terminated = false,
        Reasons = Array.Empty<string>(),
        StagedArchives = Array.Empty<string>(),
        FirstSeenUtc = DateTime.UtcNow,
        LastUpdatedUtc = DateTime.UtcNow,
    };

    [Fact]
    public void Playbook_IsolateHost_Is_Refused_And_Logged_By_Default()
    {
        var sink = new CaptureSink();
        using var comp = Build(sink);

        comp.RunExtendedAction(PlaybookAction.IsolateHost, Snapshot());

        Assert.Contains(sink.Snapshot(), e => e.Level == "ACTION" && e.Message.Contains("host isolation refused"));
        // Nothing may have reached the isolation primitive: it never even got to refuse.
        Assert.DoesNotContain(sink.Snapshot(), e => e.Message.Contains("host isolation failed"));
        Assert.False(comp.Isolation.State.Active);
    }

    [Fact]
    public void Opting_In_Hands_IsolateHost_To_NetworkIsolation_Which_Still_Refuses_An_Empty_Allowlist()
    {
        // The gate must open on the flag alone, and opening it must not weaken the
        // empty-allowlist refusal that stops a playbook from causing a total blackout.
        var sink = new CaptureSink();
        using var comp = Build(sink, allowPlaybookIsolation: true);

        comp.RunExtendedAction(PlaybookAction.IsolateHost, Snapshot());

        Assert.DoesNotContain(sink.Snapshot(), e => e.Message.Contains("host isolation refused"));
        Assert.Contains(sink.Snapshot(),
            e => e.Level == "ACTION" && e.Message.Contains("host isolation failed") && e.Message.Contains("empty allowlist"));
        Assert.False(comp.Isolation.State.Active);
    }

    [Fact]
    public void Startup_Notes_That_Revocation_Checking_Is_Off()
    {
        var sink = new CaptureSink();
        using var comp = Build(sink, checkRevocation: false);

        Assert.Contains(sink.Snapshot(),
            e => e.Level == "INFO" && e.Message.Contains("allowlist.checkRevocation is false"));
    }

    [Fact]
    public void Startup_Is_Quiet_About_Revocation_When_It_Is_On()
    {
        var sink = new CaptureSink();
        using var comp = Build(sink, checkRevocation: true);

        Assert.DoesNotContain(sink.Snapshot(), e => e.Message.Contains("allowlist.checkRevocation"));
    }
}

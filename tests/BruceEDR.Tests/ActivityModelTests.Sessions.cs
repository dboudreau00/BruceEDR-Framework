using BruceEDR.Activity;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Monitoring;
using BruceEDR.Replay;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>Saved sessions: the file a run is kept in, and a trace opened as one.</summary>
public sealed partial class ActivityModelTests
{
    // ================================================================ saved sessions

    [Fact]
    public void A_saved_session_loads_back_the_same_tree_files_and_verdicts()
    {
        var m = Feed(
            Start(100, 4, "dropper.exe", 0, @"C:\Users\u\dropper.exe", "dropper.exe -x"), Create(100, Payload, 1),
            Start(200, 100, "payload.exe", 2, Payload), Delete(200, Payload, 6, "on-close"),
            Rename(100, @"C:\x\a.txt", @"C:\x\b.txt", 7));
        m.Observe(new Signal { Kind = SignalKind.NetworkConnect, Pid = 200, RemoteAddress = "10.0.0.5", RemotePort = 443, TimestampUtc = T0.AddSeconds(8) });
        var before = m.Snapshot();

        string path = SessionStore.Save(_dir, before, label: "Lab run");
        var after = SessionStore.Load(path);

        Assert.Equal("session", after.Source);
        Assert.Equal("Lab run", after.Name);
        Assert.Equal(before.Processes.Select(p => (p.Id, p.Name, p.ParentId, p.CommandLine)),
                     after.Processes.Select(p => (p.Id, p.Name, p.ParentId, p.CommandLine)));
        Assert.Equal(MeltKind.SelfDelete, File(after, Payload).Melt);
        Assert.Equal(File(before, Payload).Events, File(after, Payload).Events);
        Assert.Equal(before.Totals, after.Totals);
        Assert.Equal(before.Destinations, after.Destinations);
        Assert.Equal(before.StartedUtc, after.StartedUtc);
    }

    [Fact]
    public void The_session_list_reads_the_side_files_newest_first_and_keeps_only_the_newest()
    {
        var snap = Feed(Start(100, 0, "a.exe", 0), Start(200, 100, "b.exe", 1)).Snapshot();
        for (int i = 0; i < 4; i++)
        {
            SessionStore.Save(_dir, snap with { EndedUtc = T0.AddMinutes(i) }, keep: 3, label: "run " + i);
            Thread.Sleep(60);
        }
        var list = SessionStore.List(_dir);

        Assert.Equal(3, list.Count);
        Assert.Equal(new[] { "run 3", "run 2", "run 1" }, list.Select(e => e.Name));
        Assert.All(list, e => Assert.Equal(2, e.Processes));
        Assert.Empty(Directory.EnumerateFiles(_dir, "*.tmp"));
    }

    [Fact]
    public void A_file_that_is_not_a_session_is_a_clear_error_and_never_listed()
    {
        Directory.CreateDirectory(_dir);
        WriteText(Path.Combine(_dir, "junk" + SessionStore.Extension), "not gzip");

        Assert.Throws<InvalidDataException>(() => SessionStore.Load(Path.Combine(_dir, "junk" + SessionStore.Extension)));
        Assert.Single(SessionStore.List(_dir));   // present, but only by name: it is not opened to list it
        Assert.Empty(SessionStore.List(Path.Combine(_dir, "missing")));
    }

    private static void WriteText(string path, string text) => System.IO.File.WriteAllText(path, text);

    [Fact]
    public void A_trace_file_opens_as_a_session_including_deletes_and_renames()
    {
        var scenario = TraceFormat.FromSignals(new[]
        {
            Start(100, 4, "dropper.exe", 0), Create(100, Payload, 1),
            Start(200, 100, "payload.exe", 2, Payload),
            Delete(200, Payload, 6, "on-close"),
            Rename(100, @"C:\x\a.txt", @"C:\x\b.txt", 7)
        }, "melt-demo");
        Directory.CreateDirectory(_dir);
        string trace = Path.Combine(_dir, "melt.jsonl");
        TraceFormat.Save(trace, scenario);

        var s = SessionStore.FromTrace(trace);

        Assert.Equal("trace", s.Source);
        Assert.Equal("melt-demo", s.Name);
        Assert.Equal(MeltKind.SelfDelete, File(s, Payload).Melt);
        Assert.Equal(@"C:\x\b.txt", File(s, @"C:\x\a.txt").Events.Last().Other);
    }
}

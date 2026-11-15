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

/// <summary>
/// The process tree and file histories behind the process map, the file map and Insights, and the
/// verdict on "melted" files: a program that deletes itself after it runs.
/// </summary>
public sealed partial class ActivityModelTests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bruce-activity-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static Signal Start(int pid, int ppid, string name, double at, string? image = null, string cmd = "")
        => new()
        {
            Kind = SignalKind.ProcessStart, Pid = pid, ParentPid = ppid, ProcessName = name,
            ImagePath = image ?? "", CommandLine = cmd, TimestampUtc = T0.AddSeconds(at)
        };

    private static Signal Stop(int pid, double at)
        => new() { Kind = SignalKind.ProcessStop, Pid = pid, TimestampUtc = T0.AddSeconds(at) };

    private static Signal Create(int pid, string path, double at, string? detail = "create")
        => new() { Kind = SignalKind.FileCreate, Pid = pid, FilePath = path, Detail = detail, TimestampUtc = T0.AddSeconds(at) };

    private static Signal Delete(int pid, string path, double at, string detail = "delete")
        => new() { Kind = SignalKind.FileDelete, Pid = pid, FilePath = path, Detail = detail, TimestampUtc = T0.AddSeconds(at) };

    private static Signal Rename(int pid, string from, string? to, double at)
        => new() { Kind = SignalKind.FileRename, Pid = pid, FilePath = from, Detail = to, TimestampUtc = T0.AddSeconds(at) };

    private static Signal Load(int pid, string path, double at)
        => new() { Kind = SignalKind.ImageLoad, Pid = pid, FilePath = path, TimestampUtc = T0.AddSeconds(at) };

    private static ActivityModel Feed(params Signal[] signals)
    {
        var m = new ActivityModel();
        foreach (var s in signals) m.Observe(s);
        return m;
    }

    private static ProcessInfo Proc(ActivitySnapshot s, int pid) => s.Processes.Last(p => p.Pid == pid);

    // ================================================================ a start event that arrives late

    [Fact]
    public void A_start_event_that_arrives_after_the_processs_own_file_events_adopts_that_process()
    {
        // Seen in a Windows 11 lab VM: the kernel delivered a program's file events before its start event.
        var snap = Feed(
            Start(100, 4, "parent.exe", 0, @"C:\x\parent.exe"),
            Create(200, @"C:\Windows\Prefetch\KB.EXE-1A.pf", 1.0),
            Start(200, 100, "kb.exe", 0.9, @"C:\x\kb.exe", "kb.exe /go")).Snapshot();

        var all = snap.Processes.Where(p => p.Pid == 200).ToList();
        var kb = Assert.Single(all);
        Assert.False(kb.PreExisting);
        Assert.Equal("kb.exe /go", kb.CommandLine);
        Assert.Equal(Proc(snap, 100).Id, kb.ParentId);
        Assert.Equal(2, snap.Total(ActivityKind.ProcessStart));   // the parent and this one, counted once each
        Assert.Equal(T0.AddSeconds(0.9), kb.StartUtc);
    }

    [Fact]
    public void A_pid_that_is_really_reused_is_still_a_second_process()
    {
        var snap = Feed(
            Start(200, 100, "first.exe", 0, @"C:\x\first.exe"),
            Stop(200, 2),
            Start(200, 100, "second.exe", 3, @"C:\x\second.exe")).Snapshot();

        Assert.Equal(2, snap.Processes.Count(p => p.Pid == 200));

        // And a process first seen mid-run, whose pid is then reused long after, is not mistaken for a late start.
        var later = Feed(
            Create(300, @"C:\x\a.dat", 1),
            Start(300, 100, "new.exe", 60, @"C:\x\new.exe")).Snapshot();
        Assert.Equal(2, later.Processes.Count(p => p.Pid == 300));
    }

    private static FileTrail File(ActivitySnapshot s, string path)
        => s.Files.Single(f => string.Equals(f.Path, path, StringComparison.OrdinalIgnoreCase));

    private const string Payload = @"C:\Users\u\AppData\Local\Temp\payload.exe";

    // ================================================================ process tree

    [Fact]
    public void A_child_is_linked_to_the_node_that_was_its_parent_when_it_started()
    {
        var s = Feed(Start(100, 4, "winword.exe", 0), Start(200, 100, "cmd.exe", 1), Start(300, 200, "powershell.exe", 2)).Snapshot();

        Assert.Equal(Proc(s, 100).Id, Proc(s, 200).ParentId);
        Assert.Equal(Proc(s, 200).Id, Proc(s, 300).ParentId);
        Assert.Equal(3, s.Total(ActivityKind.ProcessStart));
    }

    [Fact]
    public void A_reused_pid_closes_the_old_process_and_the_new_one_gets_its_own_children()
    {
        var s = Feed(
            Start(100, 4, "old.exe", 0), Start(150, 100, "oldchild.exe", 1),
            Start(100, 4, "new.exe", 10), Start(160, 100, "newchild.exe", 11)).Snapshot();

        var oldOne = s.Processes.Single(p => p.Name == "old.exe");
        var newOne = s.Processes.Single(p => p.Name == "new.exe");
        Assert.NotNull(oldOne.ExitUtc);
        Assert.Null(newOne.ExitUtc);
        Assert.Equal(oldOne.Id, Proc(s, 150).ParentId);
        Assert.Equal(newOne.Id, Proc(s, 160).ParentId);
    }

    [Fact]
    public void A_parent_that_started_before_monitoring_becomes_one_shared_stand_in()
    {
        int lookups = 0;
        var m = new ActivityModel(new ActivityModelOptions { ResolveName = pid => { lookups++; return pid == 900 ? "explorer.exe" : null; } });
        m.Observe(Start(201, 900, "a.exe", 0));
        m.Observe(Start(202, 900, "b.exe", 1));
        var s = m.Snapshot();

        var parent = Proc(s, 900);
        Assert.True(parent.PreExisting);
        Assert.Equal("explorer.exe", parent.Name);
        Assert.Equal(parent.Id, Proc(s, 201).ParentId);
        Assert.Equal(parent.Id, Proc(s, 202).ParentId);
        Assert.Equal(1, lookups);
    }

    [Fact]
    public void A_pid_that_has_moved_on_is_not_shown_as_a_parent_it_never_was()
    {
        // pid 100 now belongs to "new.exe", started after the child named it as its parent.
        var s = Feed(Start(100, 4, "new.exe", 50), Start(200, 100, "child.exe", 10)).Snapshot();

        Assert.Equal(0, Proc(s, 200).ParentId);
    }

    [Fact]
    public void A_stop_closes_the_process_and_late_telemetry_stays_with_it()
    {
        var s = Feed(Start(100, 0, "a.exe", 0), Stop(100, 5), Create(100, @"C:\x\late.dat", 5.2)).Snapshot();

        Assert.Single(s.Processes);
        Assert.NotNull(Proc(s, 100).ExitUtc);
        Assert.Equal(1, Proc(s, 100).Count(ActivityKind.FileCreate));
    }

    [Fact]
    public void Signals_from_a_process_never_seen_start_create_a_node_flagged_pre_existing()
    {
        var s = Feed(Create(777, @"C:\x\a.dat", 0)).Snapshot();

        Assert.True(Proc(s, 777).PreExisting);
    }

    [Fact]
    public void Opening_files_counts_but_follows_nothing()
    {
        var m = Feed(Start(100, 4, "a.exe", 0));
        for (int i = 0; i < 500; i++) m.Observe(Create(100, $@"C:\Windows\System32\f{i}.dll", 1, "open"));
        var s = m.Snapshot();

        Assert.Equal(500, s.Total(ActivityKind.FileOpen));
        Assert.Equal(500, Proc(s, 100).Count(ActivityKind.FileOpen));
        Assert.Empty(s.Files);
    }

    [Fact]
    public void Kernel_device_paths_are_shown_as_drive_paths()
    {
        var m = new ActivityModel(new ActivityModelOptions
        {
            NormalizePath = p => p.StartsWith(@"\Device\HarddiskVolume3\", StringComparison.OrdinalIgnoreCase) ? "C:\\" + p[24..] : p
        });
        m.Observe(Start(100, 4, "a.exe", 0));
        m.Observe(Create(100, @"\Device\HarddiskVolume3\Users\u\note.txt", 1));

        Assert.Equal(@"C:\Users\u\note.txt", m.Snapshot().Files.Single().Path);
    }

    // ================================================================ files

    [Fact]
    public void A_file_made_by_one_program_and_run_by_another_is_dropped()
    {
        var s = Feed(
            Start(100, 4, "dropper.exe", 0), Create(100, Payload, 1),
            Start(200, 100, "payload.exe", 2, Payload)).Snapshot();

        var f = File(s, Payload);
        Assert.True(f.Dropped);
        Assert.Equal(Proc(s, 100).Id, f.CreatorId);
        Assert.Equal(Proc(s, 200).Id, f.RunnerId);
    }

    [Fact]
    public void The_kernel_start_event_has_only_a_name_so_the_run_is_registered_at_the_image_load()
    {
        var s = Feed(
            Start(100, 4, "dropper.exe", 0), Create(100, Payload, 1),
            Start(200, 100, "payload.exe", 2),               // no path yet
            Load(200, Payload, 2.1)).Snapshot();

        Assert.Equal(Payload, Proc(s, 200).Image);
        Assert.True(File(s, Payload).Executed);
    }

    [Fact]
    public void A_deleted_file_that_never_ran_is_deleted_and_not_melted()
    {
        var s = Feed(Start(100, 4, "a.exe", 0), Create(100, @"C:\x\notes.txt", 1), Delete(100, @"C:\x\notes.txt", 5)).Snapshot();

        var f = File(s, @"C:\x\notes.txt");
        Assert.True(f.Deleted);
        Assert.Equal(MeltKind.None, f.Melt);
    }

    [Fact]
    public void A_program_that_deletes_its_own_file_is_melted()
    {
        var s = Feed(
            Start(100, 4, "dropper.exe", 0), Create(100, Payload, 1),
            Start(200, 100, "payload.exe", 2, Payload),
            Delete(200, Payload, 6)).Snapshot();

        var f = File(s, Payload);
        Assert.Equal(MeltKind.SelfDelete, f.Melt);
        Assert.True(f.IsMelted);
        Assert.Equal(Proc(s, 200).Id, f.DeleterId);
        Assert.Contains("payload.exe", f.MeltNote);
    }

    [Fact]
    public void Delete_on_close_by_the_running_program_is_melted_and_says_so()
    {
        var s = Feed(
            Start(200, 4, "payload.exe", 0, Payload),
            Delete(200, Payload, 1, "on-close")).Snapshot();

        var f = File(s, Payload);
        Assert.Equal(MeltKind.SelfDelete, f.Melt);
        Assert.Equal(FileOp.DeletedOnClose, f.Events.Last().Op);
        Assert.Contains("deleted its own file", f.MeltNote);
    }

    [Fact]
    public void A_shell_the_program_started_that_deletes_it_after_it_exited_is_a_child_delete()
    {
        // payload.exe starts "cmd /c ping ... & del payload.exe", exits, and cmd removes the file.
        var s = Feed(
            Start(200, 4, "payload.exe", 0, Payload),
            Start(201, 200, "cmd.exe", 1, @"C:\Windows\System32\cmd.exe"),
            Stop(200, 2),
            Delete(201, Payload, 5)).Snapshot();

        var f = File(s, Payload);
        Assert.Equal(MeltKind.ChildDelete, f.Melt);
        Assert.Contains("started by payload.exe", f.MeltNote);
    }

    [Fact]
    public void A_delete_two_shells_down_is_still_the_programs_doing()
    {
        var s = Feed(
            Start(200, 4, "payload.exe", 0, Payload),
            Start(201, 200, "cmd.exe", 1, @"C:\Windows\System32\cmd.exe"),
            Start(202, 201, "cmd.exe", 2, @"C:\Windows\System32\cmd.exe"),
            Delete(202, Payload, 5)).Snapshot();

        Assert.Equal(MeltKind.ChildDelete, File(s, Payload).Melt);
    }

    [Fact]
    public void A_stranger_that_deletes_a_file_soon_after_it_ran_is_only_ran_then_deleted()
    {
        var s = Feed(
            Start(50, 4, "explorer.exe", 0, @"C:\Windows\explorer.exe"),
            Start(200, 50, "tool.exe", 1, Payload), Stop(200, 3),
            Delete(50, Payload, 30)).Snapshot();

        var f = File(s, Payload);
        Assert.Equal(MeltKind.AfterRun, f.Melt);
        Assert.False(f.IsMelted);
        Assert.Contains("explorer.exe", f.MeltNote);
    }

    [Fact]
    public void A_delete_long_after_the_program_ended_is_not_connected_to_it()
    {
        var s = Feed(
            Start(50, 4, "explorer.exe", 0, @"C:\Windows\explorer.exe"),
            Start(200, 50, "tool.exe", 1, Payload), Stop(200, 3),
            Delete(50, Payload, 3 + 30 * 60)).Snapshot();

        Assert.Equal(MeltKind.None, File(s, Payload).Melt);
    }

    [Fact]
    public void A_kernel_delete_and_a_watcher_delete_of_the_same_file_are_one_event_with_the_process_named()
    {
        var m = Feed(
            Start(200, 4, "payload.exe", 0, Payload),
            Delete(0, Payload, 5),            // the folder watcher: no process
            Delete(200, Payload, 5.2));       // the kernel monitor
        var s = m.Snapshot();

        var f = File(s, Payload);
        Assert.Single(f.Events, e => e.Op is FileOp.Deleted or FileOp.DeletedOnClose);
        Assert.Equal(Proc(s, 200).Id, f.DeleterId);
        Assert.Equal(1, s.Total(ActivityKind.FileDelete));
        Assert.Equal(MeltKind.SelfDelete, f.Melt);
    }

    [Fact]
    public void A_delete_on_close_followed_by_its_own_delete_is_one_removal()
    {
        var s = Feed(Start(200, 4, "payload.exe", 0, Payload), Delete(200, Payload, 1, "on-close"), Delete(200, Payload, 1.5)).Snapshot();

        Assert.Single(File(s, Payload).Events, e => e.Op is FileOp.Deleted or FileOp.DeletedOnClose);
    }

    [Fact]
    public void A_rename_links_both_names_and_the_program_keeps_its_run()
    {
        const string Moved = @"C:\Users\u\AppData\Local\Temp\x.tmp";
        var s = Feed(
            Start(100, 4, "dropper.exe", 0), Create(100, Payload, 1),
            Start(200, 100, "payload.exe", 2, Payload),
            Rename(200, Payload, Moved, 3)).Snapshot();

        Assert.True(File(s, Payload).Renamed);
        Assert.Equal(Moved, File(s, Payload).Events.Last().Other);
        var moved = File(s, Moved);
        Assert.Equal(Payload, moved.Events.Last().Other);
        Assert.Equal(FileOp.RenamedFrom, moved.Events.Last().Op);
        Assert.True(moved.Executed);
    }

    [Fact]
    public void A_rename_without_a_new_name_still_records_the_old_one()
    {
        var s = Feed(Start(100, 4, "a.exe", 0), Rename(100, @"C:\x\report.docx", null, 1)).Snapshot();

        Assert.True(File(s, @"C:\x\report.docx").Renamed);
        Assert.Equal(1, s.Total(ActivityKind.FileRename));
    }

    [Fact]
    public void A_dropped_module_that_gets_loaded_is_in_its_history_and_a_system_dll_is_not_followed()
    {
        const string Dll = @"C:\Users\u\AppData\Local\Temp\evil.dll";
        var s = Feed(
            Start(100, 4, "a.exe", 0), Create(100, Dll, 1),
            Load(100, Dll, 2), Load(100, @"C:\Windows\System32\kernel32.dll", 2)).Snapshot();

        Assert.Contains(File(s, Dll).Events, e => e.Op == FileOp.Loaded);
        Assert.Single(s.Files);
    }

    [Theory]
    [InlineData(@"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Cache\f_001", true)]
    [InlineData(@"C:\Users\u\AppData\Local\Microsoft\Windows\INetCache\x.js", true)]
    [InlineData(@"C:\Windows\Prefetch\A.pf", true)]
    [InlineData(@"C:\Users\u\AppData\Local\Temp\payload.exe", false)]
    public void Cache_churn_is_marked_noisy_and_a_temp_file_is_not(string path, bool noisy)
    {
        var f = Feed(Start(100, 4, "a.exe", 0), Create(100, path, 1)).Snapshot().Files.Single();

        Assert.Equal(noisy, f.Noisy);
    }

    [Fact]
    public void A_burst_of_opens_for_writing_is_one_creation()
    {
        var m = Feed(Start(100, 4, "a.exe", 0));
        for (int i = 0; i < 40; i++) m.Observe(Create(100, @"C:\x\log.txt", 1 + i * 0.01));

        Assert.Single(m.Snapshot().Files.Single().Events);
    }

    // ================================================================ caps

    [Fact]
    public void The_file_cap_drops_cache_and_plain_files_before_deletes_and_melts()
    {
        var m = new ActivityModel(new ActivityModelOptions { MaxFiles = 50 });
        m.Observe(Start(200, 4, "payload.exe", 0, Payload));
        m.Observe(Delete(200, Payload, 1, "on-close"));
        for (int i = 0; i < 200; i++) m.Observe(Create(200, $@"C:\Users\u\AppData\Local\Temp\f{i}.bin", 2 + i * 0.01));
        var s = m.Snapshot();

        Assert.True(s.Files.Count <= 50);
        Assert.Contains(s.Files, f => f.Path == Payload && f.IsMelted);
    }

    [Fact]
    public void The_process_cap_drops_exited_unflagged_processes_first()
    {
        var m = new ActivityModel(new ActivityModelOptions { MaxProcesses = 40 });
        m.Observe(Start(1, 4, "keeper.exe", 0));
        for (int pid = 100; pid < 200; pid++) { m.Observe(Start(pid, 1, "x.exe", pid)); m.Observe(Stop(pid, pid + 0.5)); }
        var s = m.Snapshot();

        Assert.True(s.Processes.Count <= 40);
        Assert.Contains(s.Processes, p => p.Name == "keeper.exe");
    }

    [Fact]
    public void The_per_file_event_list_is_bounded_and_keeps_the_ending()
    {
        var m = new ActivityModel(new ActivityModelOptions { MaxEventsPerFile = 6 });
        m.Observe(Start(100, 4, "a.exe", 0));
        for (int i = 0; i < 30; i++) m.Observe(Create(100, @"C:\x\f.bin", 10 + i * 3));
        m.Observe(Delete(100, @"C:\x\f.bin", 500));
        var f = m.Snapshot().Files.Single();

        Assert.True(f.Events.Count <= 6);
        Assert.Equal(FileOp.Deleted, f.Events.Last().Op);
    }

    // ================================================================ counts and scores

    [Fact]
    public void Counts_are_kept_per_second_and_per_kind_and_the_destinations_are_ranked()
    {
        var m = Feed(Start(100, 4, "a.exe", 0));
        m.Observe(new Signal { Kind = SignalKind.NetworkConnect, Pid = 100, RemoteAddress = "10.0.0.5", RemotePort = 443, TimestampUtc = T0.AddSeconds(1) });
        m.Observe(new Signal { Kind = SignalKind.NetworkConnect, Pid = 100, RemoteAddress = "10.0.0.5", RemotePort = 443, TimestampUtc = T0.AddSeconds(1.4) });
        m.Observe(new Signal { Kind = SignalKind.NetworkConnect, Pid = 100, RemoteAddress = "10.0.0.9", RemotePort = 80, TimestampUtc = T0.AddSeconds(3) });
        m.Observe(new Signal { Kind = SignalKind.DnsQuery, Pid = 100, Domain = "example.test", TimestampUtc = T0.AddSeconds(3) });
        var s = m.Snapshot();

        Assert.Equal(3, s.Total(ActivityKind.Network));
        var second = s.Series.Single(p => p.Counts[(int)ActivityKind.Network] == 2);
        Assert.Equal(2, second.Counts[(int)ActivityKind.Network]);
        Assert.Equal("10.0.0.5:443", s.Destinations[0].Name);
        Assert.Equal(2, s.Destinations[0].Count);
        Assert.Equal("example.test", s.Domains.Single().Name);
        Assert.Equal(T0, s.StartedUtc);
        Assert.Equal(T0.AddSeconds(3), s.EndedUtc);
    }

    [Fact]
    public void Engine_verdicts_colour_the_processes_they_describe()
    {
        var m = Feed(Start(100, 4, "bad.exe", 0), Start(200, 4, "calm.exe", 0), Start(300, 4, "signed.exe", 0));
        ProfileSnapshot Snap(int pid, int score, bool trusted = false, bool contained = false) => new()
        {
            Pid = pid, ProcessName = "p", ImagePath = "", Score = score, Trusted = trusted, Contained = contained, SuspendedByAnalyst = false,
            Terminated = false, Reasons = new[] { "reason one" }, StagedArchives = Array.Empty<string>(),
            FirstSeenUtc = T0, LastUpdatedUtc = T0, Techniques = new[] { "T1055" }
        };
        m.ApplyProfiles(new[] { Snap(100, 80), Snap(200, 30), Snap(300, 90, trusted: true) }, containAt: 70);
        var s = m.Snapshot();

        Assert.Equal("threat", Proc(s, 100).Level);
        Assert.Equal("watch", Proc(s, 200).Level);
        Assert.Equal("safe", Proc(s, 300).Level);
        Assert.Equal(new[] { "T1055" }, Proc(s, 100).Techniques);
        Assert.True(Proc(s, 100).Flagged);
    }

    [Fact]
    public void A_snapshot_is_cached_until_the_model_changes()
    {
        var m = Feed(Start(100, 4, "a.exe", 0));
        var a = m.Snapshot();
        Assert.Same(a, m.Snapshot());
        long v = m.Version;
        m.Observe(Start(101, 100, "b.exe", 1));

        Assert.NotEqual(v, m.Version);
        Assert.NotSame(a, m.Snapshot());
    }

    [Fact]
    public async Task Reading_while_the_host_writes_never_throws_or_tears()
    {
        var m = new ActivityModel(new ActivityModelOptions { MaxProcesses = 400, MaxFiles = 400 });
        using var stop = new CancellationTokenSource();
        var failures = new List<Exception>();
        var writer = Task.Run(() =>
        {
            try
            {
                for (int i = 1; i < 6000 && !stop.IsCancellationRequested; i++)
                {
                    m.Observe(Start(i, i > 1 ? i - 1 : 4, "p" + i + ".exe", i * 0.01));
                    m.Observe(Create(i, $@"C:\t\f{i}.bin", i * 0.01 + 0.001));
                    if (i % 3 == 0) m.Observe(Delete(i, $@"C:\t\f{i}.bin", i * 0.01 + 0.002));
                    if (i % 5 == 0) m.Observe(Stop(i, i * 0.01 + 0.003));
                }
            }
            catch (Exception ex) { lock (failures) failures.Add(ex); }
        });
        var readers = Enumerable.Range(0, 3).Select(_ => Task.Run(() =>
        {
            try { while (!writer.IsCompleted) { var s = m.Snapshot(); _ = s.Processes.Count + s.Files.Count; } }
            catch (Exception ex) { lock (failures) failures.Add(ex); }
        })).ToArray();
        await Task.WhenAll(readers.Append(writer)).WaitAsync(TimeSpan.FromSeconds(60));

        Assert.Empty(failures);
    }

    [Fact]
    public void A_directory_open_is_not_a_file_and_counts_for_nothing()
    {
        var s = Feed(Start(100, 4, "a.exe", 0), Create(100, @"C:\Users\u\Documents", 1, "dir")).Snapshot();

        Assert.Empty(s.Files);
        Assert.Equal(0, s.Total(ActivityKind.FileCreate) + s.Total(ActivityKind.FileOpen));
    }

    [Fact]
    public void A_temp_file_made_and_removed_by_the_same_process_within_moments_starts_hidden_as_churn()
    {
        const string Tmp = @"C:\Users\u\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\a.temp";
        const string Probe = @"C:\Users\u\AppData\Local\Temp\__PSScriptPolicyTest_x.ps1";
        const string Staged = @"C:\Users\u\AppData\Local\Temp\cache.zip";       // an interesting kind of file
        const string Slow = @"C:\Users\u\AppData\Local\Temp\note.tmp";          // kept for longer than a moment
        const string Elsewhere = @"C:\Users\u\Documents\note.tmp";              // not a temp area
        var s = Feed(
            Start(100, 4, "a.exe", 0),
            Create(100, Tmp, 1.0), Delete(100, Tmp, 1.2),
            Create(100, Probe, 1.0), Delete(100, Probe, 1.1),
            Create(100, Staged, 1.0), Delete(100, Staged, 1.2),
            Create(100, Slow, 1.0), Delete(100, Slow, 9.0),
            Create(100, Elsewhere, 1.0), Delete(100, Elsewhere, 1.2)).Snapshot();

        Assert.True(File(s, Tmp).Noisy);
        Assert.True(File(s, Probe).Noisy);
        Assert.False(File(s, Staged).Noisy);
        Assert.False(File(s, Slow).Noisy);
        Assert.False(File(s, Elsewhere).Noisy);
    }
}

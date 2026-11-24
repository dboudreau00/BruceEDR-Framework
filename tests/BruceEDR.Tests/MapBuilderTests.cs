using BruceEDR.Activity;
using BruceEDR.Core;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>The process map and file map: what each shows for a given set of activity, and where it puts it.</summary>
public sealed class MapBuilderTests
{
    private static readonly DateTime T0 = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
    private const string Payload = @"C:\Users\u\AppData\Local\Temp\payload.exe";

    private static Signal Start(int pid, int ppid, string name, double at, string? image = null)
        => new() { Kind = SignalKind.ProcessStart, Pid = pid, ParentPid = ppid, ProcessName = name, ImagePath = image ?? "", TimestampUtc = T0.AddSeconds(at) };
    private static Signal Stop(int pid, double at) => new() { Kind = SignalKind.ProcessStop, Pid = pid, TimestampUtc = T0.AddSeconds(at) };
    private static Signal Create(int pid, string path, double at)
        => new() { Kind = SignalKind.FileCreate, Pid = pid, FilePath = path, Detail = "create", TimestampUtc = T0.AddSeconds(at) };
    private static Signal Delete(int pid, string path, double at, string detail = "delete")
        => new() { Kind = SignalKind.FileDelete, Pid = pid, FilePath = path, Detail = detail, TimestampUtc = T0.AddSeconds(at) };
    private static Signal Rename(int pid, string from, string to, double at)
        => new() { Kind = SignalKind.FileRename, Pid = pid, FilePath = from, Detail = to, TimestampUtc = T0.AddSeconds(at) };

    private static ActivitySnapshot Snap(params Signal[] signals)
    {
        var m = new ActivityModel();
        foreach (var s in signals) m.Observe(s);
        return m.Snapshot();
    }

    private static ActivitySnapshot Flag(ActivitySnapshot snap, params (int Pid, string Level, int Score)[] marks)
        => snap with
        {
            Processes = snap.Processes.Select(p => marks.FirstOrDefault(m => m.Pid == p.Pid) is { Pid: > 0 } m ? p with { Level = m.Level, Score = m.Score } : p).ToList()
        };

    /// <summary>winword, cmd, powershell (flagged), a browser and ten of its renderers.</summary>
    private static ActivitySnapshot Scene()
    {
        var signals = new List<Signal>
        {
            Start(100, 0, "explorer.exe", 0), Start(200, 100, "winword.exe", 1), Start(201, 200, "cmd.exe", 2),
            Start(202, 201, "powershell.exe", 3), Start(300, 100, "chrome.exe", 1)
        };
        for (int i = 0; i < 12; i++) signals.Add(Start(400 + i, 300, "chrome.exe", 4 + i));
        return Flag(Snap(signals.ToArray()), (202, "threat", 85), (201, "watch", 30));
    }

    private static MapNode Find(MapNode root, string label) => root.Walk(includeHidden: true).First(n => n.Label == label);

    // ================================================================ process map

    [Fact]
    public void The_flagged_view_shows_what_was_flagged_with_its_ancestors_and_nothing_else()
    {
        var r = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.Flagged });
        var names = r.Root.Walk(includeHidden: true).Where(n => n.Kind == MapKind.Process).Select(n => n.Label).ToList();

        Assert.Contains("powershell.exe", names);
        Assert.Contains("cmd.exe", names);
        Assert.Contains("winword.exe", names);
        Assert.Contains("explorer.exe", names);
        Assert.DoesNotContain("chrome.exe", names);
        Assert.Equal("", r.Note);
        Assert.Equal("explorer.exe", r.Root.Children.Single().Label);
    }

    [Fact]
    public void With_nothing_flagged_the_view_says_so_and_shows_every_process()
    {
        var snap = Snap(Start(1, 0, "a.exe", 0), Start(2, 1, "b.exe", 1));
        var r = ProcessMapBuilder.Build(snap);

        Assert.Equal(2, r.Shown);
        Assert.Contains("Nothing is flagged", r.Note);
    }

    [Fact]
    public void A_process_that_made_a_melted_file_counts_as_flagged_though_the_engine_scored_nothing()
    {
        var snap = Snap(
            Start(100, 0, "dropper.exe", 0), Create(100, Payload, 1),
            Start(200, 100, "payload.exe", 2, Payload), Delete(200, Payload, 5, "on-close"),
            Start(900, 0, "notepad.exe", 0));
        var names = ProcessMapBuilder.Build(snap).Root.Walk(includeHidden: true).Where(n => n.Kind == MapKind.Process).Select(n => n.Label).ToList();

        Assert.Contains("dropper.exe", names);
        Assert.Contains("payload.exe", names);
        Assert.DoesNotContain("notepad.exe", names);
    }

    [Fact]
    public void The_live_view_drops_what_has_exited_but_keeps_the_ancestors_of_what_remains()
    {
        var snap = Snap(Start(1, 0, "parent.exe", 0), Start(2, 1, "gone.exe", 1), Stop(2, 3), Start(3, 1, "child.exe", 4), Stop(1, 5));
        var names = ProcessMapBuilder.Build(snap, new ProcessMapOptions { Filter = ProcessFilter.Live }).Root
            .Walk(includeHidden: true).Where(n => n.Kind == MapKind.Process).Select(n => n.Label).ToList();

        Assert.Equal(new[] { "child.exe", "parent.exe" }, names.OrderBy(n => n));
    }

    [Fact]
    public void Search_shows_the_matches_with_their_ancestors_and_descendants()
    {
        var r = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All, Search = "winword" });
        var names = r.Root.Walk(includeHidden: true).Where(n => n.Kind == MapKind.Process).Select(n => n.Label).ToList();

        Assert.Equal(new[] { "cmd.exe", "explorer.exe", "powershell.exe", "winword.exe" }, names.OrderBy(n => n));
        Assert.Contains("No process matches", ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Search = "zzz" }).Note);
    }

    [Fact]
    public void Search_by_pid_matches_only_that_pid()
    {
        var r = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All, Search = "201" });

        Assert.Contains(r.Root.Walk(includeHidden: true), n => n.Label == "cmd.exe");
    }

    [Fact]
    public void The_scrubber_shows_the_tree_as_it_stood_at_that_moment()
    {
        var snap = Snap(Start(1, 0, "a.exe", 0), Start(2, 1, "b.exe", 10), Stop(2, 20), Start(3, 1, "c.exe", 30));
        var at15 = ProcessMapBuilder.Build(snap, new ProcessMapOptions { Filter = ProcessFilter.All, AtUtc = T0.AddSeconds(15) });
        var names = at15.Root.Walk(includeHidden: true).Where(n => n.Kind == MapKind.Process).Select(n => n.Label).ToList();

        Assert.Equal(new[] { "a.exe", "b.exe" }, names.OrderBy(n => n));
    }

    [Fact]
    public void A_wide_branch_starts_collapsed_unless_something_flagged_is_under_it()
    {
        var all = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All });
        Assert.True(Find(all.Root, "explorer.exe").Collapsed == false);
        var browser = all.Root.Walk(includeHidden: true).First(n => n.Label == "chrome.exe" && n.Children.Count == 12);
        Assert.True(browser.Collapsed);

        var snap = Flag(Scene(), (405, "threat", 90));
        var flagged = ProcessMapBuilder.Build(snap, new ProcessMapOptions { Filter = ProcessFilter.All });
        Assert.False(flagged.Root.Walk(includeHidden: true).First(n => n.Label == "chrome.exe" && n.Children.Count == 12).Collapsed);
    }

    [Fact]
    public void The_user_can_open_and_close_branches_over_the_automatic_choice()
    {
        var key = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All }).Root.Walk(includeHidden: true)
            .First(n => n.Label == "chrome.exe" && n.Children.Count == 12).Key;

        var open = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All, Expanded = new HashSet<string> { key } });
        Assert.False(open.Root.Walk(includeHidden: true).First(n => n.Key == key).Collapsed);

        var shut = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All, Collapsed = new HashSet<string> { ProcessMapBuilder.KeyOf(1) } });
        Assert.True(shut.Root.Walk(includeHidden: true).First(n => n.Key == ProcessMapBuilder.KeyOf(1)).Collapsed);
    }

    [Fact]
    public void An_oversized_tree_is_cut_to_the_budget_and_says_so()
    {
        var signals = new List<Signal> { Start(1, 0, "root.exe", 0) };
        for (int i = 2; i < 200; i++) signals.Add(Start(i, i - 1, "p" + i + ".exe", i));
        var r = ProcessMapBuilder.Build(Snap(signals.ToArray()), new ProcessMapOptions { Filter = ProcessFilter.All, MaxNodes = 50 });

        Assert.True(r.Root.Count() - 1 <= 50);
        Assert.Contains("Showing 50 of", r.Note);
    }

    [Fact]
    public void An_exited_process_is_faded_and_a_flagged_one_carries_its_score()
    {
        var snap = Flag(Snap(Start(1, 0, "a.exe", 0), Stop(1, 5), Start(2, 0, "b.exe", 0)), (2, "threat", 77));
        var r = ProcessMapBuilder.Build(snap, new ProcessMapOptions { Filter = ProcessFilter.All });

        Assert.True(Find(r.Root, "a.exe").Ghost);
        Assert.Contains("ran 5 s", Find(r.Root, "a.exe").Sub);
        Assert.Equal("77", Find(r.Root, "b.exe").Badge);
        Assert.Equal("threat", Find(r.Root, "b.exe").Level);
    }

    // ================================================================ layout

    private static (double, double) Box(MapNode n) => (120, 30);

    [Fact]
    public void The_tree_layout_puts_each_depth_in_its_own_column_and_centres_a_parent_on_its_children()
    {
        var r = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All });
        var bounds = MapLayout.Tree(r.Root, Box);

        foreach (var n in r.Root.Walk())
            foreach (var c in n.Shown) Assert.True(c.X > n.X, "a child sits to the right of its parent");
        foreach (var n in r.Root.Walk().Where(n => n.Shown.Count > 0))
            Assert.Equal((n.Shown[0].Y + n.Shown[^1].Y) / 2, n.Y, 6);
        Assert.True(bounds.Width > 0 && bounds.Height > 0);
    }

    [Fact]
    public void No_two_visible_nodes_overlap_in_either_layout()
    {
        var r = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All, AutoCollapseOver = 100 });
        foreach (var layout in new Func<MapNode, Func<MapNode, (double, double)>, MapBounds>[] { MapLayout.Tree, MapLayout.Outline, MapLayout.Radial })
        {
            layout(r.Root, Box);
            var nodes = r.Root.Walk().ToList();
            for (int i = 0; i < nodes.Count; i++)
                for (int j = i + 1; j < nodes.Count; j++)
                {
                    bool apart = Math.Abs(nodes[i].X - nodes[j].X) >= (nodes[i].Width + nodes[j].Width) / 2 - 0.01 ||
                                 Math.Abs(nodes[i].Y - nodes[j].Y) >= (nodes[i].Height + nodes[j].Height) / 2 - 0.01;
                    Assert.True(apart, $"{nodes[i].Label} overlaps {nodes[j].Label}");
                }
        }
    }

    private static MapNode RandomTree(Random rng, int size)
    {
        var root = new MapNode { Key = "root", Kind = MapKind.Root };
        var all = new List<MapNode> { root };
        for (int i = 1; i < size; i++)
        {
            // Mostly bushy, sometimes a long chain: both shapes a process tree really has.
            var parent = rng.Next(4) == 0 ? all[^1] : all[rng.Next(all.Count)];
            all.Add(parent.Add(new MapNode { Key = "n" + i, Kind = MapKind.Process, Label = "n" + i }));
        }
        return root;
    }

    [Fact]
    public void No_layout_ever_overlaps_two_nodes_whatever_the_tree_looks_like()
    {
        var rng = new Random(20261114);
        foreach (var shape in Enum.GetValues<MapShape>())
            for (int trial = 0; trial < 40; trial++)
            {
                var root = RandomTree(rng, 2 + rng.Next(70));
                var sizes = new Dictionary<string, (double, double)>();
                (double, double) Sized(MapNode n) => sizes.TryGetValue(n.Key, out var s) ? s : sizes[n.Key] = (110 + rng.Next(190), n.Kind == MapKind.Root ? 50 : 36);
                MapLayout.Arrange(shape, root, Sized);

                var nodes = root.Walk().ToList();
                for (int i = 0; i < nodes.Count; i++)
                    for (int j = i + 1; j < nodes.Count; j++)
                    {
                        bool apart = Math.Abs(nodes[i].X - nodes[j].X) >= (nodes[i].Width + nodes[j].Width) / 2 - 0.01 ||
                                     Math.Abs(nodes[i].Y - nodes[j].Y) >= (nodes[i].Height + nodes[j].Height) / 2 - 0.01;
                        Assert.True(apart, $"{shape}, trial {trial}: {nodes[i].Key} overlaps {nodes[j].Key}");
                    }
            }
    }

    [Fact]
    public void A_long_chain_goes_straight_out_in_the_radial_layout_instead_of_spiralling_far_away()
    {
        var root = new MapNode { Key = "root", Kind = MapKind.Root };
        var tip = root;
        for (int i = 1; i <= 8; i++) tip = tip.Add(new MapNode { Key = "c" + i, Kind = MapKind.Process });
        var bounds = MapLayout.Radial(root, n => (n.Kind == MapKind.Root ? 150 : 220, 36));

        // Eight levels of 220-wide boxes would be over 1,800 across if the chain ran sideways; running up or down
        // it costs a row or so per level.
        Assert.True(Math.Max(bounds.Width, bounds.Height) < 900, $"the chain took {bounds.Width:0} x {bounds.Height:0}");
    }

    [Fact]
    public void The_outline_gives_every_node_its_own_row_and_steps_in_once_per_level()
    {
        var r = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All, AutoCollapseOver = 100 });
        var bounds = MapLayout.Outline(r.Root, Box);
        var nodes = r.Root.Walk().ToList();

        Assert.Equal(nodes.Count, nodes.Select(n => n.Y).Distinct().Count());
        foreach (var n in nodes)
        {
            Assert.Equal(n.Depth * MapLayout.Indent, n.X - n.Width / 2, 6);
            if (n.Parent is { } p) Assert.True(n.Y > p.Y, "a child sits below its parent");
        }
        // A deep chain costs rows, not width: the widest level is the deepest one plus its own box.
        Assert.Equal(nodes.Max(n => n.Depth) * MapLayout.Indent + 120, bounds.Width, 6);
    }

    [Fact]
    public void Arrange_picks_the_layout_for_the_shape()
    {
        var r = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All, AutoCollapseOver = 100 });

        var flow = MapLayout.Arrange(MapShape.Flow, r.Root, Box);
        var outline = MapLayout.Arrange(MapShape.Outline, r.Root, Box);
        var radial = MapLayout.Arrange(MapShape.Radial, r.Root, Box);

        Assert.True(outline.Width < flow.Width, "an outline is narrower than the same tree laid out left to right");
        Assert.True(radial.Left < 0 && radial.Right > 0, "a radial map is centred on the root");
    }

    [Fact]
    public void The_radial_layout_keeps_a_ring_per_depth_and_puts_the_root_at_the_centre()
    {
        var r = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All, AutoCollapseOver = 100 });
        MapLayout.Radial(r.Root, Box);

        Assert.Equal(0, r.Root.X, 6);
        Assert.Equal(0, r.Root.Y, 6);
        foreach (var group in r.Root.Walk().Where(n => n.Depth > 0).GroupBy(n => n.Depth))
        {
            var radii = group.Select(n => Math.Sqrt(n.X * n.X + n.Y * n.Y)).ToList();
            Assert.True(radii.Max() - radii.Min() < 0.001, "every node of a depth is on one ring");
        }
    }

    [Fact]
    public void A_collapsed_node_hides_its_children_from_the_layout_and_counts_them()
    {
        var r = ProcessMapBuilder.Build(Scene(), new ProcessMapOptions { Filter = ProcessFilter.All });
        MapLayout.Tree(r.Root, Box);
        var browser = r.Root.Walk(includeHidden: true).First(n => n.Label == "chrome.exe" && n.Children.Count == 12);

        Assert.True(browser.Collapsed);
        Assert.Equal(12, browser.Hidden);
        Assert.DoesNotContain(r.Root.Walk(), n => n.Parent == browser);
    }

    // ================================================================ file map

    /// <summary>One melted, one ran-then-deleted, one dropped, one deleted, one renamed, one created, one cache file.</summary>
    private static ActivitySnapshot FileScene()
    {
        const string Cache = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Cache\f_001";
        return Snap(
            Start(10, 0, "explorer.exe", 0, @"C:\Windows\explorer.exe"),
            Start(100, 10, "dropper.exe", 1), Create(100, Payload, 2),
            Start(200, 100, "payload.exe", 3, Payload), Delete(200, Payload, 8, "on-close"),
            Create(100, @"C:\Users\u\AppData\Local\Temp\tool.exe", 4),
            Start(210, 10, "tool.exe", 5, @"C:\Users\u\AppData\Local\Temp\tool.exe"), Stop(210, 6),
            Delete(10, @"C:\Users\u\AppData\Local\Temp\tool.exe", 20),
            Create(100, @"C:\Users\u\AppData\Local\Temp\loader.dll", 4.5),
            Start(220, 100, "loader.dll", 5.5, @"C:\Users\u\AppData\Local\Temp\loader.dll"),
            Create(100, @"C:\Users\u\Documents\old.txt", 6), Delete(100, @"C:\Users\u\Documents\old.txt", 7),
            Rename(100, @"C:\Users\u\Documents\a.docx", @"C:\Users\u\Documents\a.docx.locked", 9),
            Create(100, @"C:\Users\u\Documents\new.txt", 10),
            Create(100, Cache, 11), Delete(100, Cache, 12));
    }

    private static List<string> Groups(MapResult r) => r.Root.Children.Select(c => c.Label).ToList();

    [Fact]
    public void Files_are_grouped_by_what_happened_to_them_melted_first()
    {
        var r = FileMapBuilder.Build(FileScene(), new FileMapOptions { Filter = FileFilter.All });

        Assert.Equal(new[] { "Melted", "Ran, then deleted", "Created, then run", "Deleted", "Renamed or moved", "Created" }, Groups(r));
        Assert.Equal("ember", r.Root.Children[0].Level);
        Assert.Equal("payload.exe", r.Root.Children[0].Children.Single().Label);
        Assert.True(r.Root.Children[0].Children.Single().Melt);
    }

    [Fact]
    public void Cache_churn_is_hidden_until_asked_for()
    {
        var hidden = FileMapBuilder.Build(FileScene(), new FileMapOptions { Filter = FileFilter.All });
        var shown = FileMapBuilder.Build(FileScene(), new FileMapOptions { Filter = FileFilter.All, ShowNoise = true });

        Assert.DoesNotContain(hidden.Root.Walk(includeHidden: true), n => n.Label == "f_001");
        Assert.Contains(shown.Root.Walk(includeHidden: true), n => n.Label == "f_001");
        Assert.Equal(1, FileMapBuilder.Count(FileScene()).Noisy);
    }

    [Fact]
    public void The_default_filter_leaves_out_plain_creations()
    {
        var r = FileMapBuilder.Build(FileScene());

        Assert.DoesNotContain("Created", Groups(r));
        Assert.Contains("Melted", Groups(r));
    }

    [Fact]
    public void A_filter_shows_only_the_chosen_kinds_and_search_narrows_by_path()
    {
        var only = FileMapBuilder.Build(FileScene(), new FileMapOptions { Filter = FileFilter.Melted });
        Assert.Equal(new[] { "Melted" }, Groups(only));

        var search = FileMapBuilder.Build(FileScene(), new FileMapOptions { Filter = FileFilter.All, Search = "documents" });
        Assert.All(search.Root.Walk().Where(n => n.Kind == MapKind.File), n => Assert.Contains("Documents", ((FileTrail)n.Tag!).Path));
    }

    [Fact]
    public void A_deleted_file_is_struck_through_and_faded_but_a_melted_one_is_not()
    {
        var r = FileMapBuilder.Build(FileScene(), new FileMapOptions { Filter = FileFilter.All });
        var deleted = r.Root.Walk().First(n => n.Label == "old.txt");
        var melted = r.Root.Walk().First(n => n.Label == "payload.exe");

        Assert.True(deleted.Strike);
        Assert.True(deleted.Ghost);
        Assert.False(melted.Strike);
        Assert.Contains("melted by payload.exe", melted.Sub);
    }

    [Fact]
    public void Grouping_by_process_puts_a_file_under_the_program_that_ran_or_removed_it()
    {
        var r = FileMapBuilder.Build(FileScene(), new FileMapOptions { Filter = FileFilter.All, GroupBy = FileGroupBy.Process });
        var payload = r.Root.Children.First(g => g.Children.Any(c => c.Label == "payload.exe"));

        Assert.Equal("payload.exe", payload.Label);
        Assert.Equal(r.Root.Children[0], payload);   // the one with a melted file comes first
        Assert.Contains("pid 200", payload.Sub);
    }

    [Fact]
    public void Grouping_by_folder_names_the_folder_and_orders_melted_folders_first()
    {
        var r = FileMapBuilder.Build(FileScene(), new FileMapOptions { Filter = FileFilter.All, GroupBy = FileGroupBy.Folder });

        Assert.Equal(@"C:\Users\u\AppData\Local\Temp", (string)r.Root.Children[0].Tag!);
        Assert.StartsWith("…\\", r.Root.Children[0].Label);
    }

    [Fact]
    public void A_group_over_the_limit_shows_a_more_node_until_opened()
    {
        var m = new ActivityModel();
        m.Observe(Start(1, 0, "a.exe", 0));
        for (int i = 0; i < 40; i++) { m.Observe(Create(1, $@"C:\x\f{i}.bin", 1 + i * 3)); m.Observe(Delete(1, $@"C:\x\f{i}.bin", 2 + i * 3)); }
        var snap = m.Snapshot();

        var closed = FileMapBuilder.Build(snap, new FileMapOptions { MaxPerGroup = 10 });
        var group = closed.Root.Children.Single();
        Assert.Equal(11, group.Children.Count);
        Assert.Equal(MapKind.More, group.Children[^1].Kind);
        Assert.Equal("+30 more", group.Children[^1].Label);

        var open = FileMapBuilder.Build(snap, new FileMapOptions { MaxPerGroup = 10, Expanded = new HashSet<string> { group.Key } });
        Assert.Equal(40, open.Root.Children.Single().Children.Count);
    }

    [Fact]
    public void Focusing_on_a_process_keeps_only_the_files_it_touched()
    {
        var snap = FileScene();
        int payloadId = snap.Processes.Single(p => p.Name == "payload.exe").Id;
        var r = FileMapBuilder.Build(snap, new FileMapOptions { Filter = FileFilter.All, FocusProcessId = payloadId });

        Assert.Equal("payload.exe", r.Root.Walk().Single(n => n.Kind == MapKind.File).Label);
    }

    [Fact]
    public void The_counts_match_what_the_groups_show()
    {
        var c = FileMapBuilder.Count(FileScene());

        Assert.Equal(1, c.Melted);
        Assert.Equal(1, c.AfterRun);
        Assert.Equal(1, c.Dropped);
        Assert.Equal(1, c.Renamed);
        Assert.Equal(2, c.Created);   // new.txt, and a.docx.locked, the name a.docx moved to
        Assert.Equal(1, c.Deleted);
        Assert.Equal(7, c.Total);
    }

    [Fact]
    public void A_files_story_reads_in_order_with_who_did_what()
    {
        var snap = FileScene();
        var f = snap.Files.Single(x => x.Path == Payload);
        var lines = FileStory.Lines(f, snap.Processes);

        Assert.Equal(3, lines.Count);
        Assert.StartsWith("Created by dropper.exe", lines[0].Text);
        Assert.StartsWith("Run as payload.exe", lines[1].Text);
        Assert.StartsWith("Deleted by payload.exe", lines[2].Text);
        Assert.Equal("ember", lines[2].Level);
        Assert.True(lines.Zip(lines.Skip(1)).All(p => p.First.AtUtc <= p.Second.AtUtc));
    }

    [Fact]
    public void A_watcher_delete_says_it_cannot_name_the_process()
    {
        var snap = Snap(Create(0, @"C:\x\loot.zip", 1), Delete(0, @"C:\x\loot.zip", 2));
        var lines = FileStory.Lines(snap.Files.Single(), snap.Processes);

        Assert.Contains(lines, l => l.Text.Contains("folder watcher cannot say who"));
    }

    // ================================================================ cycles, caps and layout speed

    private static MapResult BuildWithin(Func<MapResult> build)
    {
        var task = Task.Run(build);
        Assert.True(task.Wait(TimeSpan.FromSeconds(10)), "the build did not finish: it is stuck in a loop");
        return task.Result;
    }

    [Fact]
    public void A_late_start_event_cannot_make_two_processes_each_others_parent()
    {
        // pid 1 is seen working before it is seen starting; pid 2 starts under it; then pid 1's own start names pid 2 as its parent.
        var snap = Snap(Create(1, @"C:\w\a.bin", 0), Start(2, 1, "child.exe", 1), Start(1, 2, "late.exe", 2));

        var byId = snap.Processes.ToDictionary(p => p.Id);
        foreach (var p in snap.Processes)
        {
            var seen = new HashSet<int>();
            for (var up = p; up.ParentId != 0 && byId.TryGetValue(up.ParentId, out var parent); up = parent)
                Assert.True(seen.Add(up.Id), "the parent chain loops");
        }
        var r = BuildWithin(() => ProcessMapBuilder.Build(snap, new ProcessMapOptions { Filter = ProcessFilter.All }));
        Assert.Equal(snap.Processes.Count, r.Shown);
    }

    [Fact]
    public void A_trace_from_disk_with_a_parent_loop_still_builds()
    {
        var snap = Snap(Start(1, 0, "a.exe", 0), Start(2, 1, "b.exe", 1), Start(3, 2, "c.exe", 2));
        int idA = snap.Processes.First(p => p.Pid == 1).Id, idC = snap.Processes.First(p => p.Pid == 3).Id;
        var looped = snap with { Processes = snap.Processes.Select(p => p.Pid == 1 ? p with { ParentId = idC } : p).ToList() };

        foreach (var filter in new[] { ProcessFilter.All, ProcessFilter.Live, ProcessFilter.Flagged })
        {
            var r = BuildWithin(() => ProcessMapBuilder.Build(looped, new ProcessMapOptions { Filter = filter }));
            Assert.True(r.Root.Count() <= looped.Processes.Count + 1);   // no node is counted twice
        }
        var searched = BuildWithin(() => ProcessMapBuilder.Build(looped, new ProcessMapOptions { Search = "a.exe" }));
        Assert.True(searched.Shown >= 1);
        Assert.NotEqual(0, idA);
    }

    [Fact]
    public void An_opened_group_stops_at_the_cap_and_still_says_how_many_are_left()
    {
        var signals = Enumerable.Range(0, 1200).Select(i => Create(0, $@"C:\work\drop\f{i}.bin", i * 0.01)).ToArray();
        var snap = Snap(signals);
        string key = "g:Created";
        var opts = new FileMapOptions { Filter = FileFilter.All, Expanded = new HashSet<string> { key } };

        var group = FileMapBuilder.Build(snap, opts).Root.Children.Single(g => g.Key == key);
        var files = group.Children.Where(c => c.Kind == MapKind.File).ToList();
        var more = group.Children.Single(c => c.Kind == MapKind.More);

        Assert.True(snap.Files.Count >= 1000, $"setup made only {snap.Files.Count} files");
        Assert.Equal(FileMapBuilder.MaxExpandedGroupItems, files.Count);
        Assert.Equal($"+{snap.Files.Count - FileMapBuilder.MaxExpandedGroupItems} more", more.Label);
    }

    [Fact]
    public void The_radial_layout_of_five_hundred_nodes_is_quick()
    {
        var root = new MapNode { Key = "root", Kind = MapKind.Root, Label = "root" };
        for (int g = 0; g < 25; g++)
        {
            var parent = root.Add(new MapNode { Key = "g" + g, Kind = MapKind.Group, Label = "group " + g });
            for (int i = 0; i < 20; i++) parent.Add(new MapNode { Key = $"f{g}_{i}", Kind = MapKind.File, Label = $"file {g}.{i}" });
        }
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var bounds = MapLayout.Radial(root, n => (n.Kind == MapKind.Root ? 150 : 120, 36));
        sw.Stop();

        Assert.True(bounds.Width > 0 && bounds.Height > 0);
        Assert.True(sw.ElapsedMilliseconds < 250, $"radial layout took {sw.ElapsedMilliseconds} ms");
    }
}
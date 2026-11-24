namespace BruceEDR.Activity;

public enum MapKind { Root, Process, Group, File, More }

/// <summary>One node of a mind map, with no WPF in it so the builders and the layouts can be tested.
/// The canvas draws these; <see cref="X"/> and <see cref="Y"/> are the centre, set by <see cref="MapLayout"/>.</summary>
public sealed class MapNode
{
    public string Key { get; init; } = "";
    public MapKind Kind { get; init; }
    public string Label { get; set; } = "";
    public string Sub { get; set; } = "";
    /// <summary>One to three characters drawn in the node's disc: a process's initial, a file's extension.</summary>
    public string Mark { get; set; } = "";
    /// <summary>
    /// The colour: processes use threat | watch | safe | info; files use ember (melted) | watch (ran then
    /// deleted) | drop | deleted | renamed | created; groups take the strongest of their children.
    /// </summary>
    public string Level { get; set; } = "info";
    /// <summary>Exited, or deleted: drawn faded.</summary>
    public bool Ghost { get; set; }
    /// <summary>A melted file: drawn dripping.</summary>
    public bool Melt { get; set; }
    public bool Strike { get; set; }
    /// <summary>Small text on the right of the node: a score, or the count a collapsed branch is hiding.</summary>
    public string Badge { get; set; } = "";
    public object? Tag { get; set; }
    public MapNode? Parent { get; private set; }
    public List<MapNode> Children { get; } = new();
    public bool Collapsed { get; set; }

    /// <summary>Descendants left out of the drawing because this node is collapsed.</summary>
    public int Hidden { get; internal set; }
    public int Depth { get; internal set; }
    /// <summary>Radial layout: where on the circle, in radians.</summary>
    public double Angle { get; internal set; }

    // layout output
    public double X { get; internal set; }
    public double Y { get; internal set; }
    public double Width { get; internal set; }
    public double Height { get; internal set; }

    public MapNode Add(MapNode child)
    {
        child.Parent = this;
        Children.Add(child);
        return child;
    }

    /// <summary>Visible children: none while collapsed.</summary>
    public IReadOnlyList<MapNode> Shown => Collapsed ? Array.Empty<MapNode>() : Children;

    public int Count()
    {
        int n = 1;
        foreach (var c in Children) n += c.Count();
        return n;
    }

    public IEnumerable<MapNode> Walk(bool includeHidden = false)
    {
        yield return this;
        foreach (var c in includeHidden ? Children : Shown)
            foreach (var d in c.Walk(includeHidden)) yield return d;
    }
}

public readonly record struct MapBounds(double Left, double Top, double Right, double Bottom)
{
    public double Width => Right - Left;
    public double Height => Bottom - Top;
    public static MapBounds Empty => new(0, 0, 0, 0);
}

/// <summary>Flow runs left to right like an org chart, Outline is one row per node with each level
/// indented (a chain of eight processes stays as narrow as one), Radial is the mind map.</summary>
public enum MapShape { Flow, Outline, Radial }

/// <summary>
/// Places the nodes of a map. Three shapes (see <see cref="MapShape"/>). All lay out only the
/// visible nodes (a collapsed node's children are left out) and all are deterministic.
/// </summary>
public static class MapLayout
{
    public const double ColumnGap = 64;
    public const double RowGap = 12;
    /// <summary>How far each level of an outline steps in, and how far a child's disc sits from its parent's.</summary>
    public const double Indent = 40;
    public const double OutlineRowGap = 10;
    /// <summary>Where a parent's connector leaves an outline row: the centre of its disc.</summary>
    public const double OutlineTrunk = 22;

    public static MapBounds Arrange(MapShape shape, MapNode root, Func<MapNode, (double Width, double Height)> measure) => shape switch
    {
        MapShape.Outline => Outline(root, measure),
        MapShape.Radial => Radial(root, measure),
        _ => Tree(root, measure)
    };

    public static MapBounds Outline(MapNode root, Func<MapNode, (double Width, double Height)> measure)
    {
        Prepare(root, 0, measure, new List<double>());
        double cursor = 0;
        Place(root);
        return Bounds(root);

        void Place(MapNode n)
        {
            n.X = n.Depth * Indent + n.Width / 2;
            n.Y = cursor + n.Height / 2;
            cursor += n.Height + OutlineRowGap;
            foreach (var c in n.Shown) Place(c);
        }
    }

    public static MapBounds Tree(MapNode root, Func<MapNode, (double Width, double Height)> measure)
    {
        var levels = new List<double>();
        Prepare(root, 0, measure, levels);

        var x = new double[levels.Count];
        double at = 0;
        for (int d = 0; d < levels.Count; d++) { x[d] = at; at += levels[d] + ColumnGap; }

        double cursor = 0;
        Place(root);
        return Bounds(root);

        void Place(MapNode n)
        {
            n.X = x[n.Depth] + levels[n.Depth] / 2;
            if (n.Shown.Count == 0)
            {
                n.Y = cursor + n.Height / 2;
                cursor += n.Height + RowGap;
                return;
            }
            foreach (var c in n.Shown) Place(c);
            n.Y = (n.Shown[0].Y + n.Shown[^1].Y) / 2;
        }
    }

    public static MapBounds Radial(MapNode root, Func<MapNode, (double Width, double Height)> measure)
    {
        var widths = new List<double>();
        Prepare(root, 0, measure, widths);
        var nodes = root.Walk().ToList();
        var rings = Enumerable.Range(0, widths.Count).Select(d => nodes.Where(n => n.Depth == d).ToList()).ToList();
        var maxW = rings.Select(r => r.Max(n => n.Width)).ToArray();
        var maxH = rings.Select(r => r.Max(n => n.Height)).ToArray();

        // A subtree gets a slice of the circle in proportion to its leaves. How far out each ring then sits comes
        // from the boxes themselves: two nodes clear each other when they are far enough apart across OR down,
        // so a ring needs a wide circle only where its neighbours run side by side (near the top and bottom) and
        // a small one where they stack (near the left and right). Which way the map is turned decides how much
        // of the ring is which, so it is tried at several angles and the tightest one is kept.
        var leaves = new Dictionary<MapNode, int>();
        Count(root);

        double[] best = Array.Empty<double>();
        double bestPhase = 0;
        for (double phase = 0; phase <= Math.PI + 1e-9; phase += Math.PI / 16)
        {
            var radii = Radii(phase);
            if (best.Length == 0 || radii[^1] < best[^1] - 1e-6) { best = radii; bestPhase = phase; }
        }
        Assign(root, bestPhase, bestPhase + 2 * Math.PI);
        var radius = best;

        // The ring maths looks at neighbours on a ring and at the ray out to the ring before; a node on another
        // ring at a slant can still clip, so any overlap left is cured by opening the circle a little at a time.
        for (int tries = 0; tries < 16; tries++)
        {
            foreach (var n in nodes)
            {
                n.X = radius[n.Depth] * Math.Cos(n.Angle);
                n.Y = radius[n.Depth] * Math.Sin(n.Angle);
            }
            if (nodes.Count > 1500 || !Overlaps(nodes)) break;
            for (int d = 1; d < radius.Length; d++) radius[d] *= 1.12;
        }
        return Bounds(root);

        double[] Radii(double phase)
        {
            Assign(root, phase, phase + 2 * Math.PI);
            var r = new double[rings.Count];
            for (int d = 1; d < rings.Count; d++)
            {
                var ring = rings[d];   // already in walk order, which is angle order: no sorting per try
                double sw = (maxW[d - 1] + maxW[d]) / 2 + 28, sh = (maxH[d - 1] + maxH[d]) / 2 + 22;
                double step = 0;
                foreach (var n in ring)
                {
                    double c = Math.Abs(Math.Cos(n.Angle)), s = Math.Abs(Math.Sin(n.Angle));
                    step = Math.Max(step, Math.Min(c > 1e-6 ? sw / c : double.MaxValue, s > 1e-6 ? sh / s : double.MaxValue));
                }
                double need = 0;
                for (int i = 0; i < ring.Count; i++)
                    for (int k = 1; k <= 2 && k < ring.Count; k++)
                    {
                        var a = ring[i]; var b = ring[(i + k) % ring.Count];
                        double ax = Math.Abs(Math.Cos(a.Angle) - Math.Cos(b.Angle)), ay = Math.Abs(Math.Sin(a.Angle) - Math.Sin(b.Angle));
                        if (ax < 1e-9 && ay < 1e-9) continue;
                        double w = (a.Width + b.Width) / 2 + 14, h = (a.Height + b.Height) / 2 + 10;
                        need = Math.Max(need, Math.Min(ax > 1e-9 ? w / ax : double.MaxValue, ay > 1e-9 ? h / ay : double.MaxValue));
                    }
                r[d] = Math.Max(r[d - 1] + step, need);
            }
            return r;
        }

        int Count(MapNode n)
        {
            int l = n.Shown.Count == 0 ? 1 : n.Shown.Sum(Count);
            leaves[n] = l;
            return l;
        }

        void Assign(MapNode n, double from, double to)
        {
            n.Angle = (from + to) / 2;
            if (n.Shown.Count == 0) return;
            double span = to - from, total = leaves[n], a = from;
            foreach (var c in n.Shown)
            {
                double part = span * leaves[c] / total;
                Assign(c, a, a + part);
                a += part;
            }
        }
    }

    /// <summary>Sweep over the nodes sorted by left edge: a node only needs checking against those that start before its right edge.</summary>
    private static bool Overlaps(IReadOnlyList<MapNode> nodes)
    {
        var sorted = nodes.OrderBy(n => n.X - n.Width / 2).ToArray();
        for (int i = 0; i < sorted.Length; i++)
        {
            var a = sorted[i];
            double aRight = a.X + a.Width / 2;
            for (int j = i + 1; j < sorted.Length; j++)
            {
                var b = sorted[j];
                if (b.X - b.Width / 2 >= aRight + 2) break;
                if (Math.Abs(a.X - b.X) < (a.Width + b.Width) / 2 + 2 &&
                    Math.Abs(a.Y - b.Y) < (a.Height + b.Height) / 2 + 2)
                    return true;
            }
        }
        return false;
    }

    private static void Prepare(MapNode n, int depth, Func<MapNode, (double Width, double Height)> measure, List<double> widths)
    {
        n.Depth = depth;
        n.Hidden = n.Collapsed ? n.Children.Sum(c => c.Count()) : 0;   // before measuring: the badge shows it
        var (w, h) = measure(n);
        n.Width = w;
        n.Height = h;
        while (widths.Count <= depth) widths.Add(0);
        if (w > widths[depth]) widths[depth] = w;
        foreach (var c in n.Shown) Prepare(c, depth + 1, measure, widths);
    }

    public static MapBounds Bounds(MapNode root)
    {
        double l = double.MaxValue, t = double.MaxValue, r = double.MinValue, b = double.MinValue;
        foreach (var n in root.Walk())
        {
            l = Math.Min(l, n.X - n.Width / 2); r = Math.Max(r, n.X + n.Width / 2);
            t = Math.Min(t, n.Y - n.Height / 2); b = Math.Max(b, n.Y + n.Height / 2);
        }
        return l > r ? MapBounds.Empty : new MapBounds(l, t, r, b);
    }
}

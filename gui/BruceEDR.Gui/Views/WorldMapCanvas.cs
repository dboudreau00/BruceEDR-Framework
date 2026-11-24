using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using BruceEDR.Analysis;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui.Views;

/// <summary>
/// World map (Miller projection) drawn straight to the visual layer.
///
/// Deliberately NOT an ItemsControl over 288 Polylines: the outline is static, redrawn only
/// on resize, and pushing it through the layout system would cost hundreds of visuals and a
/// full measure/arrange pass on every window drag. Markers, arcs and the threat pulse are
/// drawn in the same pass, so a hover or a pulse frame is one OnRender, not a layout pass.
/// </summary>
public sealed class WorldMapCanvas : FrameworkElement
{
    private static readonly Pen LandPen = Frozen(new Pen(Solid(0x33, 0x3E, 0x57), 1));
    private static readonly Brush LandFill = Solid(0x17, 0x1D, 0x2B);
    private static readonly Pen GridPen = Frozen(new Pen(Solid(0x13, 0x17, 0x23), 1));
    private static readonly Pen HighlightPen = Frozen(new Pen(Solid(0x7C, 0x6C, 0xFF), 1.5));
    private static readonly Brush Ocean = OceanBrush();

    private static readonly Color SafeC = Color.FromRgb(0x34, 0xD3, 0x99);
    private static readonly Color WatchC = Color.FromRgb(0xF2, 0xB3, 0x3D);
    private static readonly Color ThreatC = Color.FromRgb(0xF2, 0x55, 0x5A);
    private static readonly Color AccentC = Color.FromRgb(0x7C, 0x6C, 0xFF);

    private static readonly Dictionary<Color, MarkerInk> Inks = new()
    {
        [SafeC] = new MarkerInk(SafeC),
        [WatchC] = new MarkerInk(WatchC),
        [ThreatC] = new MarkerInk(ThreatC),
    };

    private Geometry? _land;
    private Size _landFor;
    private Rect _map;

    // Miller cylindrical: conformal enough to read, and about 1.36:1 rather than 2:1, so a
    // dashboard-sized panel shows the world without stretching it.
    private static readonly double MillerMax = MillerY(90);
    private static readonly double Aspect = 2 * Math.PI / (2 * MillerMax);

    private static double MillerY(double latDeg)
    {
        double phi = Math.Clamp(latDeg, -89.9, 89.9) * Math.PI / 180;
        return 1.25 * Math.Log(Math.Tan(Math.PI / 4 + 0.4 * phi));
    }

    private static Rect Fit(double w, double h)
    {
        double mw = w, mh = w / Aspect;
        if (mh > h) { mh = h; mw = h * Aspect; }
        return new Rect((w - mw) / 2, (h - mh) / 2, mw, mh);
    }

    private static Point Project(Rect r, double lon, double lat)
        => new(r.X + (lon + 180) / 360 * r.Width,
               r.Y + (MillerMax - MillerY(lat)) / (2 * MillerMax) * r.Height);

    private static Pen Frozen(Pen p) { p.Freeze(); return p; }
    private static SolidColorBrush Solid(byte r, byte g, byte b) => Solid(Color.FromRgb(r, g, b));
    private static SolidColorBrush Solid(Color c)
    {
        var br = new SolidColorBrush(c);
        br.Freeze();
        return br;
    }

    private static Brush OceanBrush()
    {
        var b = new RadialGradientBrush(Color.FromArgb(0xFF, 0x0E, 0x13, 0x22), Color.FromArgb(0x00, 0x0E, 0x13, 0x22))
        {
            Center = new Point(0.5, 0.45),
            GradientOrigin = new Point(0.5, 0.45),
            RadiusX = 0.7,
            RadiusY = 0.8,
        };
        b.Freeze();
        return b;
    }

    /// <summary>Frozen brushes and pens for one marker colour, built once.</summary>
    private sealed class MarkerInk
    {
        public readonly Brush Core;
        public readonly Brush Disk;
        public readonly Brush Glow;
        public readonly Pen Dashed;
        public readonly Color Color;

        public MarkerInk(Color c)
        {
            Color = c;
            Core = Solid(c);
            Disk = Solid(Color.FromArgb(0x40, c.R, c.G, c.B));
            var glow = new RadialGradientBrush(Color.FromArgb(0x60, c.R, c.G, c.B), Color.FromArgb(0x00, c.R, c.G, c.B));
            glow.Freeze();
            Glow = glow;
            Dashed = Frozen(new Pen(Core, 1) { DashStyle = new DashStyle(new double[] { 2, 2 }, 0) });
        }
    }

    public static readonly DependencyProperty WorldProperty = DependencyProperty.Register(
        nameof(World), typeof(WorldMap), typeof(WorldMapCanvas),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnWorldChanged));

    public WorldMap? World
    {
        get => (WorldMap?)GetValue(WorldProperty);
        set => SetValue(WorldProperty, value);
    }

    public static readonly DependencyProperty MarkersProperty = DependencyProperty.Register(
        nameof(Markers), typeof(IEnumerable<MapMarker>), typeof(WorldMapCanvas),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnMarkersChanged));

    public IEnumerable<MapMarker>? Markers
    {
        get => (IEnumerable<MapMarker>?)GetValue(MarkersProperty);
        set => SetValue(MarkersProperty, value);
    }

    public static readonly DependencyProperty HomeProperty = DependencyProperty.Register(
        nameof(Home), typeof(MapHome), typeof(WorldMapCanvas),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>Where arcs start. Null draws markers only.</summary>
    public MapHome? Home
    {
        get => (MapHome?)GetValue(HomeProperty);
        set => SetValue(HomeProperty, value);
    }

    private static readonly DependencyProperty PulsePhaseProperty = DependencyProperty.Register(
        "PulsePhase", typeof(double), typeof(WorldMapCanvas),
        new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>Raised with the marker under the cursor, or null when it leaves one.</summary>
    public event Action<MapMarker?>? MarkerHovered;

    private bool _pulsing;

    public WorldMapCanvas()
    {
        ClipToBounds = true;
        IsVisibleChanged += (_, _) => UpdatePulse();
        Unloaded += (_, _) => StopPulse();
        Loaded += (_, _) => UpdatePulse();
    }

    private static void OnWorldChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var c = (WorldMapCanvas)d;
        c._land = null;
        c.InvalidateVisual();
    }

    private static void OnMarkersChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var c = (WorldMapCanvas)d;
        if (e.OldValue is INotifyCollectionChanged oldCol) oldCol.CollectionChanged -= c.OnMarkersCollectionChanged;
        if (e.NewValue is INotifyCollectionChanged newCol) newCol.CollectionChanged += c.OnMarkersCollectionChanged;
        c.Unsubscribe(c._subscribed.ToList());
        c.Subscribe(e.NewValue as IEnumerable<MapMarker>);
        c.UpdatePulse();
        c.InvalidateVisual();
    }

    private void OnMarkersCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Reset)
            Unsubscribe(_subscribed.ToList());   // Clear() reports no OldItems: drop every handler we hold
        else
            Unsubscribe(e.OldItems?.OfType<MapMarker>());
        Subscribe(e.NewItems?.OfType<MapMarker>());
        UpdatePulse();
        InvalidateVisual();
    }

    private readonly List<MapMarker> _subscribed = new();

    // Markers mutate in place across refreshes (that is what keeps a hover alive), so the
    // canvas listens to each one rather than only to the collection.
    private void Subscribe(IEnumerable<MapMarker>? markers)
    {
        if (markers is null) return;
        foreach (var m in markers)
        {
            if (_subscribed.Contains(m)) continue;
            m.PropertyChanged += OnMarkerPropertyChanged;
            _subscribed.Add(m);
        }
    }

    private void Unsubscribe(IEnumerable<MapMarker>? markers)
    {
        if (markers is null) return;
        foreach (var m in markers.ToList())
        {
            m.PropertyChanged -= OnMarkerPropertyChanged;
            _subscribed.Remove(m);
        }
    }

    private void OnMarkerPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        // X and Y are written by OnRender itself; reacting to them would loop.
        if (e.PropertyName is nameof(MapMarker.X) or nameof(MapMarker.Y)) return;
        if (e.PropertyName == nameof(MapMarker.Severity)) UpdatePulse();
        InvalidateVisual();
    }

    /// <summary>The pulse runs only while a threat is on screen; an idle map costs nothing.</summary>
    private void UpdatePulse()
    {
        bool want = IsVisible && IsLoaded && (Markers?.Any(m => m.Severity == "threat") ?? false);
        if (want == _pulsing) return;
        if (want)
        {
            _pulsing = true;
            var anim = new DoubleAnimation(0, 1, TimeSpan.FromSeconds(2.4)) { RepeatBehavior = RepeatBehavior.Forever };
            Timeline.SetDesiredFrameRate(anim, 30);
            BeginAnimation(PulsePhaseProperty, anim);
        }
        else StopPulse();
    }

    private void StopPulse()
    {
        _pulsing = false;
        BeginAnimation(PulsePhaseProperty, null);
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 0 || h <= 0) return;

        // A FrameworkElement is only hit-testable where it actually drew something, so the
        // transparent backdrop is what makes hover work across the whole map.
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
        dc.DrawRectangle(Ocean, null, new Rect(0, 0, w, h));

        _map = Fit(w, h);
        DrawGraticule(dc, _map);

        if (World is { IsLoaded: true } world)
        {
            if (_land is null || _landFor != new Size(w, h))
            {
                _land = BuildLand(world, _map);
                _landFor = new Size(w, h);
            }
            dc.DrawGeometry(LandFill, LandPen, _land);
        }

        var markers = Markers?.ToArray() ?? Array.Empty<MapMarker>();
        foreach (var m in markers)
        {
            var p = Project(_map, m.Longitude, m.Latitude);
            if (Math.Abs(m.X - p.X) > 0.01) m.X = p.X;
            if (Math.Abs(m.Y - p.Y) > 0.01) m.Y = p.Y;
        }

        var home = Home;
        Point? homePt = null;
        if (home is not null)
        {
            homePt = Project(_map, home.Longitude, home.Latitude);
            foreach (var m in markers) DrawArc(dc, homePt.Value, m);
        }

        double phase = (double)GetValue(PulsePhaseProperty);
        foreach (var m in markers.OrderBy(m => m.IsHighlighted).ThenBy(m => Rank(m.Severity)))
            DrawMarker(dc, m, phase);

        if (homePt is { } hp) DrawHome(dc, hp, home!);

        bool few = markers.Length <= 12;
        foreach (var m in markers.Where(m => few || m.IsHighlighted || m.Severity == "threat" || m.Radius >= 7))
        {
            // The home label already names the home country.
            if (home is not null && string.Equals(m.CountryCode, home.CountryCode, StringComparison.OrdinalIgnoreCase)) continue;
            DrawLabel(dc, m, w);
        }
    }

    private static int Rank(string severity) => severity switch { "threat" => 2, "watch" => 1, _ => 0 };

    private static MarkerInk InkFor(string severity) => severity switch
    {
        "threat" => Inks[ThreatC],
        "watch" => Inks[WatchC],
        _ => Inks[SafeC],
    };

    private static void DrawArc(DrawingContext dc, Point from, MapMarker m)
    {
        var to = new Point(m.X, m.Y);
        double dx = to.X - from.X, dy = to.Y - from.Y;
        double dist = Math.Sqrt(dx * dx + dy * dy);
        if (dist < 6) return;

        // Lift the control point off the straight line so routes read as arcs, always bowing
        // toward the top of the map, the way great-circle routes look on this projection.
        var mid = new Point((from.X + to.X) / 2, (from.Y + to.Y) / 2);
        double nx = -dy / dist, ny = dx / dist;
        if (ny > 0) { nx = -nx; ny = -ny; }
        var ctrl = new Point(mid.X + nx * dist * 0.22, mid.Y + ny * dist * 0.22);

        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(from, false, false);
            ctx.QuadraticBezierTo(ctrl, to, true, true);
        }
        g.Freeze();

        var c = InkFor(m.Severity).Color;
        byte alpha = m.IsHighlighted ? (byte)0xD0 : m.Severity == "threat" ? (byte)0x80 : (byte)0x48;
        var pen = new Pen(new SolidColorBrush(Color.FromArgb(alpha, c.R, c.G, c.B)), m.IsHighlighted ? 1.8 : 1.1);
        pen.Freeze();
        dc.DrawGeometry(null, pen, g);
    }

    private static void DrawMarker(DrawingContext dc, MapMarker m, double phase)
    {
        var p = new Point(m.X, m.Y);
        var ink = InkFor(m.Severity);
        double r = m.Radius;

        dc.DrawEllipse(ink.Glow, null, p, r * 2.4, r * 2.4);

        if (m.Severity == "threat")
        {
            double pr = r + 3 + phase * 16;
            var c = ink.Color;
            var pulse = new Pen(new SolidColorBrush(Color.FromArgb((byte)(0xB0 * (1 - phase)), c.R, c.G, c.B)), 1.5);
            pulse.Freeze();
            dc.DrawEllipse(null, pulse, p, pr, pr);
        }

        if (m.IsHighlighted)
            dc.DrawEllipse(null, HighlightPen, p, r + 6, r + 6);

        dc.DrawEllipse(ink.Disk, null, p, r, r);
        double core = Math.Max(2.5, r * 0.45);
        dc.DrawEllipse(ink.Core, null, p, core, core);

        // Plaintext HTTP gets a dashed ring: the one property here an analyst should be able
        // to spot without hovering anything.
        if (m.HasPlaintext)
            dc.DrawEllipse(null, ink.Dashed, p, r + 3, r + 3);
    }

    private void DrawHome(DrawingContext dc, Point p, MapHome home)
    {
        var accent = Solid(AccentC);
        var ring = Frozen(new Pen(Solid(Color.FromArgb(0xA0, AccentC.R, AccentC.G, AccentC.B)), 1.2));
        dc.DrawEllipse(Solid(Color.FromArgb(0x30, AccentC.R, AccentC.G, AccentC.B)), ring, p, 7, 7);
        dc.DrawEllipse(accent, null, p, 3, 3);
        var label = Text($"{home.CountryCode} (region setting)", Solid(Color.FromRgb(0x99, 0xA2, 0xB8)));
        dc.DrawText(label, new Point(p.X + 10, p.Y + 4));
    }

    private void DrawLabel(DrawingContext dc, MapMarker m, double w)
    {
        var fg = m.IsHighlighted ? Solid(Color.FromRgb(0xE8, 0xEC, 0xF5)) : Solid(Color.FromRgb(0x99, 0xA2, 0xB8));
        var t = Text(m.CountryCode, fg);
        double x = m.X + m.Radius + 5;
        if (x + t.Width > w - 2) x = m.X - m.Radius - 5 - t.Width;
        var bg = new Rect(x - 3, m.Y - t.Height / 2 - 1, t.Width + 6, t.Height + 2);
        dc.DrawRoundedRectangle(Solid(Color.FromArgb(0xC0, 0x0B, 0x0E, 0x18)), null, bg, 3, 3);
        dc.DrawText(t, new Point(x, m.Y - t.Height / 2));
    }

    private FormattedText Text(string s, Brush fg)
    {
        var family = TryFindResource("Font.Data") as FontFamily ?? new FontFamily("Consolas");
        return new FormattedText(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            new Typeface(family, FontStyles.Normal, FontWeights.Medium, FontStretches.Normal),
            9.5, fg, VisualTreeHelper.GetDpi(this).PixelsPerDip);
    }

    private static void DrawGraticule(DrawingContext dc, Rect r)
    {
        for (int lon = -150; lon <= 150; lon += 30)
        {
            double x = Math.Round(Project(r, lon, 0).X) + 0.5;
            dc.DrawLine(GridPen, new Point(x, r.Top), new Point(x, r.Bottom));
        }
        for (int lat = -60; lat <= 60; lat += 30)
        {
            double y = Math.Round(Project(r, 0, lat).Y) + 0.5;
            dc.DrawLine(GridPen, new Point(r.Left, y), new Point(r.Right, y));
        }
    }

    private static Geometry BuildLand(WorldMap world, Rect r)
    {
        var group = new StreamGeometry { FillRule = FillRule.EvenOdd };
        using (var ctx = group.Open())
        {
            foreach (var ring in world.Rings)
            {
                if (ring.Points.Count < 3) continue;
                ctx.BeginFigure(Project(r, ring.Points[0].Lon, ring.Points[0].Lat), isFilled: true, isClosed: true);
                for (int i = 1; i < ring.Points.Count; i++)
                {
                    ctx.LineTo(Project(r, ring.Points[i].Lon, ring.Points[i].Lat), isStroked: true, isSmoothJoin: false);
                }
            }
        }
        group.Freeze();
        return group;
    }

    // ------------------------------------------------------------------ hover

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var hit = HitTestMarker(e.GetPosition(this));
        if (!ReferenceEquals(hit, _hovered))
        {
            _hovered = hit;
            ToolTip = hit?.Tooltip;
            Cursor = hit is null ? null : Cursors.Hand;
            MarkerHovered?.Invoke(hit);
        }
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        if (_hovered is null) return;
        _hovered = null;
        ToolTip = null;
        Cursor = null;
        MarkerHovered?.Invoke(null);
    }

    private MapMarker? _hovered;

    /// <summary>
    /// Nearest marker within its own radius (plus a few px of slop, because a 4px dot is
    /// hard to hit). Nearest-wins so overlapping markers resolve predictably.
    /// </summary>
    private MapMarker? HitTestMarker(Point p)
    {
        MapMarker? best = null;
        double bestDist = double.MaxValue;
        foreach (var m in Markers ?? Enumerable.Empty<MapMarker>())
        {
            double dx = p.X - m.X, dy = p.Y - m.Y;
            double d2 = dx * dx + dy * dy;
            double r = m.Radius + 4;
            if (d2 <= r * r && d2 < bestDist) { bestDist = d2; best = m; }
        }
        return best;
    }

    protected override void OnRenderSizeChanged(SizeChangedInfo info)
    {
        base.OnRenderSizeChanged(info);
        _land = null;
        InvalidateVisual();
    }
}

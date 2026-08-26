using System.Collections.Specialized;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using BruceEDR.Analysis;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui.Views;

/// <summary>
/// Equirectangular world map drawn straight to the visual layer.
///
/// Deliberately NOT an ItemsControl over 288 Polylines: the outline is static, redrawn only
/// on resize, and pushing it through the layout system would cost hundreds of visuals and a
/// full measure/arrange pass on every window drag. Markers are drawn in the same pass, so a
/// hover repaint is one OnRender, not a layout invalidation.
/// </summary>
public sealed class WorldMapCanvas : FrameworkElement
{
    // Landmasses are filled a shade above the sea and outlined a shade above that. At this
    // simplification level a bare stroke reads as noise; the fill is what makes the shape
    // legible at dashboard size.
    private static readonly Pen LandPen = Frozen(new Pen(new SolidColorBrush(Color.FromRgb(0x33, 0x3E, 0x57)), 1));
    private static readonly Brush LandFill = FrozenBrush(0x18, 0x1E, 0x2C);
    private static readonly Pen GridPen = Frozen(new Pen(new SolidColorBrush(Color.FromRgb(0x14, 0x18, 0x24)), 1));
    private static readonly Pen HighlightPen = Frozen(new Pen(new SolidColorBrush(Color.FromRgb(0x7C, 0x6C, 0xFF)), 1.5));

    private static readonly Brush Safe = FrozenBrush(0x34, 0xD3, 0x99);
    private static readonly Brush Watch = FrozenBrush(0xF2, 0xB3, 0x3D);
    private static readonly Brush Threat = FrozenBrush(0xF2, 0x55, 0x5A);

    private Geometry? _land;
    private Size _landFor;

    private static Pen Frozen(Pen p) { p.Freeze(); return p; }
    private static Brush FrozenBrush(byte r, byte g, byte b)
    {
        var br = new SolidColorBrush(Color.FromRgb(r, g, b));
        br.Freeze();
        return br;
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

    /// <summary>Raised with the marker under the cursor, or null when it leaves one.</summary>
    public event Action<MapMarker?>? MarkerHovered;

    public WorldMapCanvas() => ClipToBounds = true;

    private static void OnWorldChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var c = (WorldMapCanvas)d;
        c._land = null;                    // force a re-project on the next render
        c.InvalidateVisual();
    }

    private static void OnMarkersChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var c = (WorldMapCanvas)d;
        if (e.OldValue is INotifyCollectionChanged oldCol) oldCol.CollectionChanged -= c.OnMarkersCollectionChanged;
        if (e.NewValue is INotifyCollectionChanged newCol) newCol.CollectionChanged += c.OnMarkersCollectionChanged;
        c.Unsubscribe(e.OldValue as IEnumerable<MapMarker>);
        c.Subscribe(e.NewValue as IEnumerable<MapMarker>);
        c.InvalidateVisual();
    }

    private void OnMarkersCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Unsubscribe(e.OldItems?.OfType<MapMarker>());
        Subscribe(e.NewItems?.OfType<MapMarker>());
        InvalidateVisual();
    }

    // Markers mutate in place across refreshes (that is what keeps a hover alive), so the
    // canvas listens to each one rather than only to the collection.
    private void Subscribe(IEnumerable<MapMarker>? markers)
    {
        if (markers is null) return;
        foreach (var m in markers) m.PropertyChanged += OnMarkerPropertyChanged;
    }

    private void Unsubscribe(IEnumerable<MapMarker>? markers)
    {
        if (markers is null) return;
        foreach (var m in markers) m.PropertyChanged -= OnMarkerPropertyChanged;
    }

    private void OnMarkerPropertyChanged(object? sender, PropertyChangedEventArgs e) => InvalidateVisual();

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 0 || h <= 0) return;

        // A FrameworkElement is only hit-testable where it actually drew something, so the
        // transparent backdrop is what makes hover work across the whole map.
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));

        DrawGraticule(dc, w, h);

        if (World is { IsLoaded: true } world)
        {
            if (_land is null || _landFor != new Size(w, h))
            {
                _land = BuildLand(world, w, h);
                _landFor = new Size(w, h);
            }
            dc.DrawGeometry(LandFill, LandPen, _land);
        }

        var markers = Markers?.ToArray() ?? Array.Empty<MapMarker>();
        foreach (var m in markers)
        {
            var (x, y) = WorldMap.Project(m.Longitude, m.Latitude, w, h);
            m.X = x;
            m.Y = y;

            var brush = m.Severity switch
            {
                "threat" => Threat,
                "watch" => Watch,
                _ => Safe,
            };

            // Halo first, so it sits under every marker rather than over its neighbours.
            if (m.IsHighlighted)
                dc.DrawEllipse(null, HighlightPen, new Point(x, y), m.Radius + 6, m.Radius + 6);

            dc.DrawEllipse(Dim(brush), null, new Point(x, y), m.Radius, m.Radius);
            dc.DrawEllipse(brush, null, new Point(x, y), Math.Max(2.5, m.Radius * 0.42), Math.Max(2.5, m.Radius * 0.42));

            // Plaintext HTTP gets a ring: it is the one property here an analyst should be
            // able to spot without hovering anything.
            if (m.HasPlaintext)
                dc.DrawEllipse(null, Frozen(new Pen(brush, 1) { DashStyle = new DashStyle(new double[] { 2, 2 }, 0) }),
                               new Point(x, y), m.Radius + 3, m.Radius + 3);
        }
    }

    /// <summary>Marker fill at ~22% so overlapping destinations stay individually readable.</summary>
    private static Brush Dim(Brush solid)
    {
        if (solid is not SolidColorBrush s) return solid;
        var b = new SolidColorBrush(Color.FromArgb(0x38, s.Color.R, s.Color.G, s.Color.B));
        b.Freeze();
        return b;
    }

    private static void DrawGraticule(DrawingContext dc, double w, double h)
    {
        for (int lon = -150; lon <= 150; lon += 30)
        {
            double x = Math.Round((lon + 180.0) / 360.0 * w) + 0.5;
            dc.DrawLine(GridPen, new Point(x, 0), new Point(x, h));
        }
        for (int lat = -60; lat <= 60; lat += 30)
        {
            double y = Math.Round((90.0 - lat) / 180.0 * h) + 0.5;
            dc.DrawLine(GridPen, new Point(0, y), new Point(w, y));
        }
        // The equator, one shade brighter, so the projection is legible as a projection.
        double eq = Math.Round(h / 2) + 0.5;
        dc.DrawLine(GridPen, new Point(0, eq), new Point(w, eq));
    }

    private static Geometry BuildLand(WorldMap world, double w, double h)
    {
        var group = new StreamGeometry { FillRule = FillRule.EvenOdd };
        using (var ctx = group.Open())
        {
            foreach (var ring in world.Rings)
            {
                if (ring.Points.Count < 3) continue;
                var (x0, y0) = WorldMap.Project(ring.Points[0].Lon, ring.Points[0].Lat, w, h);
                ctx.BeginFigure(new Point(x0, y0), isFilled: true, isClosed: true);
                for (int i = 1; i < ring.Points.Count; i++)
                {
                    var (x, y) = WorldMap.Project(ring.Points[i].Lon, ring.Points[i].Lat, w, h);
                    ctx.LineTo(new Point(x, y), isStroked: true, isSmoothJoin: false);
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
        var p = e.GetPosition(this);
        var hit = HitTestMarker(p);
        if (!ReferenceEquals(hit, _hovered))
        {
            _hovered = hit;
            ToolTip = hit?.Tooltip;
            MarkerHovered?.Invoke(hit);
        }
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        if (_hovered is null) return;
        _hovered = null;
        ToolTip = null;
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

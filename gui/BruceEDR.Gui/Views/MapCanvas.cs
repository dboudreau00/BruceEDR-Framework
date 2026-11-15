using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using BruceEDR.Activity;

namespace BruceEDR.Gui.Views;

public sealed record LegendItem(string Level, string Text);

/// <summary>
/// The surface the process map and the file map are drawn on: a mind map you can pan, zoom and fold,
/// as a flow, an outline or a radial map. Everything is drawn in one pass, like the world map, and frames are
/// requested only while something moves (the camera, a node arriving, a threat pulsing, a melted file
/// dripping), so a still map costs nothing.
///
/// What goes where is not decided here: <see cref="MapLayout"/> places the nodes and the view model
/// builds them. This only measures, draws and hit-tests.
/// </summary>
public sealed class MapCanvas : FrameworkElement
{
    // ---------------------------------------------------------------- properties

    public static readonly DependencyProperty RootProperty = DependencyProperty.Register(
        nameof(Root), typeof(MapNode), typeof(MapCanvas), new FrameworkPropertyMetadata(null, OnRootChanged));
    public static readonly DependencyProperty ShapeProperty = DependencyProperty.Register(
        nameof(Shape), typeof(MapShape), typeof(MapCanvas), new FrameworkPropertyMetadata(MapShape.Flow, OnLayoutChanged));
    public static readonly DependencyProperty SelectedKeyProperty = DependencyProperty.Register(
        nameof(SelectedKey), typeof(string), typeof(MapCanvas),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, (d, _) => ((MapCanvas)d).Redraw()));
    public static readonly DependencyProperty AnimateProperty = DependencyProperty.Register(
        nameof(Animate), typeof(bool), typeof(MapCanvas), new FrameworkPropertyMetadata(true, (d, _) => ((MapCanvas)d).WantFrames()));

    public MapNode? Root { get => (MapNode?)GetValue(RootProperty); set => SetValue(RootProperty, value); }
    public MapShape Shape { get => (MapShape)GetValue(ShapeProperty); set => SetValue(ShapeProperty, value); }
    public string? SelectedKey { get => (string?)GetValue(SelectedKeyProperty); set => SetValue(SelectedKeyProperty, value); }
    public bool Animate { get => (bool)GetValue(AnimateProperty); set => SetValue(AnimateProperty, value); }

    /// <summary>Longer text for the card shown on hover; null shows the node's own label and subtitle.</summary>
    public Func<MapNode, string?>? Describe { get; set; }

    /// <summary>A node was double-clicked: the view model folds or unfolds it.</summary>
    public event EventHandler<MapNode>? NodeActivated;

    // ---------------------------------------------------------------- palette

    private static readonly Color PaperC = Color.FromRgb(0xE8, 0xEC, 0xF5);
    private static readonly Color MistC = Color.FromRgb(0x99, 0xA2, 0xB8);
    private static readonly Color FaintC = Color.FromRgb(0x5C, 0x64, 0x79);
    private static readonly Color AccentC = Color.FromRgb(0x7C, 0x6C, 0xFF);

    private static readonly Brush Paper = Solid(PaperC);
    private static readonly Brush Mist = Solid(MistC);
    private static readonly Brush Faint = Solid(FaintC);
    /// <summary>Secondary text on a node: readable on the dark card, still quieter than the label.</summary>
    private static readonly Brush SubInk = Solid(Color.FromRgb(0x80, 0x89, 0xA0));
    private static readonly Brush Backdrop = Solid(Color.FromRgb(0x07, 0x09, 0x10));
    private static readonly Brush Vignette = RadialBrush(Color.FromArgb(0x00, 0, 0, 0), Color.FromArgb(0x66, 0, 0, 0), 0.55);
    private static readonly Brush Dot = Solid(Color.FromArgb(0x30, 0x6C, 0x78, 0x9A));
    private static readonly Brush CardFill = Solid(Color.FromArgb(0xF0, 0x0B, 0x0E, 0x18));
    private static readonly Pen CardPen = Frozen(new Pen(Solid(Color.FromRgb(0x2A, 0x31, 0x44)), 1));
    private static readonly Pen LinkPen = Frozen(new Pen(Solid(Color.FromRgb(0x37, 0x41, 0x5A)), 1.6) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
    private static readonly Pen SelectPen = Frozen(new Pen(Solid(AccentC), 2));
    private static readonly Pen HoverPen = Frozen(new Pen(Solid(Color.FromArgb(0xB0, PaperC.R, PaperC.G, PaperC.B)), 1.2));

    private sealed class Ink
    {
        public readonly Color Color;
        public readonly Brush Core, Soft, Glow, Disc;
        public readonly Pen Rim, RimGhost, Link, LinkGlow;

        public Ink(Color c)
        {
            Color = c;
            Core = Solid(c);
            Soft = Solid(Color.FromArgb(0x30, c.R, c.G, c.B));
            Disc = Solid(Color.FromArgb(0x42, c.R, c.G, c.B));
            Glow = RadialBrush(Color.FromArgb(0x70, c.R, c.G, c.B), Color.FromArgb(0x00, c.R, c.G, c.B), 0.5);
            Rim = Frozen(new Pen(Solid(Color.FromArgb(0xD0, c.R, c.G, c.B)), 1.4));
            RimGhost = Frozen(new Pen(Solid(Color.FromArgb(0x70, c.R, c.G, c.B)), 1.1) { DashStyle = new DashStyle(new double[] { 3, 3 }, 0) });
            Link = Frozen(new Pen(Solid(Color.FromArgb(0xB0, c.R, c.G, c.B)), 1.8) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
            LinkGlow = Frozen(new Pen(Solid(Color.FromArgb(0x2E, c.R, c.G, c.B)), 8) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
        }
    }

    private static readonly Dictionary<string, Ink> Inks = new()
    {
        ["threat"] = new(Color.FromRgb(0xF2, 0x55, 0x5A)),
        ["watch"] = new(Color.FromRgb(0xF2, 0xB3, 0x3D)),
        ["safe"] = new(Color.FromRgb(0x34, 0xD3, 0x99)),
        ["info"] = new(Color.FromRgb(0x4C, 0x8D, 0xFF)),
        ["ember"] = new(Color.FromRgb(0xFF, 0x8A, 0x3D)),
        ["drop"] = new(Color.FromRgb(0xA7, 0x8B, 0xFA)),
        ["deleted"] = new(Color.FromRgb(0x8A, 0x93, 0xA8)),
        ["renamed"] = new(Color.FromRgb(0x38, 0xBD, 0xF8)),
        ["created"] = new(Color.FromRgb(0x34, 0xD3, 0x99)),
        ["accent"] = new(AccentC)
    };

    private static Ink InkOf(string level) => Inks.TryGetValue(level, out var i) ? i : Inks["info"];
    private static bool Hot(string level) => level is "threat" or "ember";

    private static SolidColorBrush Solid(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }
    private static Pen Frozen(Pen p) { p.Freeze(); return p; }
    private static Brush RadialBrush(Color inner, Color outer, double radius)
    {
        var b = new RadialGradientBrush(inner, outer) { RadiusX = radius, RadiusY = radius };
        b.Freeze();
        return b;
    }

    // ---------------------------------------------------------------- state

    private sealed class Visual
    {
        public FormattedText Label = null!, Sub = null!, Badge = null!, Mark = null!;
        public double LabelWidth;
        public string Signature = "";
        public Rect Rect;           // world space, set by layout
        public double Born;         // seconds on the clock; the node fades in from here
    }

    private static readonly Stopwatch Clock = Stopwatch.StartNew();
    private readonly Dictionary<MapNode, Visual> _visuals = new();
    private readonly Dictionary<string, Visual> _texts = new();   // by node key: text objects are the costly part of a rebuild
    private readonly Dictionary<string, double> _born = new();
    private HashSet<string> _keys = new();
    private List<MapNode> _nodes = new();
    private List<(MapNode Parent, MapNode Child)> _links = new();
    private MapBounds _bounds = MapBounds.Empty;
    private bool _hasPulse;

    private double _scale = 1, _tx, _ty;
    private double _goalScale = 1, _goalTx, _goalTy;
    private bool _cameraMoving, _userMoved, _wholeMap;
    private Point _dragFrom;
    private bool _dragging, _moved;
    private MapNode? _hover;
    private Point _mouse;
    private string? _anchorKey;
    private Point _anchorScreen;
    private bool _hooked;
    private double _lastFrame;

    public MapCanvas()
    {
        ClipToBounds = true;
        Focusable = true;
        Cursor = Cursors.Arrow;
        SnapsToDevicePixels = false;
        Loaded += (_, _) => WantFrames();
        Unloaded += (_, _) => Unhook();
        IsVisibleChanged += (_, _) => WantFrames();
        SizeChanged += (_, _) => { if (!_userMoved) Reframe(animate: false); };
    }

    private static void OnRootChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) => ((MapCanvas)d).Rebuild();
    private static void OnLayoutChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var c = (MapCanvas)d;
        c._userMoved = false;
        c._wholeMap = false;
        c._born.Clear();
        c.Rebuild();
    }

    private void Redraw() => InvalidateVisual();

    // ---------------------------------------------------------------- build

    private FormattedText Text(string s, double size, Brush brush, bool bold = false, bool mono = false, double maxWidth = 0)
    {
        var ft = ChartInk.Text(this, s, size, brush, mono, bold ? FontWeights.SemiBold : FontWeights.Normal);
        if (maxWidth > 0)
        {
            ft.MaxTextWidth = maxWidth;
            ft.MaxLineCount = 1;
            ft.Trimming = TextTrimming.CharacterEllipsis;
        }
        return ft;
    }

    private (double, double) Measure(MapNode n)
    {
        string badgeText = n.Collapsed && n.Hidden > 0 ? "+" + n.Hidden : n.Badge;
        string sig = string.Join("|", n.Label, n.Sub, badgeText, n.Mark, n.Ghost, (int)n.Kind);
        var v = new Visual { Signature = sig };
        _visuals[n] = v;
        if (_texts.TryGetValue(n.Key, out var cached) && cached.Signature == sig)
        {
            v.Label = cached.Label; v.Sub = cached.Sub; v.Badge = cached.Badge; v.Mark = cached.Mark; v.LabelWidth = cached.LabelWidth;
        }
        else
        {
            double labelSize = n.Kind is MapKind.Root ? 14 : n.Kind == MapKind.Group ? 13.5 : 12.5;
            bool bold = n.Kind != MapKind.File && n.Kind != MapKind.More;
            v.Label = Text(n.Label, labelSize, n.Ghost ? Mist : Paper, bold, maxWidth: 230);
            v.Sub = Text(n.Sub, 10.5, SubInk, mono: true, maxWidth: 230);
            v.Badge = Text(badgeText, 10, Paper, bold: true, mono: true);
            v.Mark = Text(n.Mark, n.Mark.Length > 2 ? 8.5 : 11, Paper, bold: true, mono: n.Kind == MapKind.File);
            v.LabelWidth = Math.Max(v.Label.WidthIncludingTrailingWhitespace, v.Sub.WidthIncludingTrailingWhitespace);
            _texts[n.Key] = v;
        }

        bool badge = n.Collapsed && n.Hidden > 0 || n.Badge.Length > 0;
        double w = 14 + 26 + v.LabelWidth + (badge ? v.Badge.Width + 20 : 0) + 8;
        return n.Kind switch
        {
            MapKind.Root => (Math.Max(150, w), 50),
            MapKind.Group => (Math.Max(150, w), 42),
            _ => (Math.Max(112, Math.Min(300, w)), 36)
        };
    }

    private void Rebuild()
    {
        var root = Root;
        var previous = _keys;
        _nodes = new();
        _links = new();
        _hover = null;
        _visuals.Clear();
        if (root is null)
        {
            _texts.Clear();
            _keys = new();
            _bounds = MapBounds.Empty;
            Redraw();
            return;
        }

        _bounds = MapLayout.Arrange(Shape, root, Measure);
        _nodes = root.Walk().ToList();
        foreach (var n in _nodes)
        {
            if (n.Parent is { } p) _links.Add((p, n));
            _visuals[n].Rect = new Rect(n.X - n.Width / 2, n.Y - n.Height / 2, n.Width, n.Height);
        }
        var liveKeys = _nodes.Select(n => n.Key).ToHashSet();
        foreach (var gone in _texts.Keys.Where(k => !liveKeys.Contains(k)).ToList()) _texts.Remove(gone);

        _keys = _nodes.Select(n => n.Key).ToHashSet();
        double now = Clock.Elapsed.TotalSeconds;
        bool first = previous.Count == 0;
        var arrived = _keys.Where(k => !previous.Contains(k)).ToList();
        // The first drawing reveals the map outwards, a few arrivals fade in, a big change just replaces it.
        for (int i = 0; i < _nodes.Count; i++)
        {
            var n = _nodes[i];
            if (_born.TryGetValue(n.Key, out var b)) { _visuals[n].Born = b; continue; }
            double born = first ? now + n.Depth * 0.09 + Math.Min(0.5, i * 0.004)
                        : arrived.Count <= 60 ? now : now - 10;
            _born[n.Key] = born;
            _visuals[n].Born = born;
        }
        foreach (var gone in _born.Keys.Where(k => !_keys.Contains(k)).ToList()) _born.Remove(gone);

        _hasPulse = _nodes.Any(n => Hot(n.Level) && !n.Ghost);
        if (_anchorKey is not null && _nodes.FirstOrDefault(n => n.Key == _anchorKey) is { } anchor)
        {
            var r = _visuals[anchor].Rect;
            _tx = _anchorScreen.X - (r.X + r.Width / 2) * _scale;
            _ty = _anchorScreen.Y - (r.Y + r.Height / 2) * _scale;
            _goalScale = _scale; _goalTx = _tx; _goalTy = _ty;
            _userMoved = true;
        }
        _anchorKey = null;
        if (!_userMoved) Reframe(animate: !first && ActualWidth > 0 && _nodes.Count < 400);
        WantFrames();
        Redraw();
    }

    // ---------------------------------------------------------------- camera

    /// <summary>Below this the labels are too small to read, so the automatic framing stops shrinking.</summary>
    private const double ReadableScale = 0.72;
    private const double FitMargin = 56;

    /// <summary>Show the whole map, however small that makes it: the overview the Fit button asks for. It stays that way as the map changes.</summary>
    public void FitToView(bool animate = true)
    {
        _wholeMap = true;
        Frame(animate, readable: false);
    }

    /// <summary>
    /// The automatic framing. The whole map when it can be read at that size; otherwise a window on what
    /// matters (what is lit, the selection, and the path back to the root), so a long process chain or a
    /// big folder never opens as a smudge you have to zoom into.
    /// </summary>
    public void FocusView(bool animate = true)
    {
        _wholeMap = false;
        Frame(animate, readable: true);
    }

    /// <summary>The refit after the map or the window changed: whichever of the two the person last asked for.</summary>
    private void Reframe(bool animate) => Frame(animate, readable: !_wholeMap);

    private double FitScale(MapBounds b, double top, double bottom)
        => Math.Min((ActualWidth - 2 * FitMargin) / Math.Max(1, b.Width), (ActualHeight - top - bottom) / Math.Max(1, b.Height));

    private void Frame(bool animate, bool readable)
    {
        _userMoved = false;
        if (ActualWidth < 10 || ActualHeight < 10 || _bounds.Width <= 0) return;
        double top = FitMargin;
        double bottom = FitMargin;

        var box = _bounds;
        double scale = Math.Clamp(FitScale(box, top, bottom), 0.12, 1.15);
        bool windowed = readable && scale < ReadableScale;
        if (windowed)
        {
            // Stay at the smallest size that reads, so as much as possible is in view, and centre on what matters.
            scale = ReadableScale;
            var (lit, trail) = FocusBoxes();
            box = FitScale(trail, top, bottom) >= ReadableScale ? trail : lit;
        }

        double cx = (box.Left + box.Right) / 2, cy = (box.Top + box.Bottom) / 2;
        if (windowed)
        {
            // Never scroll past the edge of the map to do it.
            double viewW = (ActualWidth - 2 * FitMargin) / scale, viewH = (ActualHeight - top - bottom) / scale;
            cx = _bounds.Width > viewW ? Math.Clamp(cx, _bounds.Left + viewW / 2, _bounds.Right - viewW / 2) : (_bounds.Left + _bounds.Right) / 2;
            cy = _bounds.Height > viewH ? Math.Clamp(cy, _bounds.Top + viewH / 2, _bounds.Bottom - viewH / 2) : (_bounds.Top + _bounds.Bottom) / 2;
        }
        double midY = top + (ActualHeight - top - bottom) / 2;
        _goalScale = scale;
        _goalTx = ActualWidth / 2 - cx * scale;
        _goalTy = midY - cy * scale;
        if (!animate) { _scale = _goalScale; _tx = _goalTx; _ty = _goalTy; _cameraMoving = false; Redraw(); }
        else { _cameraMoving = true; WantFrames(); }
    }

    /// <summary>What is lit or selected, and the same with every ancestor added. With nothing lit, the first levels.</summary>
    private (MapBounds Lit, MapBounds Trail) FocusBoxes()
    {
        var lit = _nodes.Where(n => n.Kind is not (MapKind.Root or MapKind.Group or MapKind.More)
                                    && (Hot(n.Level) || n.Level == "watch" || n.Key == SelectedKey)).ToList();
        if (lit.Count == 0) lit = _nodes.Where(n => n.Depth <= 2).ToList();
        var trail = new HashSet<MapNode>(lit);
        foreach (var n in lit)
            for (var up = n.Parent; up is not null; up = up.Parent) trail.Add(up);
        return (Union(lit), Union(trail));
    }

    private MapBounds Union(IEnumerable<MapNode> nodes)
    {
        double l = double.MaxValue, t = double.MaxValue, r = double.MinValue, b = double.MinValue;
        foreach (var n in nodes)
        {
            var rect = _visuals[n].Rect;
            l = Math.Min(l, rect.Left); r = Math.Max(r, rect.Right);
            t = Math.Min(t, rect.Top); b = Math.Max(b, rect.Bottom);
        }
        return l > r ? _bounds : new MapBounds(l, t, r, b);
    }

    public void ZoomBy(double factor) => ZoomAt(new Point(ActualWidth / 2, ActualHeight / 2), factor);

    private void ZoomAt(Point screen, double factor)
    {
        double s = Math.Clamp(_scale * factor, 0.1, 3.2);
        factor = s / _scale;
        _tx = screen.X - (screen.X - _tx) * factor;
        _ty = screen.Y - (screen.Y - _ty) * factor;
        _scale = s;
        _goalScale = _scale; _goalTx = _tx; _goalTy = _ty;
        _cameraMoving = false;
        _userMoved = true;
        Redraw();
    }

    private Point ToWorld(Point screen) => new((screen.X - _tx) / _scale, (screen.Y - _ty) / _scale);

    private MapNode? HitTest(Point screen)
    {
        var w = ToWorld(screen);
        for (int i = _nodes.Count - 1; i >= 0; i--)
            if (_visuals.TryGetValue(_nodes[i], out var v) && v.Rect.Contains(w)) return _nodes[i];
        return null;
    }

    // ---------------------------------------------------------------- frames

    private bool NeedsFrames(double now)
    {
        if (!IsVisible || !IsLoaded) return false;
        if (_cameraMoving) return true;
        if (Animate && _hasPulse) return true;
        foreach (var v in _visuals.Values) if (now - v.Born < 0.6) return true;
        return false;
    }

    private void WantFrames()
    {
        if (_hooked || !IsLoaded) return;
        _hooked = true;
        CompositionTarget.Rendering += OnFrame;
    }

    private void Unhook()
    {
        if (!_hooked) return;
        _hooked = false;
        CompositionTarget.Rendering -= OnFrame;
    }

    private void OnFrame(object? sender, EventArgs e)
    {
        double now = Clock.Elapsed.TotalSeconds;
        if (now - _lastFrame < 1.0 / 32) return;
        double dt = Math.Min(0.1, now - _lastFrame);
        _lastFrame = now;
        if (_cameraMoving)
        {
            double k = 1 - Math.Pow(0.0008, dt);
            _scale += (_goalScale - _scale) * k;
            _tx += (_goalTx - _tx) * k;
            _ty += (_goalTy - _ty) * k;
            if (Math.Abs(_goalScale - _scale) < 0.0008 && Math.Abs(_goalTx - _tx) < 0.2 && Math.Abs(_goalTy - _ty) < 0.2)
            {
                _scale = _goalScale; _tx = _goalTx; _ty = _goalTy;
                _cameraMoving = false;
            }
        }
        InvalidateVisual();
        if (!NeedsFrames(now)) Unhook();
    }

    // ---------------------------------------------------------------- input

    protected override void OnMouseWheel(MouseWheelEventArgs e)
    {
        ZoomAt(e.GetPosition(this), Math.Pow(1.0016, e.Delta));
        e.Handled = true;
    }

    protected override void OnMouseDown(MouseButtonEventArgs e)
    {
        Focus();
        _mouse = e.GetPosition(this);
        if (e.ChangedButton is MouseButton.Left or MouseButton.Right or MouseButton.Middle)
        {
            if (e.ClickCount == 2 && e.ChangedButton == MouseButton.Left && HitTest(_mouse) is { } hit)
            {
                _anchorKey = hit.Key;
                var r = _visuals[hit].Rect;
                _anchorScreen = new Point((r.X + r.Width / 2) * _scale + _tx, (r.Y + r.Height / 2) * _scale + _ty);
                NodeActivated?.Invoke(this, hit);
                e.Handled = true;
                return;
            }
            _dragFrom = _mouse;
            _dragging = true;
            _moved = false;
            CaptureMouse();
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        _mouse = e.GetPosition(this);
        if (_dragging)
        {
            var d = _mouse - _dragFrom;
            if (!_moved && d.Length < 3) return;
            _moved = true;
            _tx += d.X; _ty += d.Y;
            _goalTx = _tx; _goalTy = _ty; _cameraMoving = false; _userMoved = true;
            _dragFrom = _mouse;
            Cursor = Cursors.SizeAll;
            Redraw();
            return;
        }
        var over = HitTest(_mouse);
        if (!ReferenceEquals(over, _hover))
        {
            _hover = over;
            Cursor = over is null ? Cursors.Arrow : Cursors.Hand;
        }
        Redraw();
    }

    protected override void OnMouseUp(MouseButtonEventArgs e)
    {
        if (!_dragging) return;
        _dragging = false;
        ReleaseMouseCapture();
        Cursor = _hover is null ? Cursors.Arrow : Cursors.Hand;
        if (!_moved && e.ChangedButton == MouseButton.Left)
            SelectedKey = HitTest(e.GetPosition(this))?.Key;
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        _hover = null;
        Redraw();
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.F: FitToView(); e.Handled = true; break;
            case Key.OemPlus or Key.Add: ZoomBy(1.25); e.Handled = true; break;
            case Key.OemMinus or Key.Subtract: ZoomBy(0.8); e.Handled = true; break;
        }
    }

    // ---------------------------------------------------------------- drawing

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w < 2 || h < 2) return;
        double now = Clock.Elapsed.TotalSeconds;
        dc.DrawRectangle(Backdrop, null, new Rect(0, 0, w, h));
        DrawGrid(dc, w, h);

        if (_nodes.Count > 0)
        {
            var view = new Rect(-_tx / _scale, -_ty / _scale, w / _scale, h / _scale);
            view.Inflate(60, 60);
            dc.PushTransform(new MatrixTransform(_scale, 0, 0, _scale, _tx, _ty));
            DrawLinks(dc, view, now);
            bool detail = _scale >= 0.34;
            foreach (var n in _nodes)
            {
                var v = _visuals[n];
                if (!v.Rect.IntersectsWith(view)) continue;
                DrawNode(dc, n, v, now, detail);
            }
            dc.Pop();
        }

        dc.DrawRectangle(Vignette, null, new Rect(0, 0, w, h));
        if (_hover is not null && !_dragging) DrawTip(dc, _hover, w, h);
    }

    private void DrawGrid(DrawingContext dc, double w, double h)
    {
        double step = 28 * Math.Clamp(_scale, 0.5, 2);
        if (step < 14) step *= 2;
        double ox = _tx % step, oy = _ty % step;
        for (double x = ox; x < w; x += step)
            for (double y = oy; y < h; y += step)
                dc.DrawRectangle(Dot, null, new Rect(x, y, 1.2, 1.2));
    }

    private static Point CubicAt(Point a, Point b, Point c, Point d, double t)
    {
        double u = 1 - t;
        double k0 = u * u * u, k1 = 3 * u * u * t, k2 = 3 * u * t * t, k3 = t * t * t;
        return new Point(k0 * a.X + k1 * b.X + k2 * c.X + k3 * d.X, k0 * a.Y + k1 * b.Y + k2 * c.Y + k3 * d.Y);
    }

    private (Point a, Point b, Point c, Point d) Curve(MapNode p, MapNode n)
    {
        if (Shape == MapShape.Outline)
        {
            // Down the parent's trunk, then a tight turn into the child's row.
            var a = new Point(p.X - p.Width / 2 + MapLayout.OutlineTrunk, p.Y + p.Height / 2 - 2);
            var d = new Point(n.X - n.Width / 2, n.Y);
            return (a, new Point(a.X, d.Y - 7), new Point(a.X + 7, d.Y), d);
        }
        if (Shape == MapShape.Flow)
        {
            var a = new Point(p.X + p.Width / 2 - 6, p.Y);
            var d = new Point(n.X - n.Width / 2 + 6, n.Y);
            double dx = Math.Max(30, (d.X - a.X) * 0.55);
            return (a, new Point(a.X + dx, a.Y), new Point(d.X - dx, d.Y), d);
        }
        else
        {
            var a = new Point(p.X, p.Y);
            var d = new Point(n.X, n.Y);
            double len = (d - a).Length;
            var pa = new Vector(Math.Cos(p.Angle), Math.Sin(p.Angle));
            var na = new Vector(Math.Cos(n.Angle), Math.Sin(n.Angle));
            var c1 = p.Depth == 0 ? a + (d - a) * 0.35 : a + pa * len * 0.42;
            return (a, c1, d - na * len * 0.42, d);
        }
    }

    private void DrawLinks(DrawingContext dc, Rect view, double now)
    {
        var plain = new StreamGeometry();
        var byInk = new Dictionary<Ink, StreamGeometryContext>();
        var geoms = new Dictionary<Ink, StreamGeometry>();
        using (var pc = plain.Open())
        {
            foreach (var (p, n) in _links)
            {
                var pr = _visuals[p].Rect; var nr = _visuals[n].Rect;
                if (!view.IntersectsWith(Rect.Union(pr, nr))) continue;
                var (a, b, c, d) = Curve(p, n);
                if (Hot(n.Level) || n.Level == "watch")
                {
                    var ink = InkOf(n.Level);
                    if (!geoms.TryGetValue(ink, out var g)) { g = new StreamGeometry(); geoms[ink] = g; byInk[ink] = g.Open(); }
                    byInk[ink].BeginFigure(a, false, false);
                    byInk[ink].BezierTo(b, c, d, true, true);
                }
                else
                {
                    pc.BeginFigure(a, false, false);
                    pc.BezierTo(b, c, d, true, true);
                }
            }
        }
        plain.Freeze();
        dc.DrawGeometry(null, LinkPen, plain);
        foreach (var (ink, ctx) in byInk)
        {
            ctx.Close();
            geoms[ink].Freeze();
            dc.DrawGeometry(null, ink.LinkGlow, geoms[ink]);
            dc.DrawGeometry(null, ink.Link, geoms[ink]);
        }

        if (!Animate || _scale < 0.3) return;
        // Little lights run down the links that lead to a threat.
        foreach (var (p, n) in _links)
        {
            if (!Hot(n.Level) || n.Ghost) continue;
            if (!view.IntersectsWith(Rect.Union(_visuals[p].Rect, _visuals[n].Rect))) continue;
            var (a, b, c, d) = Curve(p, n);
            var ink = InkOf(n.Level);
            for (int k = 0; k < 2; k++)
            {
                double t = (now * 0.42 + k * 0.5 + (n.Key.GetHashCode() & 0xFF) / 255.0) % 1.0;
                dc.DrawEllipse(ink.Core, null, CubicAt(a, b, c, d, t), 2.4, 2.4);
            }
        }
    }

    private void DrawNode(DrawingContext dc, MapNode n, Visual v, double now, bool detail)
    {
        var ink = InkOf(n.Kind is MapKind.Root ? "accent" : n.Level);
        var r = v.Rect;
        double age = now - v.Born;
        if (age < 0) return;
        double ease = age >= 0.45 ? 1 : 1 - Math.Pow(1 - age / 0.45, 3);
        double alpha = n.Ghost ? 0.78 * ease : ease;
        bool selected = n.Key == SelectedKey, hover = ReferenceEquals(n, _hover);
        double scaleIn = 0.86 + 0.14 * ease;

        dc.PushOpacity(alpha);
        if (scaleIn < 0.999) dc.PushTransform(new ScaleTransform(scaleIn, scaleIn, r.X + r.Width / 2, r.Y + r.Height / 2));

        if (!detail)
        {
            dc.DrawRoundedRectangle(ink.Core, null, r, 6, 6);
            if (scaleIn < 0.999) dc.Pop();
            dc.Pop();
            return;
        }

        bool hot = Hot(n.Level) && !n.Ghost;
        if (hot && n.Kind != MapKind.Group)
        {
            double pulse = Animate ? 0.55 + 0.45 * Math.Sin(now * 2.4 + (n.Key.GetHashCode() & 0xF)) : 0.8;
            var glow = new Rect(r.X - 26, r.Y - 22, r.Width + 52, r.Height + 44);
            dc.PushOpacity(0.35 + 0.4 * pulse);
            dc.DrawEllipse(ink.Glow, null, new Point(r.X + r.Width / 2, r.Y + r.Height / 2), glow.Width / 2, glow.Height / 2);
            dc.Pop();
        }

        if (n.Melt) DrawDrips(dc, r, now, ink);

        double radius = n.Kind == MapKind.Root ? 25 : n.Kind == MapKind.Group ? 13 : 10;
        var fill = new LinearGradientBrush(
            n.Kind is MapKind.Root or MapKind.Group
                ? Color.FromArgb(0xFF, (byte)(0x12 + ink.Color.R / 24), (byte)(0x14 + ink.Color.G / 24), (byte)(0x22 + ink.Color.B / 20))
                : Color.FromRgb(0x16, 0x1B, 0x2A),
            Color.FromRgb(0x0E, 0x12, 0x1E), 90);
        if (n.Melt) fill = new LinearGradientBrush(Color.FromRgb(0x2E, 0x1A, 0x12), Color.FromRgb(0x14, 0x10, 0x16), 90);
        fill.Freeze();

        // Calm nodes keep a neutral edge so the ones that matter are the ones with colour.
        bool calm = n.Kind switch
        {
            MapKind.Process => n.Level is not ("threat" or "watch"),
            MapKind.File => n.Level is "created" or "deleted" or "renamed",
            _ => false
        };
        Pen border = selected ? SelectPen
            : n.Ghost || n.Kind == MapKind.More ? ink.RimGhost
            : calm ? CardPen
            : ink.Rim;
        dc.DrawRoundedRectangle(fill, hover && !selected ? HoverPen : border, r, radius, radius);
        if (selected)
            dc.DrawRoundedRectangle(null, new Pen(Solid(Color.FromArgb(0x55, AccentC.R, AccentC.G, AccentC.B)), 6), new Rect(r.X - 3, r.Y - 3, r.Width + 6, r.Height + 6), radius + 3, radius + 3);

        // The disc (a process's initial, a group's count) or the extension tag of a file.
        double midY = r.Y + r.Height / 2;
        double textX;
        if (n.Kind == MapKind.File)
        {
            var tag = new Rect(r.X + 8, midY - 10, 30, 20);
            dc.DrawRoundedRectangle(ink.Disc, null, tag, 5, 5);
            v.Mark.SetForegroundBrush(ink.Core);
            dc.DrawText(v.Mark, new Point(tag.X + (tag.Width - v.Mark.Width) / 2, midY - v.Mark.Height / 2));
            textX = tag.Right + 8;
        }
        else
        {
            double dr = n.Kind == MapKind.Root ? 15 : 12;
            var c = new Point(r.X + 10 + dr, midY);
            dc.DrawEllipse(ink.Disc, null, c, dr, dr);
            v.Mark.SetForegroundBrush(n.Kind == MapKind.Root ? Paper : ink.Core);
            dc.DrawText(v.Mark, new Point(c.X - v.Mark.Width / 2, c.Y - v.Mark.Height / 2));
            textX = c.X + dr + 9;
        }

        bool two = v.Sub.Text.Length > 0;
        double ty = two ? midY - (v.Label.Height + v.Sub.Height) / 2 + 0.5 : midY - v.Label.Height / 2;
        dc.DrawText(v.Label, new Point(textX, ty));
        if (n.Strike)
        {
            double sy = ty + v.Label.Height * 0.55;
            dc.DrawLine(new Pen(Solid(Color.FromArgb(0xC0, FaintC.R, FaintC.G, FaintC.B)), 1.2), new Point(textX, sy), new Point(textX + Math.Min(v.Label.Width, 230), sy));
        }
        if (two) dc.DrawText(v.Sub, new Point(textX, ty + v.Label.Height - 1));

        bool badge = n.Collapsed && n.Hidden > 0 || n.Badge.Length > 0;
        if (badge)
        {
            double bw = v.Badge.Width + 12;
            var br = new Rect(r.Right - bw - 8, midY - 9, bw, 18);
            bool fold = n.Collapsed && n.Hidden > 0;
            dc.DrawRoundedRectangle(fold ? Solid(Color.FromArgb(0x40, AccentC.R, AccentC.G, AccentC.B)) : ink.Disc, fold ? SelectPen : null, br, 9, 9);
            v.Badge.SetForegroundBrush(fold ? Paper : ink.Core);
            dc.DrawText(v.Badge, new Point(br.X + 6, br.Y + (br.Height - v.Badge.Height) / 2));
        }

        if (scaleIn < 0.999) dc.Pop();
        dc.Pop();
    }

    private void DrawDrips(DrawingContext dc, Rect r, double now, Ink ink)
    {
        if (!Animate) return;
        // A puddle, and three drops that run down off the bottom edge and fade as they fall.
        dc.PushOpacity(0.16);
        dc.DrawEllipse(ink.Core, null, new Point(r.X + r.Width / 2, r.Bottom + 25), r.Width * 0.42, 4.5);
        dc.Pop();
        double[] at = { 0.2, 0.52, 0.8 };
        for (int i = 0; i < at.Length; i++)
        {
            double phase = (now * 0.52 + i * 0.37) % 1.0;
            double fall = phase * phase * 26;
            double a = 1 - phase * phase * phase;
            double x = r.X + r.Width * at[i];
            var pen = new Pen(Solid(Color.FromArgb((byte)(210 * a), ink.Color.R, ink.Color.G, ink.Color.B)), 2.2) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            dc.DrawLine(pen, new Point(x, r.Bottom - 2), new Point(x, r.Bottom + Math.Max(0.5, fall * 0.8)));
            dc.PushOpacity(a);
            dc.DrawEllipse(ink.Core, null, new Point(x, r.Bottom + fall), 2.8, 3.4);
            dc.Pop();
        }
    }

    private void DrawTip(DrawingContext dc, MapNode n, double w, double h)
    {
        string body = Describe?.Invoke(n) ?? n.Sub;
        var title = Text(n.Label, 12.5, Paper, bold: true, maxWidth: 380);
        var text = Text(body, 11, Mist, mono: true, maxWidth: 380);
        text.MaxLineCount = 6;
        double cw = Math.Max(title.Width, body.Length > 0 ? text.Width : 0) + 24;
        double ch = title.Height + (body.Length > 0 ? text.Height + 6 : 0) + 20;
        double x = _mouse.X + 16, y = _mouse.Y + 18;
        if (x + cw > w - 8) x = _mouse.X - cw - 12;
        if (y + ch > h - 8) y = _mouse.Y - ch - 12;
        var card = new Rect(Math.Max(8, x), Math.Max(8, y), cw, ch);
        dc.DrawRoundedRectangle(CardFill, new Pen(InkOf(n.Level).Rim.Brush, 1), card, 9, 9);
        dc.DrawText(title, new Point(card.X + 12, card.Y + 10));
        if (body.Length > 0) dc.DrawText(text, new Point(card.X + 12, card.Y + 10 + title.Height + 6));
    }
}

using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Input;
using System.Windows.Media;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui.Views;

/// <summary>
/// The incident scene as a radial mind map: the process in the centre, the attack stages on
/// the first ring and the log steps as leaves, growing in as the scene reveals them.
///
/// Drawn in one pass like the world map. Frames are requested only while something moves
/// (a branch growing, the current step pulsing during playback, the model writing); a paused
/// scene with a finished answer costs nothing.
/// </summary>
public sealed class MindMapCanvas : FrameworkElement
{
    private const double RevealSeconds = 0.75;
    private const double StaggerSeconds = 0.09;
    private const double FlashSeconds = 0.7;
    private const double ScoreSeconds = 0.6;
    private const double PulseSeconds = 1.9;
    private const double StageGap = 0.75;
    private const double FrameSeconds = 1.0 / 32;
    private const int Segments = 18;

    private static readonly Stopwatch Clock = Stopwatch.StartNew();

    private static readonly Color PaperC = Color.FromRgb(0xE8, 0xEC, 0xF5);
    private static readonly Color AccentC = Color.FromRgb(0x7C, 0x6C, 0xFF);

    private static readonly Brush Paper = Solid(PaperC);
    private static readonly Brush Mist = Solid(Color.FromRgb(0x99, 0xA2, 0xB8));
    private static readonly Brush Faint = Solid(Color.FromRgb(0x5C, 0x64, 0x79));
    private static readonly Brush Panel = Solid(Color.FromRgb(0x10, 0x14, 0x1F));
    private static readonly Brush Raised = Solid(Color.FromRgb(0x0B, 0x0E, 0x18));
    private static readonly Brush OnAccent = Solid(Color.FromRgb(0x0A, 0x0A, 0x16));
    private static readonly Brush Accent = Solid(AccentC);
    private static readonly Brush Ghost = Solid(Color.FromRgb(0x2A, 0x31, 0x44));
    private static readonly Brush Backdrop = Radial(Color.FromArgb(0x30, 0x1C, 0x22, 0x3C), Color.FromArgb(0x00, 0x1C, 0x22, 0x3C));
    private static readonly Brush AccentGlow = Radial(Color.FromArgb(0x70, AccentC.R, AccentC.G, AccentC.B), Color.FromArgb(0x00, AccentC.R, AccentC.G, AccentC.B));

    private static readonly Pen LinePen = Frozen(new Pen(Solid(Color.FromRgb(0x23, 0x29, 0x38)), 1));
    private static readonly Pen GuidePen = Frozen(new Pen(Solid(Color.FromRgb(0x1A, 0x20, 0x30)), 1) { DashStyle = new DashStyle(new double[] { 2, 5 }, 0) });
    private static readonly Pen TrunkPen = Frozen(new Pen(Solid(Color.FromRgb(0x3A, 0x45, 0x63)), 1.8) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
    private static readonly Pen TrackPen = Frozen(new Pen(Solid(Color.FromRgb(0x1D, 0x24, 0x36)), 4));
    private static readonly Pen TickPen = Frozen(new Pen(Paper, 1.5));
    private static readonly Pen HoverPen = Frozen(new Pen(Solid(Color.FromArgb(0x90, PaperC.R, PaperC.G, PaperC.B)), 1));
    private static readonly Pen AccentPen = Frozen(new Pen(Accent, 1.5));
    private static readonly Pen SweepPen = Frozen(new Pen(Accent, 2) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
    private static readonly Pen FocusPen = Frozen(new Pen(Accent, 1.5));
    private static readonly Pen MarkRim = Frozen(new Pen(Panel, 1.5));

    private static readonly Ink ThreatInk = new(Color.FromRgb(0xF2, 0x55, 0x5A));
    private static readonly Ink WatchInk = new(Color.FromRgb(0xF2, 0xB3, 0x3D));
    private static readonly Ink InfoInk = new(Color.FromRgb(0x4C, 0x8D, 0xFF));

    private static Pen Frozen(Pen p) { p.Freeze(); return p; }

    private static SolidColorBrush Solid(Color c)
    {
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }

    private static Brush Radial(Color inner, Color outer)
    {
        var b = new RadialGradientBrush(inner, outer);
        b.Freeze();
        return b;
    }

    /// <summary>Frozen brushes and pens for one severity colour, built once.</summary>
    private sealed class Ink
    {
        public readonly Brush Core;
        public readonly Brush Soft;
        public readonly Brush Glow;
        public readonly Pen Rim;
        public readonly Pen Branch;
        public readonly Pen BranchHot;
        public readonly Pen BranchGlow;
        public readonly Pen Arc;

        public Ink(Color c)
        {
            Core = Solid(c);
            Soft = Solid(Color.FromArgb(0x34, c.R, c.G, c.B));
            Glow = Radial(Color.FromArgb(0x66, c.R, c.G, c.B), Color.FromArgb(0x00, c.R, c.G, c.B));
            Rim = Frozen(new Pen(Core, 1.5));
            Branch = Frozen(new Pen(Solid(Color.FromArgb(0x9A, c.R, c.G, c.B)), 1.5) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
            BranchHot = Frozen(new Pen(Core, 2.2) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
            BranchGlow = Frozen(new Pen(Solid(Color.FromArgb(0x30, c.R, c.G, c.B)), 7) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
            Arc = Frozen(new Pen(Core, 4) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
        }
    }

    private static Ink InkFor(string severity) => severity switch
    {
        "threat" => ThreatInk,
        "watch" => WatchInk,
        _ => InfoInk,
    };

    private readonly record struct Curve(Point P0, Point P1, Point P2, Point P3)
    {
        public Point At(double t)
        {
            double u = 1 - t;
            double a = u * u * u, b = 3 * u * u * t, c = 3 * u * t * t, d = t * t * t;
            return new Point(a * P0.X + b * P1.X + c * P2.X + d * P3.X, a * P0.Y + b * P1.Y + c * P2.Y + d * P3.Y);
        }
    }

    private sealed class Stage
    {
        public string Name = "";
        public double Angle;
        public Point At;
        public Curve Trunk;
        public readonly List<Leaf> Leaves = new();
    }

    private sealed class Leaf
    {
        public StepItem Item = null!;
        public Stage Stage = null!;
        public double Angle;
        public Point At;
        public Curve Branch;
    }

    public static readonly DependencyProperty StepsProperty = DependencyProperty.Register(
        nameof(Steps), typeof(IEnumerable<StepItem>), typeof(MindMapCanvas),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnStepsChanged));

    public IEnumerable<StepItem>? Steps
    {
        get => (IEnumerable<StepItem>?)GetValue(StepsProperty);
        set => SetValue(StepsProperty, value);
    }

    public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(
        nameof(Title), typeof(string), typeof(MindMapCanvas),
        new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.AffectsRender));

    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }

    public static readonly DependencyProperty PidProperty = DependencyProperty.Register(
        nameof(Pid), typeof(int), typeof(MindMapCanvas),
        new FrameworkPropertyMetadata(0, FrameworkPropertyMetadataOptions.AffectsRender));

    public int Pid { get => (int)GetValue(PidProperty); set => SetValue(PidProperty, value); }

    public static readonly DependencyProperty ContainAtProperty = DependencyProperty.Register(
        nameof(ContainAt), typeof(int), typeof(MindMapCanvas),
        new FrameworkPropertyMetadata(70, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>Score at which the engine contains; drawn as a tick on the centre ring.</summary>
    public int ContainAt { get => (int)GetValue(ContainAtProperty); set => SetValue(ContainAtProperty, value); }

    public static readonly DependencyProperty IsPlayingProperty = DependencyProperty.Register(
        nameof(IsPlaying), typeof(bool), typeof(MindMapCanvas),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender, OnMotionChanged));

    public bool IsPlaying { get => (bool)GetValue(IsPlayingProperty); set => SetValue(IsPlayingProperty, value); }

    public static readonly DependencyProperty IsThinkingProperty = DependencyProperty.Register(
        nameof(IsThinking), typeof(bool), typeof(MindMapCanvas),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender, OnMotionChanged));

    /// <summary>True while the model is writing; lights travel along the branches.</summary>
    public bool IsThinking { get => (bool)GetValue(IsThinkingProperty); set => SetValue(IsThinkingProperty, value); }

    public static readonly DependencyProperty JumpCommandProperty = DependencyProperty.Register(
        nameof(JumpCommand), typeof(ICommand), typeof(MindMapCanvas), new FrameworkPropertyMetadata(null));

    /// <summary>Executed with the clicked step.</summary>
    public ICommand? JumpCommand { get => (ICommand?)GetValue(JumpCommandProperty); set => SetValue(JumpCommandProperty, value); }

    private readonly List<StepItem> _items = new();
    private readonly Dictionary<StepItem, double> _revealAt = new();
    private readonly Dictionary<StepItem, double> _explainedAt = new();
    private readonly List<Stage> _stages = new();
    private readonly List<Leaf> _leaves = new();
    private Typeface? _ui, _uiBold, _mono, _monoBold;
    private StepItem? _hover;
    private bool _hooked;
    private double _lastFrame;
    private double _lastStart;
    private double _scoreFrom, _scoreTo, _scoreAt = -100;
    private Point _centre;
    private double _a1, _b1, _a2, _b2, _r0, _rLeaf, _stageWidth;

    public MindMapCanvas()
    {
        ClipToBounds = true;
        Focusable = true;
        IsVisibleChanged += (_, _) => Sync();
        Loaded += (_, _) => Sync();
        Unloaded += (_, _) => Unhook();
    }

    private static double Now => Clock.Elapsed.TotalSeconds;

    private static void OnMotionChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) => ((MindMapCanvas)d).Sync();

    private static void OnStepsChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var c = (MindMapCanvas)d;
        if (e.OldValue is INotifyCollectionChanged oldCol) oldCol.CollectionChanged -= c.OnCollectionChanged;
        if (e.NewValue is INotifyCollectionChanged newCol) newCol.CollectionChanged += c.OnCollectionChanged;
        c.Resubscribe();
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => Resubscribe();

    // A Reset carries no old items, so the canvas keeps its own list of what it listens to.
    private void Resubscribe()
    {
        foreach (var i in _items) i.PropertyChanged -= OnItemChanged;
        _items.Clear();
        if (Steps is not null) _items.AddRange(Steps);
        foreach (var i in _items) i.PropertyChanged += OnItemChanged;

        foreach (var gone in _revealAt.Keys.Where(k => !_items.Contains(k)).ToArray()) _revealAt.Remove(gone);
        foreach (var gone in _explainedAt.Keys.Where(k => !_items.Contains(k)).ToArray()) _explainedAt.Remove(gone);
        if (_hover is not null && !_items.Contains(_hover)) _hover = null;

        double now = Now;
        foreach (var i in _items)
        {
            if (i.IsRevealed && !_revealAt.ContainsKey(i)) Reveal(i, now);
            if (i.IsExplained && !_explainedAt.ContainsKey(i)) _explainedAt[i] = now - FlashSeconds;
        }
        var current = _items.FirstOrDefault(i => i.IsCurrent);
        if (current is null) { _scoreFrom = _scoreTo = 0; _scoreAt = -100; }
        else if (current.ScoreAfter != (int)_scoreTo) AimScore(current.ScoreAfter, now);
        Sync();
    }

    private void OnItemChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not StepItem item) return;
        double now = Now;
        switch (e.PropertyName)
        {
            case nameof(StepItem.IsRevealed):
                if (item.IsRevealed) Reveal(item, now); else _revealAt.Remove(item);
                break;
            case nameof(StepItem.IsCurrent):
                if (item.IsCurrent) AimScore(item.ScoreAfter, now);
                break;
            case nameof(StepItem.IsExplained):
                if (item.IsExplained) _explainedAt[item] = now; else _explainedAt.Remove(item);
                break;
            default:
                return;
        }
        Sync();
    }

    // Steps revealed together (opening at a later log, a restart) cascade instead of popping at once.
    private void Reveal(StepItem item, double now)
    {
        double start = Math.Max(now, _lastStart + StaggerSeconds);
        _lastStart = start;
        _revealAt[item] = start;
    }

    private void AimScore(int target, double now)
    {
        _scoreFrom = ScoreShown(now);
        _scoreTo = target;
        _scoreAt = now;
    }

    private double ScoreShown(double now)
        => _scoreFrom + (_scoreTo - _scoreFrom) * Ease((now - _scoreAt) / ScoreSeconds);

    private static double Ease(double t)
    {
        t = Math.Clamp(t, 0, 1);
        return 1 - (1 - t) * (1 - t) * (1 - t);
    }

    private bool Moving(double now)
    {
        if (!IsVisible || !IsLoaded || _items.Count == 0) return false;
        if (IsThinking) return true;
        if (IsPlaying && _items.Any(i => i.IsCurrent)) return true;
        if (now - _scoreAt < ScoreSeconds) return true;
        foreach (double t in _revealAt.Values) if (now - t < RevealSeconds) return true;
        foreach (double t in _explainedAt.Values) if (now - t < FlashSeconds) return true;
        return false;
    }

    private void Sync()
    {
        if (Moving(Now)) Hook(); else Unhook();
        InvalidateVisual();
    }

    private void Hook()
    {
        if (_hooked) return;
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
        double now = Now;
        if (!Moving(now))
        {
            Unhook();
            InvalidateVisual();
            return;
        }
        if (now - _lastFrame < FrameSeconds) return;
        _lastFrame = now;
        InvalidateVisual();
    }

    private static Point On(Point c, double a, double b, double angle) => new(c.X + a * Math.Cos(angle), c.Y + b * Math.Sin(angle));

    private static Vector Unit(Vector v)
    {
        double len = v.Length;
        return len < 1e-6 ? new Vector(0, -1) : v / len;
    }

    private void Arrange(double w, double h)
    {
        _stages.Clear();
        _leaves.Clear();
        _centre = new Point(w / 2, h / 2);
        _a2 = Math.Max(40, w / 2 - 60);
        _b2 = Math.Max(40, h / 2 - 46);
        _a2 = Math.Min(_a2, _b2 * 1.7);
        _b2 = Math.Min(_b2, _a2 * 1.12);
        double small = Math.Min(_a2, _b2);
        _r0 = Math.Clamp(small * 0.23, 27, 54);
        _rLeaf = Math.Clamp(small * 0.066, 9.5, 14.5);
        // The stage ring sits midway in the band between the centre node and the leaves.
        _a1 = (_r0 + 8 + _a2 - _rLeaf - 4) / 2;
        _b1 = (_r0 + 8 + _b2 - _rLeaf - 4) / 2;
        _stageWidth = Math.Clamp(_a2 - _rLeaf - _r0 - 12, 56, 156);
        if (_items.Count == 0) return;

        foreach (var item in _items)
        {
            var stage = _stages.Find(s => s.Name == item.Stage);
            if (stage is null) _stages.Add(stage = new Stage { Name = item.Stage });
            var leaf = new Leaf { Item = item, Stage = stage };
            stage.Leaves.Add(leaf);
            _leaves.Add(leaf);
        }

        double gap = _stages.Count > 1 ? StageGap : 0;
        double unit = 2 * Math.PI / (_items.Count + _stages.Count * gap);
        double t = -Math.PI / 2 - _stages[0].Leaves.Count * unit / 2;
        foreach (var stage in _stages)
        {
            double first = t + unit / 2;
            foreach (var leaf in stage.Leaves)
            {
                leaf.Angle = t + unit / 2;
                leaf.At = On(_centre, _a2, _b2, leaf.Angle);
                t += unit;
            }
            stage.Angle = (first + t - unit / 2) / 2;
            stage.At = On(_centre, _a1, _b1, stage.Angle);
            t += gap * unit;

            var outS = Unit(stage.At - _centre);
            var side = new Vector(-outS.Y, outS.X);
            var from = _centre + outS * (_r0 + 5);
            double len = (stage.At - from).Length;
            stage.Trunk = new Curve(from, from + (outS + side * 0.3) * (len * 0.36), stage.At - (outS - side * 0.3) * (len * 0.36), stage.At);

            foreach (var leaf in stage.Leaves)
            {
                var outL = Unit(leaf.At - _centre);
                var end = leaf.At - outL * _rLeaf;
                double d = (end - stage.At).Length;
                leaf.Branch = new Curve(stage.At, stage.At + outS * (d * 0.55), end - outL * (d * 0.45), end);
            }
        }
    }

    private double Progress(StepItem item, double now)
        => _revealAt.TryGetValue(item, out double at) ? Math.Clamp((now - at) / RevealSeconds, 0, 1) : 0;

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w < 60 || h < 60) return;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));

        double now = Now;
        Arrange(w, h);
        bool moving = _hooked;

        dc.DrawEllipse(Backdrop, null, _centre, _a2 * 1.25, _b2 * 1.25);
        dc.DrawEllipse(null, GuidePen, _centre, _a1, _b1);
        dc.DrawEllipse(null, GuidePen, _centre, _a2, _b2);

        var current = _leaves.Find(l => l.Item.IsCurrent);

        foreach (var leaf in _leaves)
            if (Progress(leaf.Item, now) <= 0) dc.DrawEllipse(Ghost, null, leaf.At, 2.5, 2.5);

        foreach (var stage in _stages)
        {
            double ps = stage.Leaves.Max(l => Progress(l.Item, now));
            if (ps <= 0) continue;
            bool hot = current is not null && ReferenceEquals(current.Stage, stage);
            DrawCurve(dc, hot ? InkFor(current!.Item.Severity).Branch : TrunkPen, stage.Trunk, Ease(ps / 0.45));
            foreach (var leaf in stage.Leaves)
            {
                double p = Progress(leaf.Item, now);
                double grow = Ease((p - 0.25) / 0.5);
                if (grow <= 0) continue;
                var ink = InkFor(leaf.Item.Severity);
                if (leaf.Item.IsCurrent)
                {
                    DrawCurve(dc, ink.BranchGlow, leaf.Branch, grow);
                    DrawCurve(dc, ink.BranchHot, leaf.Branch, grow);
                }
                else DrawCurve(dc, ink.Branch, leaf.Branch, grow);
            }
        }

        if (IsThinking && moving) DrawLights(dc, now);

        foreach (var stage in _stages)
        {
            double ps = stage.Leaves.Max(l => Progress(l.Item, now));
            double show = Math.Clamp((ps - 0.3) / 0.3, 0, 1);
            if (show <= 0) continue;
            DrawStage(dc, stage, show, current is not null && ReferenceEquals(current.Stage, stage));
        }

        foreach (var leaf in _leaves)
        {
            double show = Math.Clamp((Progress(leaf.Item, now) - 0.7) / 0.3, 0, 1);
            if (show > 0) DrawLeaf(dc, leaf, show, now, moving);
        }

        DrawCentre(dc, now, moving);

        if (IsKeyboardFocused)
            dc.DrawRoundedRectangle(null, FocusPen, new Rect(1.5, 1.5, w - 3, h - 3), 8, 8);
    }

    private static void DrawCurve(DrawingContext dc, Pen pen, Curve c, double fraction)
    {
        if (fraction <= 0) return;
        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(c.P0, false, false);
            if (fraction >= 1) ctx.BezierTo(c.P1, c.P2, c.P3, true, true);
            else
                for (int i = 1; i <= Segments; i++) ctx.LineTo(c.At(fraction * i / Segments), true, true);
        }
        g.Freeze();
        dc.DrawGeometry(null, pen, g);
    }

    private void DrawLights(DrawingContext dc, double now)
    {
        for (int i = 0; i < _leaves.Count; i++)
        {
            var leaf = _leaves[i];
            if (Progress(leaf.Item, now) < 1) continue;
            double phase = (now * 0.5 + i * 0.381) % 1.0;
            var at = phase < 0.4 ? leaf.Stage.Trunk.At(phase / 0.4) : leaf.Branch.At((phase - 0.4) / 0.6);
            dc.PushOpacity(Math.Sin(Math.PI * phase));
            dc.DrawEllipse(AccentGlow, null, at, 7, 7);
            dc.DrawEllipse(Paper, null, at, 1.6, 1.6);
            dc.Pop();
        }
    }

    private void DrawStage(DrawingContext dc, Stage stage, double show, bool hot)
    {
        var text = Text(stage.Name, _rLeaf > 12 ? 10.5 : 10, hot ? Paper : Mist, mono: false, bold: hot);
        text.MaxLineCount = 1;
        text.Trimming = TextTrimming.CharacterEllipsis;
        text.MaxTextWidth = _stageWidth - 20;
        double tw = Math.Min(text.Width, text.MaxTextWidth);
        var box = new Rect(stage.At.X - tw / 2 - 10, stage.At.Y - 11, tw + 20, 22);
        dc.PushOpacity(show);
        dc.DrawRoundedRectangle(Raised, hot ? AccentPen : LinePen, box, 11, 11);
        dc.DrawText(text, new Point(box.X + 10, stage.At.Y - text.Height / 2));
        dc.Pop();
    }

    private void DrawLeaf(DrawingContext dc, Leaf leaf, double show, double now, bool moving)
    {
        var item = leaf.Item;
        var ink = InkFor(item.Severity);
        bool hot = item.IsCurrent;
        double r = (hot ? _rLeaf + 2.5 : _rLeaf) * (0.6 + 0.4 * show);

        dc.PushOpacity(show);
        if (hot)
        {
            dc.DrawEllipse(ink.Glow, null, leaf.At, r * 2.7, r * 2.7);
            if (moving && IsPlaying)
            {
                double phase = (now % PulseSeconds) / PulseSeconds;
                dc.PushOpacity((1 - phase) * 0.7);
                dc.DrawEllipse(null, ink.Rim, leaf.At, r + 2 + 13 * phase, r + 2 + 13 * phase);
                dc.Pop();
            }
            else
            {
                dc.PushOpacity(0.45);
                dc.DrawEllipse(null, ink.Rim, leaf.At, r + 4, r + 4);
                dc.Pop();
            }
            dc.DrawEllipse(ink.Core, null, leaf.At, r, r);
        }
        else
        {
            dc.DrawEllipse(Panel, null, leaf.At, r, r);
            dc.DrawEllipse(ink.Soft, ink.Rim, leaf.At, r, r);
        }
        if (ReferenceEquals(_hover, item)) dc.DrawEllipse(null, HoverPen, leaf.At, r + 3.5, r + 3.5);

        var number = Text(item.Number.ToString(CultureInfo.CurrentCulture), hot ? 11 : 10, hot ? OnAccent : Paper, mono: true, bold: true);
        dc.DrawText(number, new Point(leaf.At.X - number.Width / 2, leaf.At.Y - number.Height / 2));

        var points = Text(item.Points, 10, hot ? ink.Core : Mist, mono: true, bold: hot);
        var dir = Unit(leaf.At - _centre);
        double reach = r + (hot ? 9 : 6) + Math.Abs(dir.X) * points.Width / 2 + Math.Abs(dir.Y) * points.Height / 2;
        var mid = leaf.At + dir * reach;
        dc.DrawText(points, new Point(mid.X - points.Width / 2, mid.Y - points.Height / 2));

        if (_explainedAt.TryGetValue(item, out double at))
        {
            double age = (now - at) / FlashSeconds;
            if (age is >= 0 and < 1)
            {
                dc.PushOpacity(1 - age);
                dc.DrawEllipse(null, AccentPen, leaf.At, r + 3 + 12 * Ease(age), r + 3 + 12 * Ease(age));
                dc.Pop();
            }
            var mark = new Point(leaf.At.X + r * 0.74, leaf.At.Y - r * 0.74);
            dc.DrawEllipse(Accent, MarkRim, mark, 3.6, 3.6);
        }
        dc.Pop();
    }

    private void DrawCentre(DrawingContext dc, double now, bool moving)
    {
        double score = ScoreShown(now);
        int contain = Math.Max(1, ContainAt);
        var ink = score >= contain ? ThreatInk : score >= contain / 2.0 ? WatchInk : InfoInk;
        double scale = Math.Max(100, _items.Count == 0 ? 100 : _items.Max(i => i.ScoreAfter));
        double frac = Math.Clamp(score / scale, 0, 1);

        if (score > 0) dc.DrawEllipse(ink.Glow, null, _centre, _r0 * 1.9, _r0 * 1.9);
        dc.DrawEllipse(Panel, null, _centre, _r0 + 2, _r0 + 2);
        dc.DrawEllipse(null, TrackPen, _centre, _r0, _r0);
        if (frac >= 0.999) dc.DrawEllipse(null, ink.Arc, _centre, _r0, _r0);
        else if (frac > 0.004) dc.DrawGeometry(null, ink.Arc, Arc(_centre, _r0, -Math.PI / 2, frac * 2 * Math.PI));

        if (contain < scale)
        {
            double a = -Math.PI / 2 + 2 * Math.PI * contain / scale;
            var dir = new Vector(Math.Cos(a), Math.Sin(a));
            dc.DrawLine(TickPen, _centre + dir * (_r0 - 4.5), _centre + dir * (_r0 + 4.5));
        }

        if (IsThinking && moving)
        {
            double a = now * 2.6 % (2 * Math.PI);
            dc.PushOpacity(0.9);
            dc.DrawGeometry(null, SweepPen, Arc(_centre, _r0 + 8, a, 1.1));
            dc.Pop();
        }

        double inner = _r0 * 1.5;
        var value = Text(Math.Round(score).ToString(CultureInfo.CurrentCulture), _r0 * 0.5, Paper, mono: true, bold: true);
        var name = Text(Title ?? "", Math.Clamp(_r0 * 0.23, 8.5, 10), Mist, mono: false, bold: false);
        name.MaxLineCount = 1;
        name.Trimming = TextTrimming.CharacterEllipsis;
        name.MaxTextWidth = inner;
        var pid = Text(Pid > 0 ? "pid " + Pid.ToString(CultureInfo.InvariantCulture) : "", Math.Clamp(_r0 * 0.2, 8, 9), Faint, mono: true, bold: false);
        double block = name.Height + value.Height * 0.86 + pid.Height;
        double y = _centre.Y - block / 2;
        dc.DrawText(name, new Point(_centre.X - Math.Min(name.Width, inner) / 2, y));
        y += name.Height - value.Height * 0.07;
        dc.DrawText(value, new Point(_centre.X - value.Width / 2, y));
        y += value.Height * 0.93;
        dc.DrawText(pid, new Point(_centre.X - pid.Width / 2, y));
    }

    private static Geometry Arc(Point c, double r, double from, double sweep)
    {
        var p0 = new Point(c.X + Math.Cos(from) * r, c.Y + Math.Sin(from) * r);
        var p1 = new Point(c.X + Math.Cos(from + sweep) * r, c.Y + Math.Sin(from + sweep) * r);
        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(p0, false, false);
            ctx.ArcTo(p1, new Size(r, r), 0, sweep > Math.PI, SweepDirection.Clockwise, true, false);
        }
        g.Freeze();
        return g;
    }

    private FormattedText Text(string s, double size, Brush brush, bool mono, bool bold)
    {
        if (_ui is null)
        {
            var ui = TryFindResource("Font.Ui") as FontFamily ?? new FontFamily("Segoe UI");
            var data = TryFindResource("Font.Data") as FontFamily ?? new FontFamily("Consolas");
            _ui = new Typeface(ui, FontStyles.Normal, FontWeights.Medium, FontStretches.Normal);
            _uiBold = new Typeface(ui, FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
            _mono = new Typeface(data, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
            _monoBold = new Typeface(data, FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
        }
        var face = mono ? (bold ? _monoBold! : _mono!) : (bold ? _uiBold! : _ui);
        return new FormattedText(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, face, size, brush,
            VisualTreeHelper.GetDpi(this).PixelsPerDip);
    }

    private StepItem? Hit(Point p)
    {
        StepItem? best = null;
        double bestDistance = _rLeaf + 7;
        foreach (var leaf in _leaves)
        {
            double d = (leaf.At - p).Length;
            if (d < bestDistance) { best = leaf.Item; bestDistance = d; }
        }
        return best;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var hit = Hit(e.GetPosition(this));
        if (ReferenceEquals(hit, _hover)) return;
        _hover = hit;
        Cursor = hit is null ? null : Cursors.Hand;
        ToolTip = hit is null ? null
            : $"Step {hit.Number}  ·  {hit.Time}  ·  {hit.Stage}  ·  {hit.Points}\n{hit.Caption}";
        InvalidateVisual();
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        if (_hover is null) return;
        _hover = null;
        Cursor = null;
        ToolTip = null;
        InvalidateVisual();
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        Focus();
        var hit = Hit(e.GetPosition(this));
        if (hit is null) return;
        Jump(hit);
        e.Handled = true;
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (_items.Count == 0) return;
        int at = _items.FindIndex(i => i.IsCurrent);
        int to = e.Key switch
        {
            Key.Right or Key.Down => Math.Min(_items.Count - 1, at + 1),
            Key.Left or Key.Up => Math.Max(0, at - 1),
            Key.Home => 0,
            Key.End => _items.Count - 1,
            _ => -1,
        };
        if (to < 0) return;
        if (to != at) Jump(_items[to]);
        e.Handled = true;
    }

    private void Jump(StepItem item)
    {
        var command = JumpCommand;
        if (command is not null && command.CanExecute(item)) command.Execute(item);
    }

    protected override void OnGotKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnGotKeyboardFocus(e);
        InvalidateVisual();
    }

    protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnLostKeyboardFocus(e);
        InvalidateVisual();
    }

    protected override AutomationPeer OnCreateAutomationPeer() => new Peer(this);

    private sealed class Peer : FrameworkElementAutomationPeer
    {
        public Peer(MindMapCanvas owner) : base(owner) { }
        protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Custom;
        protected override string GetClassNameCore() => nameof(MindMapCanvas);
        protected override bool IsControlElementCore() => true;
        protected override bool IsContentElementCore() => true;
    }
}

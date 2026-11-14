using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui.Views;

/// <summary>Brushes and text helpers shared by the drawn charts, read from the theme.</summary>
internal static class ChartInk
{
    public static Brush Get(FrameworkElement e, string key, Color fallback)
        => e.TryFindResource(key) as Brush ?? Frozen(new SolidColorBrush(fallback));

    public static Brush Frozen(Brush b) { b.Freeze(); return b; }

    public static Brush WithAlpha(Brush b, byte alpha)
    {
        if (b is not SolidColorBrush s) return b;
        return Frozen(new SolidColorBrush(Color.FromArgb(alpha, s.Color.R, s.Color.G, s.Color.B)));
    }

    public static FormattedText Text(FrameworkElement e, string s, double size, Brush brush, bool mono = false, FontWeight? weight = null)
    {
        var family = (e.TryFindResource(mono ? "Font.Data" : "Font.Ui") as FontFamily) ?? new FontFamily("Segoe UI");
        return new FormattedText(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            new Typeface(family, FontStyles.Normal, weight ?? FontWeights.Normal, FontStretches.Normal),
            size, brush, VisualTreeHelper.GetDpi(e).PixelsPerDip);
    }
}

/// <summary>A small filled line of recent samples, newest on the right.</summary>
public sealed class Sparkline : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IReadOnlyList<double>), typeof(Sparkline),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public IReadOnlyList<double>? Values
    {
        get => (IReadOnlyList<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(Brush), typeof(Sparkline),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public Brush? Stroke
    {
        get => (Brush?)GetValue(StrokeProperty);
        set => SetValue(StrokeProperty, value);
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        var values = Values;
        if (w <= 2 || h <= 2 || values is null || values.Count < 2) return;

        var stroke = Stroke as SolidColorBrush ?? (SolidColorBrush)ChartInk.Get(this, "Brush.Accent", Color.FromRgb(0x7C, 0x6C, 0xFF));
        double max = Math.Max(values.Max(), 1e-9);
        double step = w / (values.Count - 1);
        Point P(int i) => new(i * step, h - 1.5 - (values[i] / max) * (h - 3));

        var line = new StreamGeometry();
        using (var ctx = line.Open())
        {
            ctx.BeginFigure(P(0), false, false);
            for (int i = 1; i < values.Count; i++) ctx.LineTo(P(i), true, true);
        }
        line.Freeze();

        var area = new StreamGeometry();
        using (var ctx = area.Open())
        {
            ctx.BeginFigure(new Point(0, h), true, true);
            for (int i = 0; i < values.Count; i++) ctx.LineTo(P(i), false, true);
            ctx.LineTo(new Point(w, h), false, true);
        }
        area.Freeze();

        var c = stroke.Color;
        var fill = new LinearGradientBrush(Color.FromArgb(0x55, c.R, c.G, c.B), Color.FromArgb(0x00, c.R, c.G, c.B), 90);
        fill.Freeze();
        dc.DrawGeometry(fill, null, area);
        var pen = new Pen(stroke, 1.5) { LineJoin = PenLineJoin.Round };
        pen.Freeze();
        dc.DrawGeometry(null, pen, line);
        dc.DrawEllipse(stroke, null, P(values.Count - 1), 2.5, 2.5);
    }
}

/// <summary>
/// Stacked activity bars per time slice (quarantine, warn, action, info), with a hover readout.
/// Drawn in one pass rather than templated, because it repaints on every refresh tick.
/// </summary>
public sealed class TimelineChart : FrameworkElement
{
    public static readonly DependencyProperty BucketsProperty = DependencyProperty.Register(
        nameof(Buckets), typeof(IReadOnlyList<ActivityBucket>), typeof(TimelineChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public IReadOnlyList<ActivityBucket>? Buckets
    {
        get => (IReadOnlyList<ActivityBucket>?)GetValue(BucketsProperty);
        set => SetValue(BucketsProperty, value);
    }

    public static readonly DependencyProperty ShowAxisProperty = DependencyProperty.Register(
        nameof(ShowAxis), typeof(bool), typeof(TimelineChart),
        new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender));

    public bool ShowAxis
    {
        get => (bool)GetValue(ShowAxisProperty);
        set => SetValue(ShowAxisProperty, value);
    }

    private int _hover = -1;
    private const double AxisHeight = 16;
    private const double LabelWidth = 26;

    public TimelineChart() => ClipToBounds = true;

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 10 || h <= 10) return;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));

        var buckets = Buckets;
        double left = ShowAxis ? LabelWidth : 0;
        double top0 = ShowAxis ? 7 : 0;
        double plotH = h - (ShowAxis ? AxisHeight : 0) - top0;
        double plotW = w - left;

        var grid = ChartInk.Get(this, "Brush.LineSoft", Color.FromRgb(0x17, 0x1C, 0x29));
        var faint = ChartInk.Get(this, "Brush.Faint", Color.FromRgb(0x5C, 0x64, 0x79));
        var gridPen = new Pen(grid, 1);
        gridPen.Freeze();

        int max = buckets is null || buckets.Count == 0 ? 0 : buckets.Max(b => b.Total);
        int top = NiceCeiling(Math.Max(max, 4));

        for (int i = 0; i <= 2; i++)
        {
            double y = Math.Round(top0 + plotH - plotH * i / 2.0) + 0.5;
            dc.DrawLine(gridPen, new Point(left, y), new Point(w, y));
            if (ShowAxis && i > 0)
            {
                var label = ChartInk.Text(this, (top * i / 2).ToString(CultureInfo.CurrentCulture), 9.5, faint, mono: true);
                dc.DrawText(label, new Point(left - label.Width - 6, y - label.Height / 2));
            }
        }

        if (buckets is null || buckets.Count == 0) return;

        var lanes = new[]
        {
            ChartInk.Get(this, "Brush.Threat", Color.FromRgb(0xF2, 0x55, 0x5A)),
            ChartInk.Get(this, "Brush.Watch", Color.FromRgb(0xF2, 0xB3, 0x3D)),
            ChartInk.Get(this, "Brush.Info", Color.FromRgb(0x4C, 0x8D, 0xFF)),
            ChartInk.WithAlpha(ChartInk.Get(this, "Brush.Mist", Color.FromRgb(0x99, 0xA2, 0xB8)), 0x70),
        };

        double slot = plotW / buckets.Count;
        double barW = Math.Max(1, slot - Math.Min(3, slot * 0.28));
        for (int i = 0; i < buckets.Count; i++)
        {
            var b = buckets[i];
            double x = left + i * slot + (slot - barW) / 2;
            if (i == _hover)
                dc.DrawRoundedRectangle(ChartInk.WithAlpha(faint, 0x30), null, new Rect(left + i * slot, top0, slot, plotH), 2, 2);

            double y = top0 + plotH;
            int[] counts = { b.Threat, b.Warn, b.Action, b.Info };
            for (int lane = 0; lane < 4; lane++)
            {
                if (counts[lane] == 0) continue;
                double segH = Math.Max(1.5, plotH * counts[lane] / top);
                y -= segH;
                dc.DrawRoundedRectangle(lanes[lane], null, new Rect(x, y, barW, segH), Math.Min(1.5, barW / 2), Math.Min(1.5, barW / 2));
            }
        }

        if (!ShowAxis) return;
        int every = Math.Max(1, buckets.Count / 4);
        for (int i = 0; i < buckets.Count; i += every)
        {
            var label = ChartInk.Text(this, buckets[i].StartLocal.ToString("HH:mm:ss", CultureInfo.CurrentCulture), 9.5, faint, mono: true);
            double lx = Math.Min(left + i * slot, w - label.Width);
            dc.DrawText(label, new Point(lx, top0 + plotH + 3));
        }
    }

    private static int NiceCeiling(int v)
    {
        foreach (int n in new[] { 4, 6, 8, 10, 20, 40, 60, 100, 200, 400, 1000 })
            if (v <= n) return n;
        return (int)Math.Ceiling(v / 1000.0) * 1000;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var buckets = Buckets;
        if (buckets is null || buckets.Count == 0) return;
        double left = ShowAxis ? LabelWidth : 0;
        double slot = (ActualWidth - left) / buckets.Count;
        int ix = (int)Math.Floor((e.GetPosition(this).X - left) / slot);
        ix = ix < 0 || ix >= buckets.Count ? -1 : ix;
        if (ix == _hover) return;
        _hover = ix;
        if (ix >= 0)
        {
            var b = buckets[ix];
            ToolTip = $"{b.StartLocal:HH:mm:ss}  ·  {b.Total} event{(b.Total == 1 ? "" : "s")}\n" +
                      $"quarantine {b.Threat}   warn {b.Warn}   action {b.Action}   info {b.Info}";
        }
        else ToolTip = null;
        InvalidateVisual();
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        _hover = -1;
        ToolTip = null;
        InvalidateVisual();
    }
}

/// <summary>
/// Radial score gauge with ticks at the warn and contain thresholds. Scores are not capped,
/// so the arc fills at 100 and the number carries the rest.
/// </summary>
public sealed class ScoreRing : FrameworkElement
{
    public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
        nameof(Value), typeof(int), typeof(ScoreRing),
        new FrameworkPropertyMetadata(0, FrameworkPropertyMetadataOptions.AffectsRender));
    public int Value { get => (int)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }

    public static readonly DependencyProperty WarnAtProperty = DependencyProperty.Register(
        nameof(WarnAt), typeof(int), typeof(ScoreRing),
        new FrameworkPropertyMetadata(40, FrameworkPropertyMetadataOptions.AffectsRender));
    public int WarnAt { get => (int)GetValue(WarnAtProperty); set => SetValue(WarnAtProperty, value); }

    public static readonly DependencyProperty ContainAtProperty = DependencyProperty.Register(
        nameof(ContainAt), typeof(int), typeof(ScoreRing),
        new FrameworkPropertyMetadata(70, FrameworkPropertyMetadataOptions.AffectsRender));
    public int ContainAt { get => (int)GetValue(ContainAtProperty); set => SetValue(ContainAtProperty, value); }

    public static readonly DependencyProperty SeverityProperty = DependencyProperty.Register(
        nameof(Severity), typeof(string), typeof(ScoreRing),
        new FrameworkPropertyMetadata("watch", FrameworkPropertyMetadataOptions.AffectsRender));
    public string Severity { get => (string)GetValue(SeverityProperty); set => SetValue(SeverityProperty, value); }

    public static readonly DependencyProperty CaptionProperty = DependencyProperty.Register(
        nameof(Caption), typeof(string), typeof(ScoreRing),
        new FrameworkPropertyMetadata("score", FrameworkPropertyMetadataOptions.AffectsRender));
    public string Caption { get => (string)GetValue(CaptionProperty); set => SetValue(CaptionProperty, value); }

    public static readonly DependencyProperty ShowTicksProperty = DependencyProperty.Register(
        nameof(ShowTicks), typeof(bool), typeof(ScoreRing),
        new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender));
    public bool ShowTicks { get => (bool)GetValue(ShowTicksProperty); set => SetValue(ShowTicksProperty, value); }

    private const double Sweep = 270;
    private const double StartAngle = 135;

    protected override void OnRender(DrawingContext dc)
    {
        double size = Math.Min(ActualWidth, ActualHeight);
        if (size <= 10) return;
        var c = new Point(ActualWidth / 2, ActualHeight / 2);
        double thickness = Math.Max(4, size * 0.09);
        double r = size / 2 - thickness / 2 - 1;

        var track = ChartInk.Get(this, "Brush.InkRaised", Color.FromRgb(0x0B, 0x0E, 0x18));
        var line = ChartInk.Get(this, "Brush.Line", Color.FromRgb(0x23, 0x29, 0x38));
        var fill = Severity switch
        {
            "threat" => ChartInk.Get(this, "Brush.Threat", Color.FromRgb(0xF2, 0x55, 0x5A)),
            "safe" => ChartInk.Get(this, "Brush.Safe", Color.FromRgb(0x34, 0xD3, 0x99)),
            "accent" => ChartInk.Get(this, "Brush.Accent", Color.FromRgb(0x7C, 0x6C, 0xFF)),
            _ => ChartInk.Get(this, "Brush.Watch", Color.FromRgb(0xF2, 0xB3, 0x3D)),
        };

        var trackPen = new Pen(track, thickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
        trackPen.Freeze();
        dc.DrawGeometry(null, trackPen, Arc(c, r, 0, 1));

        double frac = Math.Clamp(Value / 100.0, 0, 1);
        if (frac > 0)
        {
            var glow = new Pen(ChartInk.WithAlpha(fill, 0x30), thickness + 6) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            glow.Freeze();
            dc.DrawGeometry(null, glow, Arc(c, r, 0, frac));
            var pen = new Pen(fill, thickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            pen.Freeze();
            dc.DrawGeometry(null, pen, Arc(c, r, 0, frac));
        }

        var tickPen = new Pen(line, 1.5);
        tickPen.Freeze();
        foreach (int t in ShowTicks ? new[] { WarnAt, ContainAt } : Array.Empty<int>())
        {
            double a = (StartAngle + Sweep * Math.Clamp(t / 100.0, 0, 1)) * Math.PI / 180;
            var inner = new Point(c.X + Math.Cos(a) * (r - thickness * 0.9), c.Y + Math.Sin(a) * (r - thickness * 0.9));
            var outer = new Point(c.X + Math.Cos(a) * (r + thickness * 0.9), c.Y + Math.Sin(a) * (r + thickness * 0.9));
            dc.DrawLine(tickPen, inner, outer);
        }

        var paper = ChartInk.Get(this, "Brush.Paper", Color.FromRgb(0xE8, 0xEC, 0xF5));
        var faint = ChartInk.Get(this, "Brush.Faint", Color.FromRgb(0x5C, 0x64, 0x79));
        var value = ChartInk.Text(this, Value.ToString(CultureInfo.CurrentCulture), size * 0.27, paper, mono: true, FontWeights.SemiBold);
        var caption = ChartInk.Text(this, Caption, size * 0.1, faint, mono: true);
        double block = value.Height + caption.Height * 0.8;
        dc.DrawText(value, new Point(c.X - value.Width / 2, c.Y - block / 2));
        dc.DrawText(caption, new Point(c.X - caption.Width / 2, c.Y - block / 2 + value.Height * 0.92));
    }

    private static Geometry Arc(Point c, double r, double from, double to)
    {
        double a0 = (StartAngle + Sweep * from) * Math.PI / 180;
        double a1 = (StartAngle + Sweep * to) * Math.PI / 180;
        var p0 = new Point(c.X + Math.Cos(a0) * r, c.Y + Math.Sin(a0) * r);
        var p1 = new Point(c.X + Math.Cos(a1) * r, c.Y + Math.Sin(a1) * r);
        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(p0, false, false);
            ctx.ArcTo(p1, new Size(r, r), 0, Sweep * (to - from) > 180, SweepDirection.Clockwise, true, false);
        }
        g.Freeze();
        return g;
    }
}

using System.Windows;

namespace BruceEDR.Gui.Views;

/// <summary>Sidebar item decorations read by the Nav.Item template.</summary>
public static class Nav
{
    public static readonly DependencyProperty IconProperty = DependencyProperty.RegisterAttached(
        "Icon", typeof(string), typeof(Nav), new PropertyMetadata(""));
    public static string GetIcon(DependencyObject o) => (string)o.GetValue(IconProperty);
    public static void SetIcon(DependencyObject o, string v) => o.SetValue(IconProperty, v);

    /// <summary>Count shown on the right of the item; hidden when empty or zero.</summary>
    public static readonly DependencyProperty BadgeProperty = DependencyProperty.RegisterAttached(
        "Badge", typeof(int), typeof(Nav), new PropertyMetadata(0));
    public static int GetBadge(DependencyObject o) => (int)o.GetValue(BadgeProperty);
    public static void SetBadge(DependencyObject o, int v) => o.SetValue(BadgeProperty, v);

    /// <summary>Short accent label beside the item (e.g. "AI"); hidden when empty.</summary>
    public static readonly DependencyProperty FlagProperty = DependencyProperty.RegisterAttached(
        "Flag", typeof(string), typeof(Nav), new PropertyMetadata(""));
    public static string GetFlag(DependencyObject o) => (string)o.GetValue(FlagProperty);
    public static void SetFlag(DependencyObject o, string v) => o.SetValue(FlagProperty, v);

    /// <summary>threat | watch | neutral: the badge colour.</summary>
    public static readonly DependencyProperty BadgeLevelProperty = DependencyProperty.RegisterAttached(
        "BadgeLevel", typeof(string), typeof(Nav), new PropertyMetadata("neutral"));
    public static string GetBadgeLevel(DependencyObject o) => (string)o.GetValue(BadgeLevelProperty);
    public static void SetBadgeLevel(DependencyObject o, string v) => o.SetValue(BadgeLevelProperty, v);
}

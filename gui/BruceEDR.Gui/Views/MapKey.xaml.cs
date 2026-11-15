using System.Windows;
using System.Windows.Controls;

namespace BruceEDR.Gui.Views;

public partial class MapKey : UserControl
{
    public static readonly DependencyProperty ItemsProperty = DependencyProperty.Register(
        nameof(Items), typeof(IReadOnlyList<LegendItem>), typeof(MapKey), new PropertyMetadata(null));

    public MapKey() => InitializeComponent();

    public IReadOnlyList<LegendItem>? Items
    {
        get => (IReadOnlyList<LegendItem>?)GetValue(ItemsProperty);
        set => SetValue(ItemsProperty, value);
    }
}

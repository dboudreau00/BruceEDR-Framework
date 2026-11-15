using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace BruceEDR.Gui.Views;

public partial class SourceBar : UserControl
{
    public SourceBar()
    {
        InitializeComponent();
        // Choosing anything in the menu closes it.
        MenuBody.AddHandler(ButtonBase.ClickEvent, new System.Windows.RoutedEventHandler((_, _) => Picker.IsChecked = false));
    }
}

using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ProcessShield.Gui.Services;
using ProcessShield.Gui.ViewModels;

namespace ProcessShield.Gui.Views;

public partial class MapView : UserControl
{
    public MapView()
    {
        InitializeComponent();

        // The canvas raises a plain event rather than binding a command: hover is a
        // high-frequency, view-local concern, and routing it through the command system
        // would re-evaluate CanExecute on every mouse move.
        Map.MarkerHovered += m => Vm?.HighlightMarker(m);
    }

    private MainViewModel? Vm => DataContext as MainViewModel;

    private void Marker_MouseEnter(object sender, MouseEventArgs e)
    {
        try
        {
            if (sender is FrameworkElement { DataContext: MapMarker marker })
                Vm?.HighlightMarker(marker);
        }
        catch (Exception ex) { AppLog.Error("map hover enter", ex); }
    }

    private void Marker_MouseLeave(object sender, MouseEventArgs e)
    {
        try { Vm?.HighlightMarker(null); }
        catch (Exception ex) { AppLog.Error("map hover leave", ex); }
    }
}

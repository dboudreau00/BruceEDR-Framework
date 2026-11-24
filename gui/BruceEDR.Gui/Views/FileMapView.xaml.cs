using System.Windows.Controls;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui.Views;

public partial class FileMapView : UserControl
{
    public FileMapView()
    {
        InitializeComponent();
        Map.Describe = n => (DataContext as FileMapViewModel)?.Describe(n);
        Map.NodeActivated += (_, n) => (DataContext as FileMapViewModel)?.Activate(n);
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is FileMapViewModel old) { old.FitRequested -= Reframe; old.FitAllRequested -= FitAll; }
            if (e.NewValue is FileMapViewModel now) { now.FitRequested += Reframe; now.FitAllRequested += FitAll; now.IsViewActive = IsVisible; }
        };
        // A hidden tab does not rebuild on every live tick; it catches up when it is shown again.
        IsVisibleChanged += (_, _) => { if (DataContext is FileMapViewModel vm) vm.IsViewActive = IsVisible; };
        Unloaded += (_, _) => { if (DataContext is FileMapViewModel vm) vm.IsViewActive = false; };
        Loaded += (_, _) => { if (DataContext is FileMapViewModel vm) vm.IsViewActive = IsVisible; };
    }

    private void Reframe() => Map.FocusView();
    private void FitAll() => Map.FitToView();
}

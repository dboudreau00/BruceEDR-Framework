using System.Windows.Controls;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui.Views;

public partial class ProcessMapView : UserControl
{
    public ProcessMapView()
    {
        InitializeComponent();
        Map.Describe = n => (DataContext as ProcessMapViewModel)?.Describe(n);
        Map.NodeActivated += (_, n) => (DataContext as ProcessMapViewModel)?.Toggle(n);
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is ProcessMapViewModel old) { old.FitRequested -= Reframe; old.FitAllRequested -= FitAll; }
            if (e.NewValue is ProcessMapViewModel now) { now.FitRequested += Reframe; now.FitAllRequested += FitAll; now.IsViewActive = IsVisible; }
        };
        // A hidden tab does not rebuild on every live tick; it catches up when it is shown again.
        IsVisibleChanged += (_, _) => { if (DataContext is ProcessMapViewModel vm) vm.IsViewActive = IsVisible; };
        Unloaded += (_, _) => { if (DataContext is ProcessMapViewModel vm) vm.IsViewActive = false; };
        Loaded += (_, _) => { if (DataContext is ProcessMapViewModel vm) vm.IsViewActive = IsVisible; };
    }

    private void Reframe() => Map.FocusView();
    private void FitAll() => Map.FitToView();
}

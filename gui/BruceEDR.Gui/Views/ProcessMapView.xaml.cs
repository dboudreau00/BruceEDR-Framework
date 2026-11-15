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
            if (e.NewValue is ProcessMapViewModel now) { now.FitRequested += Reframe; now.FitAllRequested += FitAll; }
        };
    }

    private void Reframe() => Map.FocusView();
    private void FitAll() => Map.FitToView();
}

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
            if (e.NewValue is FileMapViewModel now) { now.FitRequested += Reframe; now.FitAllRequested += FitAll; }
        };
    }

    private void Reframe() => Map.FocusView();
    private void FitAll() => Map.FitToView();
}

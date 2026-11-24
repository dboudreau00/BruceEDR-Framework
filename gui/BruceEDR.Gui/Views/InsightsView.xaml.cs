using System.Windows.Controls;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui.Views;

public partial class InsightsView : UserControl
{
    public InsightsView()
    {
        InitializeComponent();
        // A hidden tab does not rebuild its charts on every live tick; it catches up when it is shown again.
        DataContextChanged += (_, e) => { if (e.NewValue is InsightsViewModel now) now.IsViewActive = IsVisible; };
        IsVisibleChanged += (_, _) => { if (DataContext is InsightsViewModel vm) vm.IsViewActive = IsVisible; };
        Unloaded += (_, _) => { if (DataContext is InsightsViewModel vm) vm.IsViewActive = false; };
        Loaded += (_, _) => { if (DataContext is InsightsViewModel vm) vm.IsViewActive = IsVisible; };
    }
}
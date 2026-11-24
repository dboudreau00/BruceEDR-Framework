using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using BruceEDR.Gui.Services;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui.Views;

public partial class TriageView : UserControl
{
    private TriageViewModel? _vm;

    public TriageView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => Attach(DataContext as TriageViewModel);
        Loaded += (_, _) => Attach(DataContext as TriageViewModel);
        Unloaded += (_, _) => Attach(null);
    }

    private void Attach(TriageViewModel? vm)
    {
        if (ReferenceEquals(vm, _vm)) return;
        if (_vm is not null) _vm.PropertyChanged -= OnVmChanged;
        _vm = vm;
        if (_vm is not null) _vm.PropertyChanged += OnVmChanged;
    }

    // The narration follows the writing while it streams, and the step on stage afterwards.
    private void OnVmChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_vm is null) return;
        try
        {
            if (e.PropertyName is nameof(TriageViewModel.IsSceneOpen) or nameof(TriageViewModel.SelectedPersona))
                NarrationScroll.ScrollToTop();
            else if (e.PropertyName == nameof(TriageViewModel.NarrationText) && _vm.NarrationState == "streaming")
                Dispatcher.BeginInvoke(DispatcherPriority.Loaded, NarrationScroll.ScrollToEnd);
            else if (e.PropertyName == nameof(TriageViewModel.Current) && !_vm.IsGenerating)
                Dispatcher.BeginInvoke(DispatcherPriority.Loaded, ShowCurrent);
            else if (e.PropertyName == nameof(TriageViewModel.NarrationState) && _vm.NarrationState is "done" or "idle" or "waiting")
                Dispatcher.BeginInvoke(DispatcherPriority.Loaded, ShowCurrent);
        }
        catch (Exception ex) { AppLog.Error("triage scroll", ex); }
    }

    private void ShowCurrent()
    {
        var current = _vm?.Current;
        if (current is null || !current.IsExplained) { NarrationScroll.ScrollToTop(); return; }
        if (StepList.ItemContainerGenerator.ContainerFromItem(current) is FrameworkElement row)
            row.BringIntoView(new Rect(0, -40, row.ActualWidth, row.ActualHeight + 80));
    }

    private void Incidents_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (_vm is not null && _vm.PlaySceneCommand.CanExecute(null))
            _vm.PlaySceneCommand.Execute(null);
    }
}

using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui.Views;

public partial class SetupView : UserControl
{
    public SetupView()
    {
        InitializeComponent();
        // Keyboard users land on Start, not somewhere in the disabled tabs underneath.
        IsVisibleChanged += (_, e) =>
        {
            if (e.NewValue is true)
                Dispatcher.BeginInvoke(() => StartButton.Focus(), DispatcherPriority.Input);
        };
    }

    private void Scenarios_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is MainViewModel vm && vm.StartReplayCommand.CanExecute(null))
            vm.StartReplayCommand.Execute(null);
    }
}

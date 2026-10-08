using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

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
}

using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace BruceEDR.Gui.Services;

/// <summary>
/// Paints the window's own title bar in the app's colours instead of the system's light one. The bar
/// stays the system's, so snap layouts, the caption buttons, keyboard and accessibility behave as in
/// any window. Windows 11 takes the caption, text and border colours as given; Windows 10 (20H1 and
/// later) has only the dark mode switch, which is close; anything older keeps the light bar.
/// </summary>
public static class TitleBar
{
    // The palette's InkRaised (sidebar and status bar), Paper (text) and Line (borders).
    private static readonly int Caption = ColorRef(0x0B, 0x0E, 0x18);
    private static readonly int Text = ColorRef(0xE8, 0xEC, 0xF5);
    private static readonly int Border = ColorRef(0x23, 0x29, 0x38);

    public static void UseAppColours(Window window)
    {
        if (new WindowInteropHelper(window).Handle != IntPtr.Zero) Apply(window);
        else window.SourceInitialized += (_, _) => Apply(window);
    }

    private static void Apply(Window window)
    {
        try
        {
            var hwnd = new WindowInteropHelper(window).Handle;
            int on = 1;
            if (DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref on, sizeof(int)) != 0)
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, ref on, sizeof(int));
            int caption = Caption, text = Text, border = Border;
            DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ref caption, sizeof(int));
            DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, ref text, sizeof(int));
            DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ref border, sizeof(int));
        }
        catch (Exception ex) { AppLog.Error("title bar colours", ex); }   // the light bar is the fallback
    }

    /// <summary>COLORREF is 0x00BBGGRR.</summary>
    private static int ColorRef(byte r, byte g, byte b) => r | (g << 8) | (b << 16);

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_BORDER_COLOR = 34;
    private const int DWMWA_CAPTION_COLOR = 35;
    private const int DWMWA_TEXT_COLOR = 36;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}

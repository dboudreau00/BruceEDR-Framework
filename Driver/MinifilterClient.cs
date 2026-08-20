using System.Runtime.InteropServices;
using System.Text;
using ProcessShield.Core;

namespace ProcessShield.Driver;

/// <summary>
/// User-mode client for the ShieldFilter minifilter. Connects to the driver's
/// communication port and pushes policy (sensitive path fragments + a block toggle).
/// If the driver is not installed the connect fails gracefully and kernel
/// enforcement is simply unavailable — the user-mode detection path continues to
/// work on its own.
///
/// This client is push-only. It sends policy to the driver and never reads back:
/// there is no FilterGetMessage pump and no callback, so nothing in ProcessShield
/// consumes block notifications. The practical consequence is that a kernel denial
/// is visible only in the driver's own logging — it does not reach ProcessShield's
/// event stream, the detection engine, or the audit chain, and no incident is
/// raised for it. Treat kernel blocking as silent-from-user-mode enforcement, not
/// as a telemetry source.
///
/// The receive path is deliberately not implemented. It needs a FilterGetMessage
/// pump with an overlapped-IO design (a dedicated reader thread or an IO completion
/// port, plus clean cancellation on Dispose) and a matching driver-side
/// FltSendMessage contract with its own reply header. The driver in this repository
/// defines no such notification message, and nobody here can load and test a signed
/// minifilter, so writing an untested pump against a message layout that does not
/// exist yet would add real complexity and a plausible hang or leak on shutdown
/// while buying nothing. A future contributor adding it must define the notification
/// struct in ShieldFilter.h first and keep this file in step with it.
///
/// The message layout here MUST match ShieldFilter.h in the driver project.
/// </summary>
public sealed class MinifilterClient : IDisposable
{
    private const string PortName = @"\ShieldFilterPort";

    // Must mirror SHIELD_COMMAND in ShieldFilter.h
    private enum ShieldCommand : uint { SetBlocking = 1, AddSensitivePath = 2, ClearPolicy = 3 }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ShieldMessage
    {
        public uint Command;
        public uint Flag;                                  // for SetBlocking
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string Path;                                // for AddSensitivePath
    }

    private IntPtr _port = IntPtr.Zero;
    private readonly Logger _log;

    public bool Connected => _port != IntPtr.Zero;

    public MinifilterClient(Logger log) => _log = log;

    /// <summary>Attempts to connect. Returns false (quietly) if the driver isn't present.</summary>
    public bool TryConnect()
    {
        try
        {
            int hr = FilterConnectCommunicationPort(PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out _port);
            if (hr != 0)
            {
                _log.Info($"minifilter not connected (hr=0x{hr:X8}); kernel enforcement disabled");
                _port = IntPtr.Zero;
                return false;
            }
            // Deliberately does not say "monitoring": the port is write-only from here,
            // so a connected driver reports nothing back to user mode.
            _log.Info("minifilter connected; policy channel open (push-only, no driver notifications consumed)");
            return true;
        }
        catch (DllNotFoundException)
        {
            _log.Info("fltlib unavailable; kernel enforcement disabled");
            return false;
        }
        catch (Exception ex)
        {
            _log.Error("minifilter connect", ex);
            return false;
        }
    }

    /// <summary>
    /// Pushes the block toggle to the driver. With blocking off the driver enforces
    /// nothing, and because this client never reads from the port it also surfaces
    /// nothing: the connection is open but user mode learns nothing about file access
    /// to sensitive paths. With blocking on, denials happen in the kernel and are
    /// recorded only by the driver's own logging.
    /// </summary>
    public void SetBlocking(bool enabled) =>
        Send(new ShieldMessage { Command = (uint)ShieldCommand.SetBlocking, Flag = enabled ? 1u : 0u, Path = "" });

    public void AddSensitivePath(string fragment) =>
        Send(new ShieldMessage { Command = (uint)ShieldCommand.AddSensitivePath, Flag = 0, Path = fragment });

    public void ClearPolicy() =>
        Send(new ShieldMessage { Command = (uint)ShieldCommand.ClearPolicy, Flag = 0, Path = "" });

    private void Send(ShieldMessage msg)
    {
        if (!Connected) return;
        int size = Marshal.SizeOf<ShieldMessage>();
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(msg, buf, false);
            int hr = FilterSendMessage(_port, buf, (uint)size, IntPtr.Zero, 0, out _);
            if (hr != 0) _log.Info($"minifilter send failed (hr=0x{hr:X8})");
        }
        catch (Exception ex) { _log.Error("minifilter send", ex); }
        finally { Marshal.FreeHGlobal(buf); }
    }

    public void Dispose()
    {
        if (_port != IntPtr.Zero)
        {
            try { CloseHandle(_port); } catch { }
            _port = IntPtr.Zero;
        }
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, IntPtr lpContext, uint wSizeOfContext,
        IntPtr lpSecurityAttributes, out IntPtr hPort);

    [DllImport("fltlib.dll", SetLastError = false)]
    private static extern int FilterSendMessage(
        IntPtr hPort, IntPtr lpInBuffer, uint dwInBufferSize,
        IntPtr lpOutBuffer, uint dwOutBufferSize, out uint lpBytesReturned);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}

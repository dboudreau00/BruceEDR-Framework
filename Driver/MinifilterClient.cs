using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using BruceEDR.Core;

namespace BruceEDR.Driver;

/// <summary>What the driver refused (BRUCE_OPERATION).</summary>
public enum KernelOperation
{
    /// <summary>An open, refused before the file system saw it.</summary>
    Open = 1,
    /// <summary>A rename onto a guarded path, or of a folder holding one.</summary>
    Rename = 2,
    /// <summary>A hard link onto a guarded path.</summary>
    Link = 3,
    /// <summary>An open by file id or with no readable name, cancelled once the opened file's name was certain.</summary>
    Reopen = 4,
    /// <summary>Dangerous access removed from a handle to a process whose image is trusted for a store.</summary>
    ProcessHandle = 5,
    /// <summary>The same for a handle to one of that process's threads.</summary>
    ThreadHandle = 6
}

/// <summary>
/// One refusal reported by the driver (BRUCE_NOTIFICATION). Paths are NT paths
/// (\Device\HarddiskVolume3\...). StoreIndex is the store's position in the pushed policy,
/// or -1 when the driver refused a name it could not resolve. For a handle operation
/// (<see cref="KernelOperation.ProcessHandle"/>, <see cref="KernelOperation.ThreadHandle"/>)
/// ProcessId and Image are the process that asked for the handle, Path is the trusted target's
/// image and StoreIndex the first store it is trusted for.
/// </summary>
public sealed record KernelDenial(KernelOperation Operation, int ProcessId, int StoreIndex, string Path, string Image);

/// <summary>The driver's live policy and its counters since it loaded (BRUCE_STATUS).</summary>
public sealed record KernelStatus(uint Version, bool Blocking, uint StoreCount, uint TrustedCount,
    uint Denied, uint Rechecked, uint NotifyDropped, uint ProcessGuard = 0)
{
    /// <summary>BRUCE_GUARD_ACTIVE: the handle callbacks that protect trusted processes are registered.</summary>
    public bool ProcessGuardActive => (ProcessGuard & 1) != 0;
    /// <summary>BRUCE_GUARD_ENUMERATED: the processes running at driver load are covered too.</summary>
    public bool ProcessGuardCoversRunning => (ProcessGuard & 2) != 0;
}

/// <summary>
/// User-mode side of the BruceFilter minifilter, protocol 2 (kernel\BruceFilter\BruceFilter.h).
///
/// Policy is built in the driver's staging copy (ClearPolicy, the guarded stores, the images
/// trusted for them) and swapped in whole by CommitPolicy; SetBlocking switches enforcement on
/// the live copy. Every refusal comes back through <see cref="StartNotifications"/>, with
/// <see cref="OutstandingReads"/> overlapped FilterGetMessage calls kept waiting on a background
/// thread. The driver never waits for this reader: a refusal that arrives while no read is
/// outstanding is dropped and counted (<see cref="KernelStatus.NotifyDropped"/>), and the
/// refusal itself stands either way.
///
/// The driver's port admits LocalSystem only, so only the agent's Windows service connects. A
/// driver that does not answer QueryStatus with protocol 2 is refused: the older driver denies
/// every process, the owning browser included, and this agent must never switch that on.
///
/// One client is one connection: when its reader stops (the driver unloaded, the port closed)
/// it is finished, and <see cref="KernelSupervisor{TPort}"/> reconnects with a new one.
///
/// The wire layouts are encoded by hand, byte for byte; MinifilterClientTests pins them
/// against BruceFilter.h.
/// </summary>
public sealed class MinifilterClient : IKernelPort
{
    internal const string PortName = @"\BruceFilterPort";
    internal const uint ProtocolVersion = 2;
    internal const int MaxPath = 260;                        // BRUCE_MAX_PATH, terminator included
    internal const int MaxStores = 64;                       // BRUCE_MAX_ENTRIES
    internal const int MaxTrusted = 64;                      // BRUCE_MAX_TRUSTED
    internal const uint AnyStore = 0xFFFFFFFF;               // BRUCE_ANY_PREFIX
    internal const int MessageSize = 8 + MaxPath * 2;        // BRUCE_MESSAGE
    internal const int StatusSize = 32;                      // BRUCE_STATUS
    internal const int HeaderSize = 16;                      // FILTER_MESSAGE_HEADER
    internal const int NotificationSize = 16 + MaxPath * 4;  // BRUCE_NOTIFICATION
    /// <summary>Reads kept waiting at once. With one, the lab VMs lost up to a third of the refusals in a burst.</summary>
    internal const int OutstandingReads = 8;

    /// <summary>BRUCE_COMMAND.</summary>
    internal enum Command : uint
    {
        SetBlocking = 1,
        AddSensitivePath = 2,
        ClearPolicy = 3,
        AddTrustedImage = 4,
        CommitPolicy = 5,
        QueryStatus = 6
    }

    private const int S_OK = 0;
    private const int HResultFileNotFound = unchecked((int)0x80070002);
    private const int HResultAccessDenied = unchecked((int)0x80070005);
    private const int HResultIoPending = unchecked((int)0x800703E5);
    private const int ErrorOperationAborted = 995;

    private readonly Logger _log;
    private readonly object _gate = new();
    private readonly ManualResetEvent _stop = new(false);
    private SafeFileHandle? _port;
    private Thread? _reader;
    private bool _disposed;

    public MinifilterClient(Logger log) => _log = log;

    public bool Connected
    {
        get { lock (_gate) return _port is not null && !_disposed; }
    }

    /// <summary>
    /// Connects and checks the driver's protocol. False, with the reason logged, when the
    /// driver is not loaded, refuses this account, or speaks another protocol.
    /// </summary>
    public bool TryConnect() => Connect() == KernelConnect.Connected;

    /// <summary>
    /// <see cref="TryConnect"/> with the reason told apart: a driver that is not loaded is what a
    /// reconnect loop waits for, anything else is a refusal it keeps trying.
    /// </summary>
    internal KernelConnect Connect()
    {
        try
        {
            int hr = FilterConnectCommunicationPort(PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out var port);
            if (hr != S_OK)
            {
                port.Dispose();
                _log.Info(hr switch
                {
                    HResultFileNotFound => @"minifilter not loaded (no \BruceFilterPort); kernel enforcement unavailable",
                    HResultAccessDenied => "minifilter refused the connection: its port admits the LocalSystem service only, " +
                                           "so kernel enforcement needs the agent running as the service",
                    _ => $"minifilter not connected (hr=0x{hr:X8}); kernel enforcement unavailable"
                });
                return hr == HResultFileNotFound ? KernelConnect.NotLoaded : KernelConnect.Failed;
            }
            lock (_gate) _port = port;

            var status = QueryStatus();
            if (status is null || status.Version != ProtocolVersion)
            {
                _log.Info($"minifilter speaks protocol {(status is null ? "1 or unknown" : status.Version.ToString())}, " +
                          $"this agent needs {ProtocolVersion}: disconnected, kernel enforcement unavailable. " +
                          "Install the BruceFilter.sys built from this release.");
                Disconnect();
                return KernelConnect.Failed;
            }
            _log.Info($"minifilter connected (protocol {ProtocolVersion}); live policy: {status.StoreCount} store(s), " +
                      $"{status.TrustedCount} trusted image(s), blocking {(status.Blocking ? "ON" : "off")}, " +
                      (status.ProcessGuardActive
                          ? "process guard on" + (status.ProcessGuardCoversRunning ? "" : " (programs already running at driver load are not covered)")
                          : "process guard OFF (handles to trusted programs are not restricted)"));
            return KernelConnect.Connected;
        }
        catch (DllNotFoundException)
        {
            _log.Info("fltlib unavailable; kernel enforcement unavailable");
            return KernelConnect.Failed;
        }
        catch (Exception ex)
        {
            _log.Error("minifilter connect", ex);
            Disconnect();
            return KernelConnect.Failed;
        }
    }

    KernelConnect IKernelPort.Connect() => Connect();

    /// <summary>Switches enforcement on the live policy.</summary>
    public bool SetBlocking(bool enabled) => Send(Command.SetBlocking, enabled ? 1u : 0u, "");

    /// <summary>Empties the staging copy. The live policy is untouched until <see cref="CommitPolicy"/>.</summary>
    public bool ClearPolicy() => Send(Command.ClearPolicy, 0, "");

    /// <summary>Swaps the staging copy in, keeping the live blocking state.</summary>
    public bool CommitPolicy() => Send(Command.CommitPolicy, 0, "");

    /// <summary>
    /// Stages one guarded store, a directory fragment such as \google\chrome\user data\. The
    /// driver numbers stores in the order it accepts them. A fragment the wire struct cannot
    /// carry whole is refused here: cut short, it would be a broader one.
    /// </summary>
    public bool AddSensitivePath(string fragment) => IsWireText(fragment) && Send(Command.AddSensitivePath, 0, fragment);

    /// <summary>Stages an image (full NT path) trusted for one store, or for every store when <paramref name="storeIndex"/> is -1.</summary>
    public bool AddTrustedImage(string ntImagePath, int storeIndex) =>
        IsWireText(ntImagePath) && storeIndex >= -1 &&
        Send(Command.AddTrustedImage, storeIndex < 0 ? AnyStore : (uint)storeIndex, ntImagePath);

    /// <summary>The driver's protocol, live policy size and counters, or null when it does not answer.</summary>
    public KernelStatus? QueryStatus()
    {
        var reply = new byte[StatusSize];
        return Send(Command.QueryStatus, 0, "", reply, out int replied) && replied >= StatusSize ? DecodeStatus(reply) : null;
    }

    /// <summary>
    /// Starts the background reader that hands each refusal to <paramref name="onDenial"/>. The
    /// handler runs on the reader thread and must be quick: refusals that arrive while every
    /// read is taken are dropped and counted by the driver.
    /// <paramref name="onStopped"/> runs once, on the reader thread, when the reader ends for any
    /// reason but <see cref="Dispose"/>: the driver unloaded, the port closed, a read failed. It is
    /// told why, after the reads are cancelled and the buffers freed. Without it the reason is logged.
    /// </summary>
    public bool StartNotifications(Action<KernelDenial> onDenial, Action<string>? onStopped = null)
    {
        lock (_gate)
        {
            if (_disposed || _port is null || _reader is not null) return false;
            var port = _port;
            _reader = new Thread(() => ReadNotifications(port, onDenial, onStopped))
            {
                IsBackground = true,
                Name = "BruceFilter notifications"
            };
            _reader.Start();
            return true;
        }
    }

    // ------------------------------------------------------------------ wire format

    /// <summary>True when the text fits BRUCE_MESSAGE.Path whole, terminator included.</summary>
    internal static bool IsWireText(string? text) => !string.IsNullOrEmpty(text) && text.Length < MaxPath && !text.Contains('\0');

    /// <summary>BRUCE_MESSAGE: Command, Flag, then Path as UTF-16 with the rest zeroed.</summary>
    internal static byte[] EncodeMessage(Command command, uint flag, string path)
    {
        if (path.Length >= MaxPath || path.Contains('\0'))
            throw new ArgumentException("the path does not fit BRUCE_MESSAGE", nameof(path));
        var bytes = new byte[MessageSize];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0, 4), (uint)command);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4, 4), flag);
        Encoding.Unicode.GetBytes(path, bytes.AsSpan(8));
        return bytes;
    }

    internal static KernelStatus? DecodeStatus(ReadOnlySpan<byte> reply)
    {
        if (reply.Length < StatusSize) return null;
        return new KernelStatus(U32(reply, 0), U32(reply, 4) != 0, U32(reply, 8), U32(reply, 12),
            U32(reply, 16), U32(reply, 20), U32(reply, 24), U32(reply, 28));
    }

    /// <summary>A BRUCE_NOTIFICATION (the bytes after FILTER_MESSAGE_HEADER), or null if it is not one.</summary>
    internal static KernelDenial? DecodeNotification(ReadOnlySpan<byte> body)
    {
        if (body.Length < NotificationSize) return null;
        uint version = U32(body, 0), operation = U32(body, 4), pid = U32(body, 8), store = U32(body, 12);
        if (version != ProtocolVersion || operation < 1 || operation > 6 || pid > int.MaxValue) return null;
        return new KernelDenial((KernelOperation)operation, (int)pid, store < MaxStores ? (int)store : -1,
            WireText(body.Slice(16, MaxPath * 2)), WireText(body.Slice(16 + MaxPath * 2, MaxPath * 2)));
    }

    private static uint U32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(offset, 4));

    private static string WireText(ReadOnlySpan<byte> field)
    {
        var text = Encoding.Unicode.GetString(field);
        int end = text.IndexOf('\0');
        return end < 0 ? text : text[..end];
    }

    // ------------------------------------------------------------------ transport

    private bool Send(Command command, uint flag, string path) => Send(command, flag, path, Array.Empty<byte>(), out _);

    private unsafe bool Send(Command command, uint flag, string path, byte[] reply, out int replied)
    {
        replied = 0;
        SafeFileHandle? port;
        lock (_gate) port = _disposed ? null : _port;
        if (port is null) return false;

        byte[] message = EncodeMessage(command, flag, path);
        try
        {
            int hr;
            uint bytes;
            fixed (byte* input = message)
            fixed (byte* output = reply)
                hr = FilterSendMessage(port, input, (uint)message.Length, output, (uint)reply.Length, out bytes);
            if (hr != S_OK)
            {
                _log.Info($"minifilter {command} refused (hr=0x{hr:X8})");
                return false;
            }
            replied = (int)Math.Min(bytes, (uint)reply.Length);
            return true;
        }
        catch (ObjectDisposedException)
        {
            return false;   // disposed while the call was being set up
        }
    }

    private unsafe void ReadNotifications(SafeFileHandle port, Action<KernelDenial> onDenial, Action<string>? onStopped)
    {
        string? reason = null;
        const int size = HeaderSize + NotificationSize;
        var buffers = new IntPtr[OutstandingReads];
        var overlapped = new IntPtr[OutstandingReads];
        var ready = new ManualResetEvent[OutstandingReads];
        var pending = new bool[OutstandingReads];
        var waits = new WaitHandle[OutstandingReads + 1];
        waits[0] = _stop;   // first, so a stop wins over a read that completed at the same time
        for (int i = 0; i < OutstandingReads; i++)
        {
            buffers[i] = (IntPtr)NativeMemory.AllocZeroed(size);
            overlapped[i] = (IntPtr)NativeMemory.AllocZeroed((nuint)sizeof(NativeOverlapped));
            ready[i] = new ManualResetEvent(false);
            waits[i + 1] = ready[i];
        }

        bool Post(int slot)
        {
            new Span<byte>((void*)buffers[slot], size).Clear();
            var ov = (NativeOverlapped*)overlapped[slot];
            *ov = default;
            ov->EventHandle = ready[slot].SafeWaitHandle.DangerousGetHandle();
            ready[slot].Reset();
            int hr = FilterGetMessage(port, (byte*)buffers[slot], size, ov);
            if (hr != S_OK && hr != HResultIoPending)
            {
                reason = $"a read of the driver's port failed (hr=0x{hr:X8})";
                return false;
            }
            pending[slot] = true;
            return true;
        }

        try
        {
            bool running = true;
            for (int i = 0; i < OutstandingReads && running; i++) running = Post(i);
            while (running)
            {
                int signalled = WaitHandle.WaitAny(waits);
                if (signalled == 0) break;
                int slot = signalled - 1;
                bool ok = GetOverlappedResult(port, (NativeOverlapped*)overlapped[slot], out _, false);
                int error = ok ? 0 : Marshal.GetLastWin32Error();
                pending[slot] = false;
                if (!ok)
                {
                    reason = error == ErrorOperationAborted
                        ? "a read of the driver's port was cancelled"
                        : $"a read of the driver's port failed (error {error})";
                    break;
                }

                var denial = DecodeNotification(new ReadOnlySpan<byte>((byte*)buffers[slot] + HeaderSize, NotificationSize));
                if (denial is not null)
                {
                    try { onDenial(denial); }
                    catch (Exception ex) { _log.Error("kernel refusal handler", ex); }
                }
                running = Post(slot);
            }
        }
        catch (Exception ex)
        {
            _log.Error("minifilter notifications", ex);   // the reader must never take the agent down
            reason ??= $"the notification reader failed ({ex.GetType().Name})";
        }
        finally
        {
            // The kernel may write into a buffer until its read is over, so each outstanding read
            // is cancelled and waited out; if one cannot be, every buffer is left to the process.
            bool idle = true;
            for (int i = 0; i < OutstandingReads; i++)
            {
                if (!pending[i]) continue;
                try
                {
                    var ov = (NativeOverlapped*)overlapped[i];
                    CancelIoEx(port, ov);
                    GetOverlappedResult(port, ov, out _, true);   // returns once the cancel has landed
                    pending[i] = false;
                }
                catch (Exception) { idle = false; }
            }
            if (idle)
            {
                for (int i = 0; i < OutstandingReads; i++)
                {
                    NativeMemory.Free((void*)overlapped[i]);
                    NativeMemory.Free((void*)buffers[i]);
                    ready[i].Dispose();
                }
            }
            ReportStopped(reason, onStopped);
        }
    }

    // A stop that Dispose asked for is not reported; any other end of the reader is.
    private void ReportStopped(string? reason, Action<string>? onStopped)
    {
        bool disposing;
        lock (_gate) disposing = _disposed;
        if (disposing) return;
        reason ??= "the driver closed the port";
        try
        {
            if (onStopped is not null) onStopped(reason);
            else _log.Info($"minifilter notifications stopped: {reason}");
        }
        catch (Exception ex) { _log.Error("minifilter stop handler", ex); }
    }

    private void Disconnect()
    {
        SafeFileHandle? port;
        lock (_gate)
        {
            port = _port;
            _port = null;
        }
        port?.Dispose();
    }

    public void Dispose()
    {
        Thread? reader;
        SafeFileHandle? port;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            reader = _reader;
            port = _port;
            _port = null;
        }
        _stop.Set();
        // The reader cancels its own read and waits for the cancel to land before freeing the
        // buffers the kernel writes into; the port closes only after that.
        bool stopped = reader is null || reader == Thread.CurrentThread || reader.Join(TimeSpan.FromSeconds(5));
        if (!stopped) _log.Info("minifilter notification reader did not stop within 5 s; closing the port regardless");
        port?.Dispose();
        if (stopped && reader != Thread.CurrentThread) _stop.Dispose();
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, IntPtr lpContext, ushort wSizeOfContext,
        IntPtr lpSecurityAttributes, out SafeFileHandle hPort);

    [DllImport("fltlib.dll")]
    private static extern unsafe int FilterSendMessage(
        SafeFileHandle hPort, byte* lpInBuffer, uint dwInBufferSize,
        byte* lpOutBuffer, uint dwOutBufferSize, out uint lpBytesReturned);

    [DllImport("fltlib.dll")]
    private static extern unsafe int FilterGetMessage(
        SafeFileHandle hPort, byte* lpMessageBuffer, uint dwMessageBufferSize, NativeOverlapped* lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool CancelIoEx(SafeFileHandle hFile, NativeOverlapped* lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool GetOverlappedResult(
        SafeFileHandle hFile, NativeOverlapped* lpOverlapped, out uint lpNumberOfBytesTransferred,
        [MarshalAs(UnmanagedType.Bool)] bool bWait);
}

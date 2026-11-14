using BruceEDR.Core;

namespace BruceEDR.Driver;

/// <summary>
/// Hands each driver refusal to the detection engine as a <see cref="SignalKind.KernelRefusal"/>
/// signal, so a process the kernel kept out of a credential store is scored and correlated like
/// one that read it.
///
/// The ACTION-event throttle (<see cref="KernelDenialThrottle"/> at 60 a minute) must not decide
/// what the engine sees, and an unbounded stream must not fill the signal queue that every
/// monitor shares. So the feed has its own throttle: one signal per process and store a minute
/// (the engine scores a store once per process anyway), and a cap far above anything a real
/// sweep needs. A refusal held back here costs the engine nothing it would have used.
/// </summary>
public sealed class KernelRefusalFeed
{
    internal const int PerMinute = 512;

    private readonly Action<Signal> _submit;
    private readonly KernelDenialThrottle _throttle = new(TimeSpan.FromMinutes(1), PerMinute);

    public KernelRefusalFeed(Action<Signal> submit) => _submit = submit;

    /// <summary>
    /// Submits the refusal unless this process was already reported for this store within the
    /// window. <paramref name="store"/> is null when the driver refused a name it could not resolve;
    /// <paramref name="path"/> and <paramref name="image"/> are drive-letter paths. True when submitted.
    /// A process guard report is not submitted: it says a process asked a trusted program for wide
    /// access, which debuggers and task managers do too, not that it reached for a store, and the
    /// cross-process rule already scores the requests that could inject.
    /// </summary>
    public bool Offer(KernelDenial denial, string? store, string path, string image, DateTime nowUtc)
    {
        if (denial.ProcessId <= 0) return false;
        if (denial.Operation is KernelOperation.ProcessHandle or KernelOperation.ThreadHandle) return false;
        if (!_throttle.Admit($"{denial.ProcessId}|{store}", nowUtc, out _)) return false;
        _submit(ToSignal(denial, store, path, image, nowUtc));
        return true;
    }

    internal static Signal ToSignal(KernelDenial denial, string? store, string path, string image, DateTime nowUtc) => new()
    {
        Kind = SignalKind.KernelRefusal,
        Pid = denial.ProcessId,
        ProcessName = image.Length > 0 ? System.IO.Path.GetFileName(image) : "",
        ImagePath = image,
        FilePath = path,
        Detail = KernelRefusalDetail.Format(OperationName(denial.Operation), store),
        TimestampUtc = nowUtc
    };

    private static string OperationName(KernelOperation operation) => operation switch
    {
        KernelOperation.Rename => "rename",
        KernelOperation.Link => "link",
        KernelOperation.Reopen => "reopen",
        _ => "open"
    };
}

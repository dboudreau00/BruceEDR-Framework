# Process guard

Closes the main residual of BruceFilter's file guard: the file guard trusts a program by image
path, so code running as the same user can reach a trusted browser through its process instead
of through its files. It ran in the lab VMs (Windows 10 21H2 under Driver Verifier, Windows 11
22H2): lab rows 43 to 49 pass and the driver unloads clean after them. Section 9 lists what is
still unproven.

## 1. Threats addressed

The file guard refuses opens of a guarded store (`\google\chrome\user data\`) unless the
requesting process image is trusted for it. Neither of these makes a file open the minifilter sees:

| Attack | Needs a handle to the trusted process with | Result without the guard |
|--------|-------------------------------------------|--------------------------|
| Duplicate the browser's own open handle to `Cookies` or `Login Data` (`DuplicateHandle`) | `PROCESS_DUP_HANDLE` | A file handle with the browser's access, no create |
| Same, through the pseudo handle: duplicating `GetCurrentProcess()` out of the browser yields a handle with maximum access to it (the warning on the [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) page) | `PROCESS_DUP_HANDLE` | Everything below |
| Write code into the browser (`WriteProcessMemory`, `VirtualProtectEx`) and run it (`CreateRemoteThread`, APC, thread hijack) | `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`, `THREAD_SET_CONTEXT`, `THREAD_SUSPEND_RESUME` | The stealer runs as the trusted image |
| Attach a debugger, set an instrumentation callback or a debug object | `PROCESS_SET_INFORMATION`, `PROCESS_SUSPEND_RESUME` | Control of the browser's execution |
| Start a child with the browser as its parent, inheriting the browser's inheritable handles | `PROCESS_CREATE_PROCESS` | Handles the child was never given |

The guard removes those rights from the handle. The request still succeeds, with fewer rights, so a
program that asked for more than it needs keeps working.

## 2. Design in one paragraph

`BruceProcessGuard.c` tracks every process with its image path (new processes from
`PsSetCreateProcessNotifyRoutineEx`, running ones from one enumeration at load) and, for each, a
64-bit trust mask: bit `p` is set when the image is trusted for guarded fragment `p`. An image
trusted for every store has every bit of the live policy's fragments set. `ObRegisterCallbacks`
registers one pre-operation callback for `PsProcessType` and `PsThreadType`, create and duplicate.
While blocking is on, when a request holds a right in the strip mask, the callback looks up the
target process (a thread's owning process) and the process that would receive the handle. If the
target's mask is not zero, and the receiver is not the target itself, not exempt (section 4: the
target's creator is), and its mask does not contain every bit of the target's, the callback removes
the strip mask from `DesiredAccess` and queues a report.

The pure decisions are `BrucePolicyTrustMask`, `BruceGuardCares` and `BruceGuardAccess` in
`BruceFilterPolicy.c`, compiled into the driver and into `test\PolicyTests.c`.

## 3. The masks, and why

Process handles (`BRUCE_PROCESS_STRIP` = `0x0AEA`):

| Right | Value | Removed | Reason |
|-------|-------|---------|--------|
| `PROCESS_CREATE_THREAD` | 0x0002 | yes | remote thread |
| `PROCESS_VM_OPERATION` | 0x0008 | yes | `VirtualProtectEx`, `WriteProcessMemory` |
| `PROCESS_VM_WRITE` | 0x0020 | yes | `WriteProcessMemory` |
| `PROCESS_DUP_HANDLE` | 0x0040 | yes | the file-handle theft and the pseudo-handle escalation |
| `PROCESS_CREATE_PROCESS` | 0x0080 | yes | handle inheritance through a spoofed parent |
| `PROCESS_SET_INFORMATION` | 0x0200 | yes | debug object, token, instrumentation callback |
| `PROCESS_SUSPEND_RESUME` | 0x0800 | yes | suspend, resume, debugger attach |
| `PROCESS_TERMINATE` | 0x0001 | **kept** | a hung browser must stay killable (Task Manager, `taskkill`, installers); killing it exposes nothing |
| `PROCESS_VM_READ` | 0x0010 | **kept** | see the residuals: not in the documented list of rights a callback may remove, and AV, task managers, profilers and the agent's own memory scan need it |
| `PROCESS_QUERY_INFORMATION`, `PROCESS_QUERY_LIMITED_INFORMATION` | 0x0400, 0x1000 | **kept** | every monitor and the shell need them; they reveal no secret |
| `PROCESS_SET_QUOTA`, `PROCESS_SET_LIMITED_INFORMATION`, `SYNCHRONIZE`, standard rights | | **kept** | working-set trim, priority class on current Windows, waiting |

Thread handles (`BRUCE_THREAD_STRIP` = `0x0232`):

| Right | Value | Removed | Reason |
|-------|-------|---------|--------|
| `THREAD_SUSPEND_RESUME` | 0x0002 | yes | hijack: suspend, set context, resume |
| `THREAD_SET_CONTEXT` | 0x0010 | yes | `SetThreadContext`, `QueueUserAPC` |
| `THREAD_SET_INFORMATION` | 0x0020 | yes | per the brief; limits what can be done to a thread other than tuning it |
| `THREAD_DIRECT_IMPERSONATION` | 0x0200 | yes | per the brief |
| `THREAD_TERMINATE`, `THREAD_GET_CONTEXT`, `THREAD_QUERY_*`, `THREAD_SET_LIMITED_INFORMATION` | | **kept** | debuggers and profilers read; none of these moves execution |

Every removed right is in the list Microsoft documents as modifiable by a callback
([OB_PRE_CREATE_HANDLE_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_create_handle_information)).
`THREAD_RESUME` (0x1000) is not in that list and is not touched; `ResumeThread` needs
`THREAD_SUSPEND_RESUME`, which is removed. The tests compare every constant with the SDK's own.

A request that names no right (`MAXIMUM_ALLOWED`, `GENERIC_ALL`) cannot be stripped bit by bit, and
Microsoft does not say whether the system resolves it before the callback runs. The guard replaces
those two wildcards with `0x1FFFFF` (all access, the same for processes and threads) and then
removes the strip mask, and drops `GENERIC_WRITE`. This is the only place the guard writes a right
the caller did not ask for by name, and only to hand back less than the wildcard could have.
UNVERIFIED in a VM (scenario P7).

## 4. Who is not stripped

| Case | How it is decided | Why |
|------|-------------------|-----|
| Kernel handles (`KernelHandle`) | the flag in `OB_PRE_OPERATION_INFORMATION` | drivers and the system itself |
| The target's own process (a thread of the browser opening its own threads, a process opening itself) | receiver equals target | the trusted program using itself |
| A receiver trusted for every store the target is trusted for | `(TargetTrust & ~ReceiverTrust) == 0` | Chrome's browser and its renderers, GPU and utility processes are one image, so they trust each other; Edge is not trusted by Chrome's mask, nor a backup agent trusted for one store by a browser trusted for another |
| System (`PsInitialSystemProcess`) and every protected process (PP or PPL) | `PsIsProtectedProcess`, `PsIsProtectedProcessLight` | csrss, services, wininit, lsass when protected, and the antimalware engine run as PPL; user-mode code cannot start or inject one, and Windows needs their handles whole |
| The agent's service process | the process that sent the last message on the SYSTEM-only port | containment suspends and kills through handles to the processes it responds to, and its memory scan reads them |
| The process that created the target | recorded, and referenced, by the process notify routine, which runs in the creating thread | the thread handle `CreateProcess` gets back is made after the notify routine ran; stripped, the creator cannot resume the first thread, so Explorer, Task Scheduler or a browser's updater could not start a trusted program (the lab saw Task Scheduler fail with access denied). See residual 1 |
| Blocking off | `gLive.Blocking` | debuggers, installers and diagnostics work as before; this is the switch for debugging a trusted browser |

For a duplicate, the receiver is `DuplicateHandleInformation.TargetProcess`, the process that ends
up holding the handle, not the caller; for a create it is the calling process.

Decided against:

- **Lineage beyond the creator** (a parent named with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, and
  the target's children). Anything the browser launches, a downloaded program included, would
  inherit them. Trust is by image, as in the file guard, and a renderer is exempt because its image
  is the browser's.
- **Windows Error Reporting.** `WerFault.exe` is not protected, and a hollowed copy of it started
  suspended by malware would inherit an exemption by image path. The cost of not exempting it is
  small: the browser's own crash handler (Crashpad, `chrome.exe` itself) is trusted, and a WER
  dump of a trusted browser loses the handle data (`MiniDumpWriteDump` documents
  `PROCESS_DUP_HANDLE` for it). If that matters, trust the dump tool in `kernelTrustedImages`.
- **System32 path exemptions** for csrss and friends: the same hollowing argument, and the
  protected-process test already covers them.
- **Debuggers while blocking is on.** Attaching to a trusted browser needs
  `PROCESS_SUSPEND_RESUME` and more. Turn blocking off, or trust the debugger.

## 5. Constraints checked

| Constraint | Handling | Source |
|------------|----------|--------|
| `ObRegisterCallbacks` returns `STATUS_ACCESS_DENIED` when the callbacks do not reside in a signed kernel image | the image is linked with `/INTEGRITYCHECK` (`build.ps1`, `BruceFilter.vcxproj`); the build output has `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` (0x80) set, read from the PE header | [ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks), [/INTEGRITYCHECK](https://learn.microsoft.com/en-us/cpp/build/reference/integritycheck-require-signature-check) |
| `PsSetCreateProcessNotifyRoutineEx` needs `FORCE_INTEGRITY` too | same flag; failure leaves the file guard running alone | [PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex) |
| The pre-operation callback runs at PASSIVE_LEVEL in an arbitrary thread with normal APCs disabled, and should stay short, make no registry or IPC calls, not wait on other threads, and queue slow work to a system worker | the callback does two list lookups under a shared push lock (`FltAcquirePushLockShared`, which disables normal APCs itself), allocates a small report, and `FltQueueGenericWorkItem` sends it with a zero timeout from a worker | [POB_PRE_OPERATION_CALLBACK](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-pob_pre_operation_callback), [Process and thread manager best practices](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager), [FltAcquirePushLockShared](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltacquirepushlockshared), [FltQueueGenericWorkItem](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueuegenericworkitem) |
| No `SeLocateProcessImageName` in the callback | the image is read once per process in the process notify routine (PASSIVE_LEVEL, creating thread's context) and stored; the callback only compares | [SeLocateProcessImageName](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-selocateprocessimagename) (PASSIVE_LEVEL) |
| An altitude string | `GUARD_ALTITUDE` = `385201`, a PLACEHOLDER like the INF's; a collision returns `STATUS_FLT_INSTANCE_ALTITUDE_COLLISION` and the guard stays off | [OB_CALLBACK_REGISTRATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration) |
| `ObUnRegisterCallbacks` before unload and on failure | `BruceProcessGuardStop`, called first in `BruceUnload` and from `BruceProcessGuardStart` when registration fails | [ObUnRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obunregistercallbacks) |
| Remove must wait for in-flight notify routines | documented for `PsSetCreateProcessNotifyRoutineEx(Remove=TRUE)`; for the handle callbacks the page does not say, so the driver counts callbacks in flight and report work items not yet freed, and waits for both to reach zero; nothing new is queued once stop has begun | same pages |
| Filter Verifier charges a Filter Manager call to the driver at the call's return address | the report worker's `FltFreeGenericWorkItem` is not its last call: compiled as a tail call it is charged to no one, reads as a leaked work item at unload, and stops a machine that has no debugger attached (it did, twice, in the lab). `build.ps1` fails a build in which a tracked free or release is a tail call | [File System Filter Verification](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/file-system-filter-verification#filter-verifier-violations) |
| Policy changes re-evaluate | `BruceProcessGuardPolicyChanged` after every commit | below |

## 6. The table, the locks, and the processes that were already running

- **Entries** are keyed by `PEPROCESS` and hold a reference on it until the process exits (the
  notify routine runs once more, with no `CreateInfo`), so a pointer cannot be reused while it is in
  the table, and a reference on the process that created it (none for a process found at load).
  They hold the image NT path as `SeLocateProcessImageName` reports it, the same form
  the file guard compares, so the two guards agree on who is trusted. A process whose name could
  not be had is tracked with trust zero: never protected, never trusted.
- **Locks.** `gLock` (a filter-manager push lock) guards the table. Order is policy lock, then
  `gLock`. The handle callback takes only `gLock`, shared, and only after a request has passed the
  cheap exits: guard running, blocking on, not a kernel handle, at least one protected process,
  a right in the strip mask requested, receiver not the target and not exempt.
- **Processes running when the driver loads.** The notify routine is registered first, then
  `ZwQuerySystemInformation(SystemProcessInformation)` lists the processes and each is looked up
  with `PsLookupProcessByProcessId`; a process seen twice is dropped the second time. This runs once,
  at load, before the filter takes any call, so the sweep never holds a lock the file guard needs.
  The alternatives were a per-commit rescan (every commit would walk the process list while holding
  the locks; unnecessary, because every process's name is already stored and a commit only recomputes
  masks, a few thousand comparisons) and a brute-force `PsLookupProcessByProcessId` walk (no upper
  bound for a process id). `ZwQuerySystemInformation` has no kernel header and no kernel
  documentation (Learn documents it for `ntdll` only, with the warning that it may change), so it is
  resolved with `MmGetSystemRoutineAddress`; if it cannot be found the guard runs without the
  `BRUCE_GUARD_ENUMERATED` flag and covers only processes started after load.
- **Policy commits.** `BruceCommitPolicy` releases the policy lock and calls
  `BruceProcessGuardPolicyChanged`, which takes the policy lock shared and `gLock` exclusive and
  recomputes every mask. A process created at the same moment computes its mask under the same
  policy lock, so it cannot keep a stale one.
- **The agent.** `BrucePortMessage` runs in the context of the caller (the documented
  [PFLT_MESSAGE_NOTIFY](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_message_notify)
  buffers are valid only there), and only the SYSTEM client the port admits can send, so the process
  of the latest message is the agent. It is referenced, and released on disconnect and on unload.
  The connect callback's context is not documented, so it is not used.
- **Reports.** Operation 5 (process handle) and 6 (thread handle). `ProcessId` and `Image` are the
  receiver; `Path` is the trusted target's image; `PrefixIndex` the first store it is trusted for.
  At most 64 are queued; more are dropped and counted. The count in `BRUCE_STATUS.Denied` now includes
  them.

## 7. Failure policy

The file guard never waits on the process guard. If the guard cannot start (the protected-process
routines cannot be resolved, `/INTEGRITYCHECK` missing, an altitude collision, no memory), the
driver loads and the file guard runs alone; `BRUCE_STATUS.ProcessGuard` is 0 and the agent logs
"process guard OFF". The alternative, refusing to load, would turn a missing second layer into the
loss of the first. The protected-process routines (`PsIsProtectedProcess`,
`PsIsProtectedProcessLight`) are exported by the kernel but have no Learn page; the guard resolves
them with [MmGetSystemRoutineAddress](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmgetsystemroutineaddress)
and does not start without them, because stripping csrss's handles could break the system.

## 8. Protocol

Version stays 2. Nothing changes layout: `BRUCE_STATUS.Reserved` became `ProcessGuard` (flags
`BRUCE_GUARD_ACTIVE`, `BRUCE_GUARD_ENUMERATED`, 0 from a driver without the guard), and two
`BRUCE_OPERATION` values were added, which an agent from before this change drops. Updated
together: `BruceFilter.h`, `Driver/MinifilterClient.cs` (the two operations, the status field, the
connect log line), `Hosting/Hosting.cs` (the ACTION event text), and `MinifilterClientTests.cs`
(which pins the enum values and the flags against the header).

## 9. Residuals, and what only a VM can prove

Residuals:

1. **The creator of a trusted process keeps full access to it.** The creator is exempt (section 4),
   because without that no untrusted program could start a trusted one: the lab's Task Scheduler
   start of the trusted copy failed with access denied. So a program can start its own `chrome.exe`
   suspended, write into it and resume it (lab row 44, a known limit), whichever order Windows makes
   the creator's process handle in. `NtCreateProcessEx`, which makes a process with no thread, gives
   the same. What the guard stops is reaching into a trusted program someone else started (rows 45
   to 47). A narrower exemption would leave the creator only what a start needs (resuming the first
   thread) and strip writing. That needs the creator's process handle stripped too, and if Windows
   makes it before the notify routine runs, a different signal: a minifilter pre-operation on the
   image section of a trusted image (`IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`), remembered for
   the creating thread.
2. **`PROCESS_VM_READ` is kept.** Reading a browser's memory (infostealers do it for cookies held
   decrypted in memory) is not stopped. The documented list of rights a callback can remove does not
   include it, and removing it would break antivirus, task managers and profilers. The agent's memory
   scan and detection rules are the answer there.
3. **Handles that predate the guard or blocking, and inherited handles.** A handle opened before
   blocking was switched on keeps its rights; handle inheritance (`bInheritHandles`) is not a
   callback operation as far as the documentation says (UNVERIFIED).
4. **A trusted image is still trusted by path.** Code that runs inside a trusted process after
   exploiting the browser itself is out of scope, as before.
5. **Per-user installs, helpers and 8.3 paths** are trusted or refused exactly as the file guard
   does: the same trust list.
6. **Administrators** can unload the driver or detach it. Short of that the callback strips for
   everyone not exempt, administrators and processes holding `SeDebugPrivilege` included.
7. **Compatibility.** While blocking is on, Process Explorer's handle view, WinDbg, Visual Studio's
   debugger, Task Manager's "Create dump file" with handle data, tools that inject into a browser
   (accessibility or capture add-ons that use `CreateRemoteThread`), and Windows Error Reporting's
   dump handle data lose rights on a trusted browser. Turn blocking off to debug one.

Shown in the lab VMs (Windows 10 21H2 under Driver Verifier, Windows 11 22H2):

- the driver loads with `/INTEGRITYCHECK` under test signing, and both registrations succeed
  (`process guard on` in `BruceLab.exe status`);
- `SeLocateProcessImageName` returns the trusted path inside the notify routine, so a trusted copy
  started after load is protected (rows 45 to 47);
- an untrusted program can start the trusted copy (row 43), the stripped rights refuse a memory
  write, a handle copy and a thread suspend, each with its report (rows 45 to 47), and the trusted
  copy and blocking off keep every right (rows 48, 49);
- the driver unloads clean under Driver Verifier after the guard has sent reports; the first
  build did not (section 5, the tail call), and stopped the VM twice;
- the agent service runs end to end with the guard on.

Still to show:

- the real access a handle gets for each mask in section 3 (an `access` verb that reads the
  granted mask);
- whether `MAXIMUM_ALLOWED` and `GENERIC_ALL` reach the callback unresolved, and what the system
  does with the explicit rights the guard substitutes;
- csrss, services, Defender (`MsMpEng`), `lsass`, WerFault and Explorer keep working with Chrome or
  Edge running and blocking on, and a normal browser session (start, sandboxed renderers, crash
  handler, update, Task Manager "End task") works;
- the cost per handle request (the fast exit should make it unmeasurable).

## 10. How to test it in the VM, and proposed BruceLab scenarios

Build (`build.ps1`), then `lab.ps1 prepare`, `testsigning`, `install`, `test` as before. The new
image carries `FORCE_INTEGRITY`, so it only loads signed: the lab's test signing covers that. Check
`BruceLab.exe status`: it prints `process guard on`. The file guard's scenarios must still pass
with the guard on during them.

BruceLab runs part of the table below as rows 43 to 49. The harness keeps a trusted copy running
(`probe hold <seconds>`) and the rows use the probe verbs `spawn` and `spawnwrite` (start the
trusted copy, P13), `vmwrite` (P1, P8, P9), `dup` (P3 for `PROCESS_DUP_HANDLE`) and `suspend` (P5).
The other rows are still proposals. They need one more verb:

- `access <pid|tid> <p|t> <hex mask> [maximum]`: `NtOpenProcess` or `OpenThread` with the mask (or
  `MAXIMUM_ALLOWED`), then `NtQueryObject(ObjectBasicInformation).GrantedAccess`; the exit code is
  0 when every requested right was granted and `ERROR_ACCESS_DENIED` when any was missing, and it
  prints the granted mask.

The lab policy trusts the trusted copy for the lab store.

| # | From | Does | Expected |
|---|------|------|----------|
| P1 | untrusted copy | open the held trusted process with `PROCESS_VM_WRITE \| PROCESS_VM_OPERATION` | granted mask lacks both (exit `ERROR_ACCESS_DENIED`); one report, operation 5, the requester's pid, `Path` = the trusted copy's image |
| P2 | untrusted copy | open it with `PROCESS_QUERY_LIMITED_INFORMATION \| PROCESS_VM_READ \| PROCESS_TERMINATE` | all granted; no report |
| P3 | each of the other stripped process rights alone | `CREATE_THREAD`, `DUP_HANDLE`, `CREATE_PROCESS`, `SET_INFORMATION`, `SUSPEND_RESUME` | each refused as in P1 |
| P4 | untrusted copy | `DuplicateHandle` out of the trusted process with the pseudo handle after a `DUP_HANDLE` open | the open already lacks it; the duplicate is not made |
| P5 | untrusted copy | open a thread of the trusted process with `SET_CONTEXT`, `SUSPEND_RESUME`, then `GET_CONTEXT`, `QUERY_LIMITED_INFORMATION` | the first two lack, the rest granted; reports are operation 6 |
| P6 | untrusted copy | with blocking off, open the trusted process fully and keep the handle; blocking on; `DuplicateHandle` it (same access) into itself | the duplicate lacks the stripped rights (the duplicate path) |
| P7 | untrusted copy | open with `MAXIMUM_ALLOWED` | granted mask is all access minus the strip mask, whatever the system resolved first |
| P8 | blocking off | P1 | full access granted, no report |
| P9 | the trusted copy | open another trusted-copy process fully | granted (same image) |
| P10 | a copy trusted for another store only | P1 | stripped (its mask does not contain the target's) |
| P11 | the harness (the port client) from a copy that is trusted for nothing | open the held trusted process fully | granted: the agent exemption |
| P12 | the harness | start with an empty policy: full access to the held process; commit a policy trusting its image; open again; commit an empty one; open again | full, stripped, full: the re-evaluation, including for a process started before the commit |
| P13 | untrusted copy | `CreateProcess` of the trusted image, plainly and `CREATE_SUSPENDED`; with the returned handles `WriteProcessMemory` and `ResumeThread` | both succeed: the creator is exempt (residual 1) |
| P14 | untrusted copy | `NtCreateProcessEx` from the trusted image's section | records the residual: expected full access |
| P15 | load the driver while a trusted copy is already running | `lab.ps1 install` with a `hold` process alive first; then P1 against it | stripped, and status shows `process guard on` without the "not covered" note |
| P16 | untrusted copy | 5,000 opens of the trusted process with `PROCESS_VM_WRITE` in a loop | no stall; reports capped at 64 queued, the rest counted in `Denied`/dropped; machine responsive |
| P17 | whole machine | start Chrome or Edge with blocking on; browse, open a second tab and a download, End task in Task Manager, `fltmc unload BruceFilter` under Verifier | no hang, no refused start, unload clean |

## 11. Files

| File | Change |
|------|--------|
| `BruceProcessGuard.c`, `.h` | new: the table, the notify routine, the handle callback, the report worker, start and stop |
| `BruceFilterPolicy.c`, `.h` | `BrucePolicyTrustMask`, `BruceGuardCares`, `BruceGuardAccess`, the strip masks |
| `BruceFilter.c` | starts and stops the guard, `BruceSendNotification`, calls the policy hook after a commit, records the agent, reports `ProcessGuard` in the status |
| `BruceFilter.h` | `ProcessGuard` status field, flags, operations 5 and 6 |
| `build.ps1`, `BruceFilter.vcxproj` | the new source, `/INTEGRITYCHECK`; `build.ps1` also fails a build with a Filter Manager release compiled as a tail call |
| `test\PolicyTests.c` | 145 more checks (masks against the SDK, trust masks, every branch of the access decision) |
| `lab\BruceLab.c` | `status` prints the process guard state; rows 43 to 49 and their probe verbs |
| `Driver/MinifilterClient.cs`, `Hosting/Hosting.cs`, `tests/BruceEDR.Tests/MinifilterClientTests.cs` | the two operations, the status field, the event text |

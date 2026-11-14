//
// BruceFilter's process guard. A trusted image is only as trustworthy as the process running
// it: code running as the same user can duplicate the browser's own handle to its cookie
// store, or inject into the browser, and neither makes a file open for the minifilter to see.
// This closes both while blocking is on: a handle to a process whose image is trusted for a
// store, or to one of its threads, loses the rights in BRUCE_PROCESS_STRIP and
// BRUCE_THREAD_STRIP unless the process receiving it is trusted for the same stores, or is
// the process that created it.
//
// The creator is exempt because the thread handle CreateProcess gets back is made after the
// notify routine has run: stripped, the creator cannot resume the new process's first thread,
// and Explorer or Task Scheduler cannot start a trusted program at all (the lab saw Task
// Scheduler fail with access denied). The cost is docs\process-guard.md, residual 1: a
// program that starts a trusted image itself can write into it.
//
// Every process is tracked, with its image path, from PsSetCreateProcessNotifyRoutineEx (new
// processes) and one enumeration at load (running ones). The handle callback runs at
// PASSIVE_LEVEL in the requesting thread with normal APCs disabled, and Microsoft asks that it
// stay short, take no registry or IPC calls and not wait on other threads. So it never asks
// for an image name: it looks up two table entries under a shared push lock, and hands a
// refusal report to a work item. The decisions are BruceGuardAccess and
// BrucePolicyTrustMask in BruceFilterPolicy.c.
//
// Lock order: policy lock, then gLock. The handle callback takes only gLock, shared.
//
// SIGNING: ObRegisterCallbacks and PsSetCreateProcessNotifyRoutineEx need the image linked
// with /INTEGRITYCHECK (build.ps1, BruceFilter.vcxproj).
//

#include <fltKernel.h>
#include "BruceFilter.h"
#include "BruceFilterPolicy.h"
#include "BruceProcessGuard.h"

#define GUARD_TAG         'pgrB'
#define GUARD_BUCKETS     128
#define GUARD_MAX_REPORTS 64
// PLACEHOLDER, like the file filter's altitude: a production driver needs its own from Microsoft.
#define GUARD_ALTITUDE    L"385201"

#define GUARD_STOPPED  0
#define GUARD_RUNNING  1
#define GUARD_STOPPING 2

typedef struct _GUARD_PROCESS {
    LIST_ENTRY Link;
    PEPROCESS  Process;     // referenced while tracked, so the pointer cannot be reused
    PEPROCESS  Creator;     // referenced too; NULL for a process running before the driver loaded
    ULONGLONG  Trust;       // BrucePolicyTrustMask of the image; 0: not protected
    USHORT     NameBytes;   // image NT path as SeLocateProcessImageName gave it
    WCHAR      Name[1];
} GUARD_PROCESS;

typedef struct _GUARD_REPORT {
    LIST_ENTRY         Link;
    BRUCE_NOTIFICATION Note;
} GUARD_REPORT;

// The documented layout of SYSTEM_PROCESS_INFORMATION (winternl.h), as far as the process id.
typedef struct _GUARD_SYSTEM_PROCESS {
    ULONG  NextEntryOffset;
    UCHAR  Reserved1[52];
    PVOID  Reserved2[3];
    HANDLE UniqueProcessId;
} GUARD_SYSTEM_PROCESS;
C_ASSERT(FIELD_OFFSET(GUARD_SYSTEM_PROCESS, UniqueProcessId) == 80);

typedef NTSTATUS (NTAPI *PGUARD_QUERY_SYSTEM_INFORMATION)(ULONG Class, PVOID Buffer, ULONG Length, PULONG Needed);
typedef BOOLEAN (NTAPI *PGUARD_IS_PROTECTED)(PEPROCESS Process);

#define GUARD_SYSTEM_PROCESS_INFORMATION 5   // SystemProcessInformation

static PFLT_FILTER          gFilter;
static PEX_PUSH_LOCK        gPolicyLock;
static const BRUCE_POLICY*  gLive;
static EX_PUSH_LOCK         gLock;
static LIST_ENTRY           gBuckets[GUARD_BUCKETS];
static volatile LONG        gProtected;      // tracked processes with a nonzero Trust
static volatile LONG        gState;
static volatile LONG        gInFlight;       // handle callbacks inside their body
static volatile LONG        gWorkPending;
static volatile LONG        gWorkItems;      // report work items allocated and not yet freed
static volatile LONG        gQueued;
static volatile LONG        gDropped;        // reports not queued
static volatile LONG        gTrackFailed;    // processes whose name or entry could not be had
static LIST_ENTRY           gReports;
static KSPIN_LOCK           gReportLock;
static PVOID                gObHandle;
static PEPROCESS volatile   gAgent;          // written under gAgentLock, compared without it
static KSPIN_LOCK           gAgentLock;
static ULONG                gFlags;
static PGUARD_IS_PROTECTED  gIsProtected;
static PGUARD_IS_PROTECTED  gIsProtectedLight;

static VOID BruceProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
static OB_PREOP_CALLBACK_STATUS BruceHandlePreOperation(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION Info);
static VOID BruceGuardWorker(_In_ PFLT_GENERIC_WORKITEM Item, _In_ PVOID FltObject, _In_opt_ PVOID Context);
static NTSTATUS BruceGuardEnumerate(VOID);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, BruceProcessGuardStart)
#pragma alloc_text(INIT, BruceGuardEnumerate)
#pragma alloc_text(PAGE, BruceProcessGuardStop)
#pragma alloc_text(PAGE, BruceProcessGuardPolicyChanged)
#endif

static PEPROCESS BruceSwapAgent(_In_opt_ PEPROCESS Agent)
{
    PEPROCESS previous;
    KIRQL irql;
    KeAcquireSpinLock(&gAgentLock, &irql);
    previous = gAgent;
    gAgent = Agent;
    KeReleaseSpinLock(&gAgentLock, irql);
    return previous;
}

// ------------------------------------------------------------------ table

static ULONG BruceBucket(_In_ PEPROCESS Process)
{
    return (ULONG)(((ULONG_PTR)Process >> 4) % GUARD_BUCKETS);
}

static GUARD_PROCESS* BruceFindLocked(_In_opt_ PEPROCESS Process)
{
    PLIST_ENTRY head;
    PLIST_ENTRY link;
    if (Process == NULL) return NULL;
    head = &gBuckets[BruceBucket(Process)];
    for (link = head->Flink; link != head; link = link->Flink)
    {
        GUARD_PROCESS* entry = CONTAINING_RECORD(link, GUARD_PROCESS, Link);
        if (entry->Process == Process) return entry;
    }
    return NULL;
}

static VOID BruceGuardRelease(_In_ GUARD_PROCESS* Entry)
{
    if (Entry->Creator != NULL) ObDereferenceObject(Entry->Creator);
    ObDereferenceObject(Entry->Process);
    ExFreePoolWithTag(Entry, GUARD_TAG);
}

// Tracks one process. With AlreadyReferenced the caller's reference becomes the table's.
static VOID BruceGuardTrack(_In_ PEPROCESS Process, _In_ BOOLEAN AlreadyReferenced, _In_opt_ PEPROCESS Creator)
{
    PUNICODE_STRING image = NULL;
    GUARD_PROCESS* entry;
    GUARD_PROCESS* existing;
    USHORT bytes = 0;

    if (NT_SUCCESS(SeLocateProcessImageName(Process, &image)) && image != NULL && image->Buffer != NULL)
        bytes = image->Length;
    entry = (GUARD_PROCESS*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*entry) + bytes, GUARD_TAG);
    if (entry == NULL)
    {
        InterlockedIncrement(&gTrackFailed);
        if (image != NULL) ExFreePool(image);
        if (AlreadyReferenced) ObDereferenceObject(Process);
        return;
    }
    entry->Process = Process;
    entry->Creator = Creator;
    entry->NameBytes = bytes;
    if (bytes != 0) RtlCopyMemory(entry->Name, image->Buffer, bytes);
    if (image != NULL) ExFreePool(image);
    else InterlockedIncrement(&gTrackFailed);   // tracked without a name: never trusted
    if (!AlreadyReferenced) ObReferenceObject(Process);
    if (Creator != NULL) ObReferenceObject(Creator);

    FltAcquirePushLockShared(gPolicyLock);
    entry->Trust = BrucePolicyTrustMask(gLive, entry->Name, entry->NameBytes / sizeof(WCHAR));
    FltAcquirePushLockExclusive(&gLock);
    existing = BruceFindLocked(Process);
    if (existing == NULL)
    {
        InsertTailList(&gBuckets[BruceBucket(Process)], &entry->Link);
        if (entry->Trust != 0) InterlockedIncrement(&gProtected);
    }
    FltReleasePushLock(&gLock);
    FltReleasePushLock(gPolicyLock);

    if (existing != NULL) BruceGuardRelease(entry);
}

static VOID BruceGuardUntrack(_In_ PEPROCESS Process)
{
    GUARD_PROCESS* entry;
    FltAcquirePushLockExclusive(&gLock);
    entry = BruceFindLocked(Process);
    if (entry != NULL)
    {
        RemoveEntryList(&entry->Link);
        if (entry->Trust != 0) InterlockedDecrement(&gProtected);
    }
    FltReleasePushLock(&gLock);
    if (entry != NULL) BruceGuardRelease(entry);
}

// A creation runs in the creating thread's context, so the current process is the creator
// (not CreateInfo->ParentProcessId, which a caller can name with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS).
_Use_decl_annotations_
static VOID BruceProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(ProcessId);
    if (CreateInfo != NULL) BruceGuardTrack(Process, FALSE, PsGetCurrentProcess());
    else BruceGuardUntrack(Process);
}

// Processes already running when the driver loads. The notify routine is registered first,
// so a process created meanwhile is tracked either way and the second sighting is dropped.
// A running process missing from the table is unprotected, never wrongly protected, so a
// failure here costs coverage of those processes and nothing else.
static NTSTATUS BruceGuardEnumerate(VOID)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
    PGUARD_QUERY_SYSTEM_INFORMATION query = (PGUARD_QUERY_SYSTEM_INFORMATION)MmGetSystemRoutineAddress(&name);
    ULONG size = 512 * 1024;
    PUCHAR buffer = NULL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (query == NULL) return STATUS_NOT_SUPPORTED;
    for (ULONG attempt = 0; attempt < 6; attempt++)
    {
        ULONG needed = 0;
        buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, size, GUARD_TAG);
        if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        status = query(GUARD_SYSTEM_PROCESS_INFORMATION, buffer, size, &needed);
        if (status != STATUS_INFO_LENGTH_MISMATCH) break;
        ExFreePoolWithTag(buffer, GUARD_TAG);
        buffer = NULL;
        size = (needed > size ? needed : size) + 128 * 1024;
    }
    if (buffer == NULL) return STATUS_BUFFER_TOO_SMALL;
    if (NT_SUCCESS(status))
    {
        ULONG offset = 0;
        while (offset + sizeof(GUARD_SYSTEM_PROCESS) <= size)
        {
            const GUARD_SYSTEM_PROCESS* info = (const GUARD_SYSTEM_PROCESS*)(buffer + offset);
            PEPROCESS process = NULL;
            if (info->UniqueProcessId != NULL && NT_SUCCESS(PsLookupProcessByProcessId(info->UniqueProcessId, &process)))
            {
                if (PsGetProcessExitStatus(process) == STATUS_PENDING) BruceGuardTrack(process, TRUE, NULL);
                else ObDereferenceObject(process);
            }
            if (info->NextEntryOffset == 0) break;
            offset += info->NextEntryOffset;
        }
    }
    ExFreePoolWithTag(buffer, GUARD_TAG);
    return status;
}

// ------------------------------------------------------------------ reports

static BOOLEAN BruceGuardHasReports(VOID)
{
    KIRQL irql;
    BOOLEAN has;
    KeAcquireSpinLock(&gReportLock, &irql);
    has = !IsListEmpty(&gReports);
    KeReleaseSpinLock(&gReportLock, irql);
    return has;
}

// At most one work item is in flight: the pending flag is the baton. Once Stop has begun
// nothing new is queued; what is left on the list, Stop frees.
static VOID BruceGuardKick(VOID)
{
    PFLT_GENERIC_WORKITEM item;
    if (gState != GUARD_RUNNING || InterlockedCompareExchange(&gWorkPending, 1, 0) != 0) return;
    InterlockedIncrement(&gWorkItems);
    item = FltAllocateGenericWorkItem();
    if (item == NULL || !NT_SUCCESS(FltQueueGenericWorkItem(item, gFilter, BruceGuardWorker, DelayedWorkQueue, NULL)))
    {
        if (item != NULL) FltFreeGenericWorkItem(item);
        InterlockedDecrement(&gWorkItems);
        InterlockedExchange(&gWorkPending, 0);
    }
}

_Use_decl_annotations_
static VOID BruceGuardWorker(PFLT_GENERIC_WORKITEM Item, PVOID FltObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(FltObject);
    UNREFERENCED_PARAMETER(Context);
    for (;;)
    {
        GUARD_REPORT* report = NULL;
        KIRQL irql;
        KeAcquireSpinLock(&gReportLock, &irql);
        if (!IsListEmpty(&gReports))
        {
            report = CONTAINING_RECORD(RemoveHeadList(&gReports), GUARD_REPORT, Link);
            InterlockedDecrement(&gQueued);
        }
        KeReleaseSpinLock(&gReportLock, irql);
        if (report == NULL)
        {
            InterlockedExchange(&gWorkPending, 0);
            // A report queued after the last look found the baton taken: take it back.
            if (!BruceGuardHasReports() || InterlockedCompareExchange(&gWorkPending, 1, 0) != 0) break;
            continue;
        }
        BruceSendNotification(&report->Note);
        ExFreePoolWithTag(report, GUARD_TAG);
    }
    // Never the routine's last call. Filter Verifier finds the driver behind a Filter Manager
    // call by its return address; compiled as a tail call, this free is charged to no one and
    // reads as a leaked work item at unload, which stops the machine without a debugger.
    FltFreeGenericWorkItem(Item);
    InterlockedDecrement(&gWorkItems);
}

static VOID BruceGuardCopyName(_Out_writes_(BRUCE_MAX_PATH) WCHAR* Dest, _In_opt_ const GUARD_PROCESS* Entry)
{
    SIZE_T chars = 0;
    if (Entry != NULL) chars = Entry->NameBytes / sizeof(WCHAR);
    if (chars > BRUCE_MAX_PATH - 1) chars = BRUCE_MAX_PATH - 1;
    if (chars != 0) RtlCopyMemory(Dest, Entry->Name, chars * sizeof(WCHAR));
    Dest[chars] = L'\0';
}

// Called with gLock held shared, at PASSIVE_LEVEL.
static VOID BruceGuardReport(_In_ BOOLEAN IsThread, _In_ PEPROCESS Receiver, _In_ const GUARD_PROCESS* Target,
    _In_opt_ const GUARD_PROCESS* Requester)
{
    GUARD_REPORT* report;
    KIRQL irql;
    ULONG first = 0;

    if (InterlockedCompareExchange(&gQueued, 0, 0) >= GUARD_MAX_REPORTS ||
        (report = (GUARD_REPORT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*report), GUARD_TAG)) == NULL)
    {
        InterlockedIncrement(&gDropped);
        return;
    }
    (VOID)_BitScanForward64(&first, Target->Trust);
    report->Note.Version = BRUCE_PROTOCOL_VERSION;
    report->Note.Operation = IsThread ? (UINT32)BruceOpThreadHandle : (UINT32)BruceOpProcessHandle;
    report->Note.ProcessId = (UINT32)(ULONG_PTR)PsGetProcessId(Receiver);
    report->Note.PrefixIndex = first;
    BruceGuardCopyName(report->Note.Path, Target);
    BruceGuardCopyName(report->Note.Image, Requester);

    KeAcquireSpinLock(&gReportLock, &irql);
    InsertTailList(&gReports, &report->Link);
    InterlockedIncrement(&gQueued);
    KeReleaseSpinLock(&gReportLock, irql);
    BruceGuardKick();
}

// ------------------------------------------------------------------ handle callback

static BOOLEAN BruceGuardExempt(_In_ PEPROCESS Process)
{
    // System and every protected process (csrss, services, the antimalware engine) cannot be
    // started or injected by a user-mode program, and Windows needs their handles whole.
    return Process == PsInitialSystemProcess || Process == gAgent ||
           gIsProtected(Process) || (gIsProtectedLight != NULL && gIsProtectedLight(Process));
}

static VOID BruceHandleDecide(_Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    BRUCE_HANDLE_REQUEST request;
    PACCESS_MASK desired;
    PEPROCESS receiver;
    PEPROCESS target;
    GUARD_PROCESS* targetEntry;
    GUARD_PROCESS* receiverEntry;
    ACCESS_MASK granted;
    BOOLEAN isThread;

    // Almost every request leaves here, without a lock or a lookup.
    if (gState != GUARD_RUNNING || !gLive->Blocking || Info->KernelHandle || gProtected == 0) return;

    isThread = (Info->ObjectType == *PsThreadType);
    if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        // The process that ends up holding the handle is the one to judge, not the caller.
        desired = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
        receiver = (PEPROCESS)Info->Parameters->DuplicateHandleInformation.TargetProcess;
    }
    else
    {
        desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
        receiver = PsGetCurrentProcess();
    }
    if (receiver == NULL || !BruceGuardCares(isThread, *desired)) return;

    target = isThread ? IoThreadToProcess((PETHREAD)Info->Object) : (PEPROCESS)Info->Object;
    if (target == receiver || BruceGuardExempt(receiver)) return;

    FltAcquirePushLockShared(&gLock);
    targetEntry = BruceFindLocked(target);
    receiverEntry = BruceFindLocked(receiver);
    request.IsThread = isThread;
    request.KernelHandle = FALSE;
    request.SameProcess = FALSE;
    request.ReceiverExempt = targetEntry != NULL && targetEntry->Creator == receiver;
    request.TargetTrust = targetEntry != NULL ? targetEntry->Trust : 0;
    request.ReceiverTrust = receiverEntry != NULL ? receiverEntry->Trust : 0;
    request.Desired = *desired;
    granted = BruceGuardAccess(&request);
    if (granted != *desired)
    {
        *desired = granted;
        if (targetEntry != NULL) BruceGuardReport(isThread, receiver, targetEntry, receiverEntry);
    }
    FltReleasePushLock(&gLock);
}

// The in-flight count comes first: Stop waits on it before the table and the code go away.
_Use_decl_annotations_
static OB_PREOP_CALLBACK_STATUS BruceHandlePreOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    InterlockedIncrement(&gInFlight);
    BruceHandleDecide(Info);
    InterlockedDecrement(&gInFlight);
    return OB_PREOP_SUCCESS;
}

// ------------------------------------------------------------------ lifetime

_Use_decl_annotations_
NTSTATUS BruceProcessGuardStart(PFLT_FILTER Filter, PEX_PUSH_LOCK PolicyLock, const BRUCE_POLICY* Live)
{
    UNICODE_STRING protectedName = RTL_CONSTANT_STRING(L"PsIsProtectedProcess");
    UNICODE_STRING lightName = RTL_CONSTANT_STRING(L"PsIsProtectedProcessLight");
    OB_OPERATION_REGISTRATION operations[2];
    OB_CALLBACK_REGISTRATION registration;
    NTSTATUS status;
    PAGED_CODE();

    // Without the protected-process test the guard cannot tell Windows' own processes from
    // anyone else's, and stripping csrss's handles would break the system: do not start.
    gIsProtected = (PGUARD_IS_PROTECTED)MmGetSystemRoutineAddress(&protectedName);
    gIsProtectedLight = (PGUARD_IS_PROTECTED)MmGetSystemRoutineAddress(&lightName);
    if (gIsProtected == NULL) return STATUS_NOT_SUPPORTED;

    gFilter = Filter;
    gPolicyLock = PolicyLock;
    gLive = Live;
    FltInitializePushLock(&gLock);
    KeInitializeSpinLock(&gReportLock);
    KeInitializeSpinLock(&gAgentLock);
    InitializeListHead(&gReports);
    for (ULONG i = 0; i < GUARD_BUCKETS; i++) InitializeListHead(&gBuckets[i]);

    status = PsSetCreateProcessNotifyRoutineEx(BruceProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        FltDeletePushLock(&gLock);
        return status;
    }
    if (NT_SUCCESS(BruceGuardEnumerate())) gFlags |= BRUCE_GUARD_ENUMERATED;

    RtlZeroMemory(operations, sizeof(operations));
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = BruceHandlePreOperation;
    operations[1] = operations[0];
    operations[1].ObjectType = PsThreadType;
    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 2;
    RtlInitUnicodeString(&registration.Altitude, GUARD_ALTITUDE);
    registration.OperationRegistration = operations;

    gState = GUARD_RUNNING;
    status = ObRegisterCallbacks(&registration, &gObHandle);
    if (!NT_SUCCESS(status))
    {
        gState = GUARD_STOPPING;
        gObHandle = NULL;
        BruceProcessGuardStop();
        return status;
    }
    gFlags |= BRUCE_GUARD_ACTIVE;
    return STATUS_SUCCESS;
}

VOID BruceProcessGuardStop(VOID)
{
    LARGE_INTEGER pause;
    PEPROCESS agent;
    PAGED_CODE();

    agent = BruceSwapAgent(NULL);
    if (agent != NULL) ObDereferenceObject(agent);
    if (gState == GUARD_STOPPED) return;
    gState = GUARD_STOPPING;
    gFlags = 0;
    // Both unregistrations first, so nothing new starts; then the stragglers are waited out.
    if (gObHandle != NULL)
    {
        ObUnRegisterCallbacks(gObHandle);
        gObHandle = NULL;
    }
    (VOID)PsSetCreateProcessNotifyRoutineEx(BruceProcessNotify, TRUE);
    pause.QuadPart = -100000;   // 10 ms
    // gWorkItems, not gWorkPending: the worker drops the baton before it frees its work item.
    while (gInFlight != 0 || gWorkPending != 0 || gWorkItems != 0) KeDelayExecutionThread(KernelMode, FALSE, &pause);
    KeDelayExecutionThread(KernelMode, FALSE, &pause);   // a callback between its entry and the count

    for (ULONG i = 0; i < GUARD_BUCKETS; i++)
    {
        while (!IsListEmpty(&gBuckets[i]))
            BruceGuardRelease(CONTAINING_RECORD(RemoveHeadList(&gBuckets[i]), GUARD_PROCESS, Link));
    }
    while (!IsListEmpty(&gReports))
        ExFreePoolWithTag(CONTAINING_RECORD(RemoveHeadList(&gReports), GUARD_REPORT, Link), GUARD_TAG);
    InterlockedExchange(&gProtected, 0);
    InterlockedExchange(&gQueued, 0);
    FltDeletePushLock(&gLock);
    gState = GUARD_STOPPED;
}

VOID BruceProcessGuardPolicyChanged(VOID)
{
    LONG protectedCount = 0;
    PAGED_CODE();

    if (gState != GUARD_RUNNING) return;
    FltAcquirePushLockShared(gPolicyLock);
    FltAcquirePushLockExclusive(&gLock);
    for (ULONG i = 0; i < GUARD_BUCKETS; i++)
    {
        PLIST_ENTRY link;
        for (link = gBuckets[i].Flink; link != &gBuckets[i]; link = link->Flink)
        {
            GUARD_PROCESS* entry = CONTAINING_RECORD(link, GUARD_PROCESS, Link);
            entry->Trust = BrucePolicyTrustMask(gLive, entry->Name, entry->NameBytes / sizeof(WCHAR));
            if (entry->Trust != 0) protectedCount++;
        }
    }
    InterlockedExchange(&gProtected, protectedCount);
    FltReleasePushLock(&gLock);
    FltReleasePushLock(gPolicyLock);
}

_Use_decl_annotations_
VOID BruceProcessGuardSetAgent(PEPROCESS Agent)
{
    PEPROCESS previous;
    if (Agent == gAgent || (Agent != NULL && gState != GUARD_RUNNING)) return;
    if (Agent != NULL) ObReferenceObject(Agent);
    previous = BruceSwapAgent(Agent);
    if (previous != NULL) ObDereferenceObject(previous);
}

ULONG BruceProcessGuardFlags(VOID)
{
    return gFlags;
}

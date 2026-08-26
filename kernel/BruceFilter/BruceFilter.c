//
// BruceFilter - a minimal but real file-system minifilter for BruceEDR.
//
// It registers a pre-operation callback on IRP_MJ_CREATE and, when blocking is
// enabled (pushed from user mode over the filter communication port), denies
// opens of paths that match any configured sensitive fragment. This is the
// "true inline prevention" layer that user-mode detection cannot provide.
//
// BUILD: requires the Windows Driver Kit (WDK) + Visual Studio. See README.md.
// SIGNING: to load on a normal (non-test) machine the .sys must be signed via
// attestation/EV through the Partner Center. In a lab, enable test signing.
//
// This is a documented skeleton: it enforces a global block policy. Extending it
// with a trusted-PID allowlist (also pushed from user mode) and/or send-event-and-
// wait semantics is the obvious next step and is flagged inline.
//

#include <fltKernel.h>
#include <ntstrsafe.h>
#include "BruceFilter.h"

#define BRUCE_TAG 'ecrB'

PFLT_FILTER  gFilter      = NULL;
PFLT_PORT    gServerPort  = NULL;
PFLT_PORT    gClientPort  = NULL;

FAST_MUTEX   gPolicyLock;
volatile BOOLEAN gBlocking = FALSE;
WCHAR        gSensitive[BRUCE_MAX_ENTRIES][BRUCE_MAX_PATH];
ULONG        gSensitiveCount = 0;

DRIVER_INITIALIZE DriverEntry;

static FLT_PREOP_CALLBACK_STATUS BrucePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

static NTSTATUS BruceUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

static NTSTATUS BruceInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

static NTSTATUS BruceInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

static NTSTATUS BrucePortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie);

static VOID BrucePortDisconnect(_In_opt_ PVOID ConnectionCookie);

static NTSTATUS BrucePortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, BrucePreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                              // Flags
    NULL,                           // ContextRegistration
    Callbacks,                      // OperationRegistration
    BruceUnload,                   // FilterUnload
    BruceInstanceSetup,            // InstanceSetup
    BruceInstanceQueryTeardown,    // InstanceQueryTeardown
    NULL,                           // InstanceTeardownStart
    NULL,                           // InstanceTeardownComplete
    NULL,                           // GenerateFileName
    NULL,                           // NormalizeNameComponent
    NULL,                           // NormalizeContextCleanup
    NULL,                           // TransactionNotification
    NULL,                           // NormalizeNameComponentEx
    NULL                            // SectionNotification
};

static SIZE_T BruceWcsLen(_In_reads_(BRUCE_MAX_PATH) PCWSTR s)
{
    SIZE_T n = 0;
    while (n < BRUCE_MAX_PATH && s[n] != L'\0') n++;
    return n;
}

// Case-insensitive substring search of a (non null-terminated) UNICODE_STRING.
static BOOLEAN BruceContainsCI(_In_ PUNICODE_STRING str, _In_ PCWSTR needle)
{
    SIZE_T nlen = BruceWcsLen(needle);
    if (nlen == 0) return FALSE;

    USHORT slen = (USHORT)(str->Length / sizeof(WCHAR));
    if ((SIZE_T)slen < nlen) return FALSE;

    for (USHORT i = 0; (SIZE_T)i + nlen <= (SIZE_T)slen; i++)
    {
        SIZE_T j = 0;
        for (; j < nlen; j++)
        {
            WCHAR a = RtlUpcaseUnicodeChar(str->Buffer[i + j]);
            WCHAR b = RtlUpcaseUnicodeChar(needle[j]);
            if (a != b) break;
        }
        if (j == nlen) return TRUE;
    }
    return FALSE;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    ExInitializeFastMutex(&gPolicyLock);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilter);
    if (!NT_SUCCESS(status)) return status;

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status))
    {
        RtlInitUnicodeString(&portName, BRUCE_PORT_NAME);
        InitializeObjectAttributes(&oa, &portName,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

        status = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL,
            BrucePortConnect, BrucePortDisconnect, BrucePortMessage, 1);

        FltFreeSecurityDescriptor(sd);
    }

    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }

    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status))
    {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return status;
}

static FLT_PREOP_CALLBACK_STATUS BrucePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    FLT_PREOP_CALLBACK_STATUS ret = FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!gBlocking) return ret;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) return ret;

    FltParseFileNameInformation(nameInfo);

    BOOLEAN sensitive = FALSE;
    ExAcquireFastMutex(&gPolicyLock);
    for (ULONG i = 0; i < gSensitiveCount; i++)
    {
        if (BruceContainsCI(&nameInfo->Name, gSensitive[i])) { sensitive = TRUE; break; }
    }
    ExReleaseFastMutex(&gPolicyLock);

    if (sensitive)
    {
        //
        // Skeleton policy: deny outright while blocking is enabled. Production:
        // allowlist trusted requestor PIDs (FltGetRequestorProcessId(Data)) pushed
        // from user mode, and/or FltSendMessage an event to the agent and act on
        // the reply before completing.
        //
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        ret = FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return ret;
}

static NTSTATUS BruceUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gServerPort) { FltCloseCommunicationPort(gServerPort); gServerPort = NULL; }
    if (gFilter) { FltUnregisterFilter(gFilter); gFilter = NULL; }
    return STATUS_SUCCESS;
}

static NTSTATUS BruceInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;   // attach to all volumes
}

static NTSTATUS BruceInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static NTSTATUS BrucePortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    gClientPort = ClientPort;
    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

static VOID BrucePortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    if (gClientPort) { FltCloseClientPort(gFilter, &gClientPort); gClientPort = NULL; }
}

static NTSTATUS BrucePortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(BRUCE_MESSAGE))
        return STATUS_INVALID_PARAMETER;

    BRUCE_MESSAGE msg;
    __try
    {
        ProbeForRead(InputBuffer, sizeof(BRUCE_MESSAGE), sizeof(UCHAR));
        RtlCopyMemory(&msg, InputBuffer, sizeof(BRUCE_MESSAGE));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_INVALID_USER_BUFFER;
    }

    ExAcquireFastMutex(&gPolicyLock);
    switch (msg.Command)
    {
    case BruceSetBlocking:
        gBlocking = (msg.Flag != 0);
        break;

    case BruceAddSensitivePath:
        if (gSensitiveCount < BRUCE_MAX_ENTRIES)
        {
            msg.Path[BRUCE_MAX_PATH - 1] = L'\0';
            RtlStringCchCopyW(gSensitive[gSensitiveCount], BRUCE_MAX_PATH, msg.Path);
            gSensitiveCount++;
        }
        break;

    case BruceClearPolicy:
        gSensitiveCount = 0;
        break;

    default:
        break;
    }
    ExReleaseFastMutex(&gPolicyLock);

    return STATUS_SUCCESS;
}

//
// BruceFilter: the inline-prevention layer for BruceEDR.
//
// While blocking is on, the filter refuses opens of guarded paths (browser credential stores
// and wallets, pushed from user mode as directory fragments), and renames or hard links onto
// them, unless the requesting process image is trusted for that path. Every refusal is
// reported to the connected agent without waiting. The decisions themselves are pure
// functions in BruceFilterPolicy.c, tested in user mode under test\.
//
// Names never fail open. Before an open the filter checks the opened name, and expands an
// 8.3 alias through the normalized name. An open whose name cannot be resolved beforehand
// (an open by file id, a failed query) is decided after the file system opens it, and
// cancelled if it is guarded; a name that cannot be resolved even then is refused.
//
// BUILD: build.ps1 (WDK NuGet packages, no WDK install needed). See README.md.
// SIGNING: a normal machine loads it only once attestation- or WHQL-signed.
//
// While blocking is on, a non-mandatory unload and a manual instance detach are refused with
// STATUS_FLT_DO_NOT_DETACH, so `fltmc unload` and `fltmc detach` cannot end protection. A
// mandatory unload (a service stop) cannot be refused.
//

#include <fltKernel.h>
#include "BruceFilter.h"
#include "BruceFilterPolicy.h"

#define BRUCE_TAG     'ecrB'
#define BRUCE_RECHECK ((PVOID)(ULONG_PTR)1)

C_ASSERT(FIELD_OFFSET(FILE_RENAME_INFORMATION, RootDirectory) == FIELD_OFFSET(BRUCE_LINK_INFO, RootDirectory));
C_ASSERT(FIELD_OFFSET(FILE_RENAME_INFORMATION, FileNameLength) == FIELD_OFFSET(BRUCE_LINK_INFO, FileNameLength));
C_ASSERT(FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) == FIELD_OFFSET(BRUCE_LINK_INFO, FileName));
C_ASSERT(FIELD_OFFSET(FILE_LINK_INFORMATION, RootDirectory) == FIELD_OFFSET(BRUCE_LINK_INFO, RootDirectory));
C_ASSERT(FIELD_OFFSET(FILE_LINK_INFORMATION, FileNameLength) == FIELD_OFFSET(BRUCE_LINK_INFO, FileNameLength));
C_ASSERT(FIELD_OFFSET(FILE_LINK_INFORMATION, FileName) == FIELD_OFFSET(BRUCE_LINK_INFO, FileName));

static PFLT_FILTER  gFilter;
static PFLT_PORT    gServerPort;
static PFLT_PORT    gClientPort;
static EX_PUSH_LOCK gPolicyLock;
static BRUCE_POLICY gLive;     // read under the shared lock; Blocking is also read without it
static BRUCE_POLICY gStaged;   // built by the agent, swapped in by BruceCommitPolicy
static volatile LONG gDenied;
static volatile LONG gRechecked;
static volatile LONG gNotifyDropped;

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS FLTAPI BruceUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

static NTSTATUS FLTAPI BruceInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

static NTSTATUS FLTAPI BruceInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

static FLT_PREOP_CALLBACK_STATUS FLTAPI BrucePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS FLTAPI BrucePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static FLT_PREOP_CALLBACK_STATUS FLTAPI BrucePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

static NTSTATUS FLTAPI BrucePortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie);

static VOID FLTAPI BrucePortDisconnect(_In_opt_ PVOID ConnectionCookie);

static NTSTATUS FLTAPI BrucePortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

static NTSTATUS BruceCreatePort(VOID);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, BruceCreatePort)
#pragma alloc_text(PAGE, BruceUnload)
#pragma alloc_text(PAGE, BruceInstanceSetup)
#pragma alloc_text(PAGE, BruceInstanceQueryTeardown)
#pragma alloc_text(PAGE, BrucePortConnect)
#pragma alloc_text(PAGE, BrucePortDisconnect)
#pragma alloc_text(PAGE, BrucePortMessage)
#endif

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, BrucePreCreate, BrucePostCreate },
    { IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, BrucePreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                              // Flags
    NULL,                           // ContextRegistration
    Callbacks,                      // OperationRegistration
    BruceUnload,                    // FilterUnload
    BruceInstanceSetup,             // InstanceSetup
    BruceInstanceQueryTeardown,     // InstanceQueryTeardown
    NULL,                           // InstanceTeardownStart
    NULL,                           // InstanceTeardownComplete
    NULL,                           // GenerateFileName
    NULL,                           // NormalizeNameComponent
    NULL,                           // NormalizeContextCleanup
    NULL,                           // TransactionNotification
    NULL,                           // NormalizeNameComponentEx
    NULL                            // SectionNotification
};

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    FltInitializePushLock(&gPolicyLock);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilter);
    if (!NT_SUCCESS(status))
    {
        FltDeletePushLock(&gPolicyLock);
        return status;
    }

    status = BruceCreatePort();
    if (NT_SUCCESS(status))
    {
        status = FltStartFiltering(gFilter);
        if (!NT_SUCCESS(status))
        {
            FltCloseCommunicationPort(gServerPort);
            gServerPort = NULL;
        }
    }
    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        FltDeletePushLock(&gPolicyLock);
    }
    return status;
}

// The port admits SYSTEM only. FltBuildDefaultSecurityDescriptor would also admit
// Administrators, and with the agent gone any administrator could then switch blocking off or
// rewrite the policy. The agent connects from the LocalSystem service.
static NTSTATUS BruceCreatePort(VOID)
{
    SECURITY_DESCRIPTOR sd;
    UNICODE_STRING name = RTL_CONSTANT_STRING(BRUCE_PORT_NAME);
    OBJECT_ATTRIBUTES oa;
    PACL acl;
    ULONG aclSize;
    NTSTATUS status;

    status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) return status;

    aclSize = sizeof(ACL) + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(SeExports->SeLocalSystemSid);
    acl = (PACL)ExAllocatePool2(POOL_FLAG_PAGED, aclSize, BRUCE_TAG);
    if (acl == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    status = RtlCreateAcl(acl, aclSize, ACL_REVISION);
    if (NT_SUCCESS(status))
        status = RtlAddAccessAllowedAce(acl, ACL_REVISION, FLT_PORT_ALL_ACCESS, SeExports->SeLocalSystemSid);
    if (NT_SUCCESS(status))
        status = RtlSetDaclSecurityDescriptor(&sd, TRUE, acl, FALSE);
    if (NT_SUCCESS(status))
    {
        InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, &sd);
        // One agent at a time. The object manager keeps its own copy of the descriptor.
        status = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL,
            BrucePortConnect, BrucePortDisconnect, BrucePortMessage, 1);
    }
    ExFreePoolWithTag(acl, BRUCE_TAG);
    return status;
}

_Use_decl_annotations_
static NTSTATUS FLTAPI BruceUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    PAGED_CODE();

    // While blocking is on, `fltmc unload` and FilterUnload are refused. A mandatory unload (a
    // service stop) cannot be refused: the filter manager unloads the driver whatever this
    // returns. Blocking off, or the agent gone and the policy reset, lets an unload through.
    if (!FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY) && gLive.Blocking)
        return STATUS_FLT_DO_NOT_DETACH;

    // The server port closes first, or unloading can hang on a connected client.
    if (gServerPort != NULL)
    {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
    if (gFilter != NULL)
    {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    FltDeletePushLock(&gPolicyLock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS FLTAPI BruceInstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    PAGED_CODE();

    // Local volumes only: a remote host's credential store is that host's EDR's to guard.
    return VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ? STATUS_FLT_DO_NOT_ATTACH : STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS FLTAPI BruceInstanceQueryTeardown(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    // Only a manual detach (`fltmc detach`, FilterDetach, FltDetachVolume) comes here; unloads
    // and volume dismounts do not, so a dismount is never held up by this.
    return gLive.Blocking ? STATUS_FLT_DO_NOT_DETACH : STATUS_SUCCESS;
}

// ------------------------------------------------------------------ decisions

static ULONG BruceMatchName(_In_ PCUNICODE_STRING Name)
{
    ULONG match;
    FltAcquirePushLockShared(&gPolicyLock);
    match = BrucePolicyMatch(&gLive, Name->Buffer, Name->Length / sizeof(WCHAR));
    FltReleasePushLock(&gPolicyLock);
    return match;
}

static ULONG BruceMatchAncestorName(_In_ PCUNICODE_STRING Name)
{
    ULONG match;
    FltAcquirePushLockShared(&gPolicyLock);
    match = BrucePolicyMatchAncestor(&gLive, Name->Buffer, Name->Length / sizeof(WCHAR));
    FltReleasePushLock(&gPolicyLock);
    return match;
}

// An unresolved name can only be trusted by an image trusted for every guarded path.
static BOOLEAN BruceTrusted(_In_ ULONG PrefixIndex, _In_opt_ PCUNICODE_STRING Image)
{
    BOOLEAN trusted;
    if (Image == NULL || Image->Buffer == NULL) return FALSE;
    FltAcquirePushLockShared(&gPolicyLock);
    trusted = BrucePolicyIsTrusted(&gLive, PrefixIndex, Image->Buffer, Image->Length / sizeof(WCHAR));
    FltReleasePushLock(&gPolicyLock);
    return trusted;
}

// The requester's image as an NT path, or NULL when it cannot be had (the caller then counts
// as untrusted). Free with ExFreePool.
static PUNICODE_STRING BruceRequestorImage(_In_ PFLT_CALLBACK_DATA Data)
{
    PEPROCESS process = FltGetRequestorProcess(Data);
    PUNICODE_STRING image = NULL;
    if (process == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) return NULL;
    if (!NT_SUCCESS(SeLocateProcessImageName(process, &image))) return NULL;
    return image;
}

static VOID BruceCopyName(_Out_writes_(BRUCE_MAX_PATH) WCHAR* Dest, _In_opt_ PCUNICODE_STRING Source)
{
    SIZE_T chars;
    Dest[0] = L'\0';
    if (Source == NULL || Source->Buffer == NULL) return;
    chars = Source->Length / sizeof(WCHAR);
    if (chars > BRUCE_MAX_PATH - 1) chars = BRUCE_MAX_PATH - 1;
    RtlCopyMemory(Dest, Source->Buffer, chars * sizeof(WCHAR));
    Dest[chars] = L'\0';
}

// Reports a refusal to the agent. Never waits: with no reader at that moment the report is
// dropped and counted, and the refusal stands either way.
static VOID BruceNotify(_In_ BRUCE_OPERATION Operation, _In_ PFLT_CALLBACK_DATA Data, _In_ ULONG PrefixIndex,
    _In_opt_ PCUNICODE_STRING Path, _In_opt_ PCUNICODE_STRING Image)
{
    PBRUCE_NOTIFICATION note;
    LARGE_INTEGER noWait;
    NTSTATUS status;

    InterlockedIncrement(&gDenied);
    if (gClientPort == NULL)
    {
        InterlockedIncrement(&gNotifyDropped);
        return;
    }
    note = (PBRUCE_NOTIFICATION)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*note), BRUCE_TAG);
    if (note == NULL)
    {
        InterlockedIncrement(&gNotifyDropped);
        return;
    }
    note->Version = BRUCE_PROTOCOL_VERSION;
    note->Operation = (UINT32)Operation;
    note->ProcessId = FltGetRequestorProcessId(Data);
    note->PrefixIndex = PrefixIndex;
    BruceCopyName(note->Path, Path);
    BruceCopyName(note->Image, Image);

    noWait.QuadPart = 0;
    status = FltSendMessage(gFilter, &gClientPort, note, sizeof(*note), NULL, NULL, &noWait);
    if (status != STATUS_SUCCESS) InterlockedIncrement(&gNotifyDropped);
    ExFreePoolWithTag(note, BRUCE_TAG);
}

static FLT_PREOP_CALLBACK_STATUS BruceRefuse(_Inout_ PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

// ------------------------------------------------------------------ callbacks

_Use_decl_annotations_
static FLT_PREOP_CALLBACK_STATUS FLTAPI BrucePreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PFLT_FILE_NAME_INFORMATION normalized = NULL;
    PFILE_OBJECT file = Data->Iopb->TargetFileObject;
    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    BOOLEAN byId = BooleanFlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID);
    BOOLEAN recheck = FALSE;
    ULONG match = BRUCE_NO_MATCH;
    UNREFERENCED_PARAMETER(FltObjects);

    *CompletionContext = NULL;
    if (!gLive.Blocking) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) || FlagOn(file->Flags, FO_VOLUME_OPEN))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &name)))
    {
        match = BruceMatchName(&name->Name);
        if (match == BRUCE_NO_MATCH && BrucePolicyMayHaveShortName(name->Name.Buffer, name->Name.Length / sizeof(WCHAR)))
        {
            // USERDA~1 hides "user data" until the name is normalized.
            if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &normalized)))
                match = BruceMatchName(&normalized->Name);
            else
                recheck = TRUE;
        }
    }
    else if (file->RelatedFileObject == NULL && !byId)
    {
        // The name provider could not build a name: a raw name that is already guarded is
        // refused here, and the rest is decided once the file is open and its name certain.
        match = BruceMatchName(&file->FileName);
        recheck = (match == BRUCE_NO_MATCH);
    }
    else
    {
        recheck = TRUE;
    }
    // Before an open by file id, any name is the filter manager's reconstruction. One that
    // clears the open is checked again against the opened file's own name.
    if (byId && match == BRUCE_NO_MATCH) recheck = TRUE;

    if (match != BRUCE_NO_MATCH)
    {
        PUNICODE_STRING image = BruceRequestorImage(Data);
        if (!BruceTrusted(match, image))
        {
            PCUNICODE_STRING shown = normalized != NULL ? &normalized->Name : name != NULL ? &name->Name : &file->FileName;
            BruceNotify(BruceOpOpen, Data, match, shown, image);
            result = BruceRefuse(Data);
        }
        if (image != NULL) ExFreePool(image);
    }
    else if (recheck)
    {
        *CompletionContext = BRUCE_RECHECK;
        result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    if (normalized != NULL) FltReleaseFileNameInformation(normalized);
    if (name != NULL) FltReleaseFileNameInformation(name);
    return result;
}

_Use_decl_annotations_
static FLT_POSTOP_CALLBACK_STATUS FLTAPI BrucePostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PUNICODE_STRING image;
    ULONG match;

    if (CompletionContext != BRUCE_RECHECK || FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE || !gLive.Blocking)
        return FLT_POSTOP_FINISHED_PROCESSING;

    InterlockedIncrement(&gRechecked);
    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name)))
        match = BruceMatchName(&name->Name);
    else
        match = BRUCE_ANY_PREFIX;   // still nameless once open: refuse rather than guess

    if (match != BRUCE_NO_MATCH)
    {
        image = BruceRequestorImage(Data);
        // A handle already made for the file cannot be taken back; the file object stays open
        // in that one case, which a post-create callback does not normally meet.
        if (!BruceTrusted(match, image) && !FlagOn(FltObjects->FileObject->Flags, FO_HANDLE_CREATED))
        {
            FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            BruceNotify(BruceOpReopen, Data, match, name != NULL ? &name->Name : NULL, image);
        }
        if (image != NULL) ExFreePool(image);
    }

    if (name != NULL) FltReleaseFileNameInformation(name);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

_Use_decl_annotations_
static FLT_PREOP_CALLBACK_STATUS FLTAPI BrucePreSetInformation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION target = NULL;
    PFLT_FILE_NAME_INFORMATION normalized = NULL;
    PFLT_FILE_NAME_INFORMATION source = NULL;
    PFLT_FILE_NAME_INFORMATION sourceNormalized = NULL;
    PCUNICODE_STRING shown = NULL;
    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    BRUCE_OPERATION operation;
    HANDLE root;
    const WCHAR* raw;
    ULONG rawBytes;
    UNICODE_STRING rawName;
    BOOLEAN isDirectory = TRUE;
    BOOLEAN shortName = FALSE;
    ULONG match;

    *CompletionContext = NULL;
    if (!gLive.Blocking) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass)
    {
    case FileShortNameInformation:
        // Since Windows 10 1903 any caller with DELETE access may set a short name, and one
        // without ~digit is never expanded: a store folder, or a folder above it, renamed to
        // ...\Google\CH\ would no longer carry its fragment. Decided like renaming that folder.
        operation = BruceOpRename;
        shortName = TRUE;
        break;
    case FileRenameInformation:
    case FileRenameInformationEx:
    case FileRenameInformationBypassAccessCheck:
    case FileRenameInformationExBypassAccessCheck:
        operation = BruceOpRename;
        break;
    case FileLinkInformation:
    case FileLinkInformationEx:
    case FileLinkInformationBypassAccessCheck:
    case FileLinkInformationExBypassAccessCheck:
        operation = BruceOpLink;
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Where the file is going. A rename onto a guarded path is the bypass this hook exists to
    // stop, so a target the filter cannot read or resolve is unknown, and refused as such. A
    // short name goes nowhere: its buffer is the new name, and only what is named matters.
    if (shortName)
    {
        match = BRUCE_NO_MATCH;
    }
    else if (!BrucePolicyReadLinkTarget(Data->Iopb->Parameters.SetFileInformation.InfoBuffer,
            Data->Iopb->Parameters.SetFileInformation.Length, &root, &raw, &rawBytes) || rawBytes > MAXUSHORT)
    {
        match = BRUCE_ANY_PREFIX;
    }
    else
    {
        rawName.Buffer = (PWSTR)raw;
        rawName.Length = rawName.MaximumLength = (USHORT)rawBytes;
        if (NT_SUCCESS(FltGetDestinationFileNameInformation(FltObjects->Instance, FltObjects->FileObject, root,
                rawName.Buffer, rawBytes, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &target)))
        {
            shown = &target->Name;
            match = BruceMatchName(&target->Name);
            if (match == BRUCE_NO_MATCH && BrucePolicyMayHaveShortName(target->Name.Buffer, target->Name.Length / sizeof(WCHAR)))
            {
                if (NT_SUCCESS(FltGetDestinationFileNameInformation(FltObjects->Instance, FltObjects->FileObject, root,
                        rawName.Buffer, rawBytes, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &normalized)))
                {
                    shown = &normalized->Name;
                    match = BruceMatchName(&normalized->Name);
                }
                else
                {
                    match = BRUCE_ANY_PREFIX;   // an alias that cannot be expanded is not taken on trust
                }
            }
        }
        else
        {
            // No destination name: a guarded-looking raw name is refused like any other
            // destination that cannot be resolved.
            shown = &rawName;
            match = BruceMatchName(&rawName);
            if (match == BRUCE_NO_MATCH) match = BRUCE_ANY_PREFIX;
        }
    }

    // What is moving. Renaming a guarded directory, or a folder above one, carries the files
    // out from under their fragment, so it is refused like a rename onto a guarded path.
    if (match == BRUCE_NO_MATCH && operation == BruceOpRename &&
        (shortName || !NT_SUCCESS(FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory)) || isDirectory))
    {
        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &source)))
        {
            shown = &source->Name;
            match = BruceMatchAncestorName(&source->Name);
            if (match == BRUCE_NO_MATCH && BrucePolicyMayHaveShortName(source->Name.Buffer, source->Name.Length / sizeof(WCHAR)))
            {
                if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &sourceNormalized)))
                {
                    shown = &sourceNormalized->Name;
                    match = BruceMatchAncestorName(&sourceNormalized->Name);
                }
                else
                {
                    match = BRUCE_ANY_PREFIX;
                }
            }
        }
        else
        {
            match = BRUCE_ANY_PREFIX;   // a directory that cannot be named is not moved on trust
        }
    }

    if (match != BRUCE_NO_MATCH)
    {
        PUNICODE_STRING image = BruceRequestorImage(Data);
        if (!BruceTrusted(match, image))
        {
            BruceNotify(operation, Data, match, shown, image);
            result = BruceRefuse(Data);
        }
        if (image != NULL) ExFreePool(image);
    }

    if (sourceNormalized != NULL) FltReleaseFileNameInformation(sourceNormalized);
    if (source != NULL) FltReleaseFileNameInformation(source);
    if (normalized != NULL) FltReleaseFileNameInformation(normalized);
    if (target != NULL) FltReleaseFileNameInformation(target);
    return result;
}

// ------------------------------------------------------------------ port

_Use_decl_annotations_
static NTSTATUS FLTAPI BrucePortConnect(
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG SizeOfContext,
    PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    PAGED_CODE();

    gClientPort = ClientPort;
    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static VOID FLTAPI BrucePortDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    PAGED_CODE();

    // Sets gClientPort to NULL, in step with any FltSendMessage in flight. The policy stays:
    // killing the agent does not switch protection off.
    FltCloseClientPort(gFilter, &gClientPort);
}

static NTSTATUS BruceReplyStatus(_Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength)
{
    BRUCE_STATUS status;

    *ReturnOutputBufferLength = 0;
    if (OutputBuffer == NULL || OutputBufferLength < sizeof(status)) return STATUS_BUFFER_TOO_SMALL;

    RtlZeroMemory(&status, sizeof(status));
    status.Version = BRUCE_PROTOCOL_VERSION;
    FltAcquirePushLockShared(&gPolicyLock);
    status.Blocking = gLive.Blocking;
    status.PrefixCount = gLive.PrefixCount;
    status.TrustedCount = gLive.TrustedCount;
    FltReleasePushLock(&gPolicyLock);
    status.Denied = (UINT32)gDenied;
    status.Rechecked = (UINT32)gRechecked;
    status.NotifyDropped = (UINT32)gNotifyDropped;

    __try
    {
        RtlCopyMemory(OutputBuffer, &status, sizeof(status));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_INVALID_USER_BUFFER;
    }
    *ReturnOutputBufferLength = sizeof(status);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS FLTAPI BrucePortMessage(
    PVOID PortCookie,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength)
{
    BRUCE_MESSAGE message;
    BRUCE_APPLY_RESULT applied;
    UNREFERENCED_PARAMETER(PortCookie);
    PAGED_CODE();

    *ReturnOutputBufferLength = 0;
    if (InputBuffer == NULL || InputBufferLength < sizeof(message)) return STATUS_INVALID_PARAMETER;

    // FltMgr has probed both buffers for the caller's mode (PFLT_MESSAGE_NOTIFY), but they stay
    // raw user memory the caller can unmap at any moment: each is touched once, under
    // try/except, as a byte copy that assumes no alignment.
    __try
    {
        RtlCopyMemory(&message, InputBuffer, sizeof(message));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_INVALID_USER_BUFFER;
    }

    switch (message.Command)
    {
    case BruceSetBlocking:
        if (message.Flag > 1) return STATUS_INVALID_PARAMETER;
        FltAcquirePushLockExclusive(&gPolicyLock);
        gLive.Blocking = (BOOLEAN)(message.Flag != 0);
        FltReleasePushLock(&gPolicyLock);
        return STATUS_SUCCESS;

    case BruceCommitPolicy:
        FltAcquirePushLockExclusive(&gPolicyLock);
        BrucePolicyCommit(&gLive, &gStaged);
        FltReleasePushLock(&gPolicyLock);
        return STATUS_SUCCESS;

    case BruceQueryStatus:
        return BruceReplyStatus(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);

    default:
        FltAcquirePushLockExclusive(&gPolicyLock);
        applied = BrucePolicyApply(&gStaged, &message);
        FltReleasePushLock(&gPolicyLock);
        switch (applied)
        {
        case BruceApplyOk:      return STATUS_SUCCESS;
        case BruceApplyFull:    return STATUS_QUOTA_EXCEEDED;
        case BruceApplyUnknown: return STATUS_INVALID_DEVICE_REQUEST;
        default:                return STATUS_INVALID_PARAMETER;
        }
    }
}

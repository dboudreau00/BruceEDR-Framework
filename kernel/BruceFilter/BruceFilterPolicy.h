#pragma once

//
// The minifilter's decisions as pure functions: no kernel calls, no locks, no allocation.
// The same source builds into the driver and into the user-mode tests under test\, so
// what the tests prove is what the kernel runs. Callers include the platform headers
// (fltKernel.h or windows.h) and BruceFilter.h first.
//

#define BRUCE_NO_MATCH 0xFFFFFFFEu   // distinct from BRUCE_ANY_PREFIX

typedef struct _BRUCE_POLICY {
    BOOLEAN Blocking;
    ULONG   PrefixCount;
    ULONG   TrustedCount;
    USHORT  PrefixChars[BRUCE_MAX_ENTRIES];
    USHORT  TrustedChars[BRUCE_MAX_TRUSTED];
    ULONG   TrustedPrefix[BRUCE_MAX_TRUSTED];     // fragment index, or BRUCE_ANY_PREFIX
    WCHAR   Prefix[BRUCE_MAX_ENTRIES][BRUCE_MAX_PATH];
    WCHAR   Trusted[BRUCE_MAX_TRUSTED][BRUCE_MAX_PATH];
} BRUCE_POLICY, *PBRUCE_POLICY;

typedef enum _BRUCE_APPLY_RESULT {
    BruceApplyOk      = 0,
    BruceApplyInvalid = 1,   // malformed entry; nothing changed
    BruceApplyFull    = 2,   // table full; nothing changed
    BruceApplyUnknown = 3    // not a policy command
} BRUCE_APPLY_RESULT;

// Mirror of FILE_RENAME_INFORMATION and FILE_LINK_INFORMATION, which share this layout.
// The driver checks the offsets against the real structs at compile time.
typedef struct _BRUCE_LINK_INFO {
    ULONG  Flags;            // ReplaceIfExists in the original classes, Flags in the Ex ones
    HANDLE RootDirectory;
    ULONG  FileNameLength;   // bytes
    WCHAR  FileName[1];
} BRUCE_LINK_INFO;

// Index of the first guarded fragment found anywhere in the path (case-insensitive), or
// BRUCE_NO_MATCH. The guarded directory itself (no trailing separator) matches as well, and
// a stream on the last name (Dir::$INDEX_ALLOCATION) does not hide it.
ULONG BrucePolicyMatch(_In_ const BRUCE_POLICY* Policy, _In_reads_(Chars) const WCHAR* Path, _In_ SIZE_T Chars);

// For a directory being renamed: the fragment it would carry away, because the directory's
// trailing components begin that fragment (...\Google\Chrome begins \google\chrome\user data\),
// or BRUCE_NO_MATCH. A stream or trailing separator on the last name is ignored here too.
ULONG BrucePolicyMatchAncestor(_In_ const BRUCE_POLICY* Policy, _In_reads_(Chars) const WCHAR* Path, _In_ SIZE_T Chars);

// TRUE when Image is exactly a trusted image for this fragment or for every fragment.
BOOLEAN BrucePolicyIsTrusted(_In_ const BRUCE_POLICY* Policy, _In_ ULONG PrefixIndex,
    _In_reads_(Chars) const WCHAR* Image, _In_ SIZE_T Chars);

// TRUE when a path component could be an 8.3 alias (USERDA~1), which hides guarded words
// until the name is normalized.
BOOLEAN BrucePolicyMayHaveShortName(_In_reads_(Chars) const WCHAR* Path, _In_ SIZE_T Chars);

// Applies one staged-policy command (clear, add fragment, add trusted image).
BRUCE_APPLY_RESULT BrucePolicyApply(_Inout_ BRUCE_POLICY* Staged, _In_ const BRUCE_MESSAGE* Message);

// Copies the staged policy over the live one, keeping the live blocking flag.
VOID BrucePolicyCommit(_Inout_ BRUCE_POLICY* Live, _In_ const BRUCE_POLICY* Staged);

// Validates a rename or link buffer and returns its target name. FALSE when the buffer is
// too short for the name it claims to hold.
BOOLEAN BrucePolicyReadLinkTarget(_In_reads_bytes_(Length) const VOID* Buffer, _In_ ULONG Length,
    _Out_ HANDLE* RootDirectory, _Outptr_result_maybenull_ const WCHAR** Name, _Out_ ULONG* NameBytes);

// ------------------------------------------------------------------ process guard
//
// Handle callbacks (BruceProcessGuard.c) take away the dangerous access bits of a handle to a
// process whose image is trusted for a store, unless the process asking is trusted for the
// same stores. The numbers are the documented access rights, spelled out so the kernel and
// the user-mode tests agree on them; the tests compare each with the SDK's constant.
//
// Taken from a process handle: the ways into a trusted process that never open its files.
#define BRUCE_PROCESS_CREATE_THREAD   0x0002   // remote thread
#define BRUCE_PROCESS_VM_OPERATION    0x0008   // VirtualProtectEx, WriteProcessMemory
#define BRUCE_PROCESS_VM_WRITE        0x0020   // WriteProcessMemory
#define BRUCE_PROCESS_DUP_HANDLE      0x0040   // DuplicateHandle: the browser's own open file handles
#define BRUCE_PROCESS_CREATE_PROCESS  0x0080   // parent for a child that inherits its handles
#define BRUCE_PROCESS_SET_INFORMATION 0x0200   // debug object, token, instrumentation callback
#define BRUCE_PROCESS_SUSPEND_RESUME  0x0800   // suspend, resume, attach a debugger
#define BRUCE_PROCESS_STRIP \
    (BRUCE_PROCESS_CREATE_THREAD | BRUCE_PROCESS_VM_OPERATION | BRUCE_PROCESS_VM_WRITE | \
     BRUCE_PROCESS_DUP_HANDLE | BRUCE_PROCESS_CREATE_PROCESS | BRUCE_PROCESS_SET_INFORMATION | \
     BRUCE_PROCESS_SUSPEND_RESUME)
// Kept: PROCESS_TERMINATE (a hung browser must stay killable), PROCESS_VM_READ and the query
// rights (monitors, task managers and the agent's memory scan need them, and the documented
// list of rights a callback may remove does not include VM_READ), SET_QUOTA, SYNCHRONIZE.

#define BRUCE_THREAD_SUSPEND_RESUME      0x0002
#define BRUCE_THREAD_SET_CONTEXT         0x0010   // APC injection, thread hijack
#define BRUCE_THREAD_SET_INFORMATION     0x0020
#define BRUCE_THREAD_DIRECT_IMPERSONATION 0x0200
#define BRUCE_THREAD_STRIP \
    (BRUCE_THREAD_SUSPEND_RESUME | BRUCE_THREAD_SET_CONTEXT | BRUCE_THREAD_SET_INFORMATION | \
     BRUCE_THREAD_DIRECT_IMPERSONATION)

// The process that created the target keeps only what starting it needs. CreateProcess hands
// back a process and a thread handle with all access, and resumes the new process's first
// thread through that thread handle (unless asked to leave it suspended), so
// THREAD_SUSPEND_RESUME stays on a thread handle. Everything that writes into the new process
// or runs code in it goes, as for anyone else: memory writes and protection changes, remote
// threads, handle copies, instrumentation callbacks, the first thread's context (APCs, hijack).
#define BRUCE_CREATOR_PROCESS_STRIP BRUCE_PROCESS_STRIP
#define BRUCE_CREATOR_THREAD_STRIP \
    (BRUCE_THREAD_SET_CONTEXT | BRUCE_THREAD_SET_INFORMATION | BRUCE_THREAD_DIRECT_IMPERSONATION)

// A request that names no right: the system may resolve these after the callback ran, so
// they are replaced by the explicit rights that survive (all access minus the stripped ones).
#define BRUCE_ACCESS_GENERIC_ALL      0x10000000u
#define BRUCE_ACCESS_GENERIC_WRITE    0x40000000u
#define BRUCE_ACCESS_MAXIMUM_ALLOWED  0x02000000u
#define BRUCE_ACCESS_ALL              0x001FFFFFu   // PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS (Vista and later)

// Bit p is set when the image is trusted for fragment p; an image trusted for every fragment
// has every bit of the live policy's fragments set. Zero: trusted for nothing, not protected.
ULONGLONG BrucePolicyTrustMask(_In_ const BRUCE_POLICY* Policy, _In_reads_(Chars) const WCHAR* Image, _In_ SIZE_T Chars);

typedef struct _BRUCE_HANDLE_REQUEST {
    BOOLEAN   IsThread;        // the target is a thread (of the process whose trust is TargetTrust)
    BOOLEAN   KernelHandle;
    BOOLEAN   SameProcess;     // the process that gets the handle is the target's own process
    BOOLEAN   ReceiverExempt;  // System, a protected process, the agent
    BOOLEAN   ReceiverIsCreator; // the process that created the target: the creator strip masks
    ULONGLONG TargetTrust;     // BrucePolicyTrustMask of the target process's image
    ULONGLONG ReceiverTrust;   // the same for the process that gets the handle (0 when unknown)
    ACCESS_MASK Desired;
} BRUCE_HANDLE_REQUEST;

// The access the handle may have: Desired, less the stripped rights when the target is
// protected and the receiver is neither the target, exempt, nor trusted for every store the
// target is trusted for. The target's creator loses the creator strip masks instead, which
// leave it able to resume the first thread. Never adds a right the caller did not ask for,
// except that a request for all or maximum access becomes the explicit rights that survive.
ACCESS_MASK BruceGuardAccess(_In_ const BRUCE_HANDLE_REQUEST* Request);

// FALSE when the request holds none of the rights the guard removes (and no wildcard), so a
// callback can leave at once without looking anything up. Most handle requests do exactly that.
BOOLEAN BruceGuardCares(_In_ BOOLEAN IsThread, _In_ ACCESS_MASK Desired);

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

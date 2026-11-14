//
// BruceFilter's decision logic. Pure functions, shared by the driver and the user-mode
// tests (test\PolicyTests.c), so the tests exercise the code the kernel runs.
//

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#define BruceUpcase(c) RtlUpcaseUnicodeChar(c)
#else
#include <windows.h>
#include <wctype.h>
#define BruceUpcase(c) ((WCHAR)towupper(c))
#endif

#include "BruceFilter.h"
#include "BruceFilterPolicy.h"

static SIZE_T BruceLength(_In_reads_(Max) const WCHAR* Text, _In_ SIZE_T Max)
{
    SIZE_T n = 0;
    while (n < Max && Text[n] != L'\0') n++;
    return n;
}

// Text against an already upper-cased pattern of the same length.
static BOOLEAN BruceEqualsUpcased(_In_reads_(Chars) const WCHAR* Text, _In_reads_(Chars) const WCHAR* Upcased,
    _In_ SIZE_T Chars)
{
    for (SIZE_T i = 0; i < Chars; i++)
        if (BruceUpcase(Text[i]) != Upcased[i]) return FALSE;
    return TRUE;
}

static BOOLEAN BruceSameChars(_In_reads_(Chars) const WCHAR* A, _In_reads_(Chars) const WCHAR* B, _In_ SIZE_T Chars)
{
    for (SIZE_T i = 0; i < Chars; i++)
        if (A[i] != B[i]) return FALSE;
    return TRUE;
}

static VOID BruceCopyUpcased(_Out_writes_(BRUCE_MAX_PATH) WCHAR* Dest, _In_reads_(Chars) const WCHAR* Src,
    _In_ SIZE_T Chars)
{
    for (SIZE_T i = 0; i < Chars; i++) Dest[i] = BruceUpcase(Src[i]);
    Dest[Chars] = L'\0';
}

// Components in a fragment: \a\b\ has two.
static ULONG BruceFragmentComponents(_In_reads_(Chars) const WCHAR* Fragment, _In_ SIZE_T Chars)
{
    ULONG separators = 0;
    for (SIZE_T i = 0; i < Chars; i++) if (Fragment[i] == L'\\') separators++;
    return separators > 0 ? separators - 1 : 0;
}

// Matches the first Count components of Fragment (it begins and ends with a separator) against
// the path components that follow the separator at Path[At]. A component's name ends at its
// first colon, wherever the component sits: Dir::$INDEX_ALLOCATION, Dir:$I30:$INDEX_ALLOCATION
// and Dir:stream all still open Dir, and the file system accepts them in the middle of a path
// as well as at its end. *After is the end of the last component matched, stream included.
static BOOLEAN BruceMatchComponents(_In_reads_(Chars) const WCHAR* Path, _In_ SIZE_T Chars, _In_ SIZE_T At,
    _In_reads_(FragmentChars) const WCHAR* Fragment, _In_ SIZE_T FragmentChars, _In_ ULONG Count,
    _Out_ SIZE_T* After)
{
    SIZE_T pos = At;
    SIZE_T f = 0;
    *After = 0;
    for (ULONG c = 0; c < Count; c++)
    {
        SIZE_T fragEnd = f + 1;
        SIZE_T nameStart = pos + 1;
        SIZE_T rawEnd = nameStart;
        SIZE_T nameEnd = nameStart;
        if (f >= FragmentChars || Fragment[f] != L'\\' || pos >= Chars || Path[pos] != L'\\') return FALSE;
        while (fragEnd < FragmentChars && Fragment[fragEnd] != L'\\') fragEnd++;
        while (rawEnd < Chars && Path[rawEnd] != L'\\') rawEnd++;
        while (nameEnd < rawEnd && Path[nameEnd] != L':') nameEnd++;
        if (nameEnd - nameStart != fragEnd - (f + 1) ||
            !BruceEqualsUpcased(Path + nameStart, Fragment + f + 1, nameEnd - nameStart))
            return FALSE;
        pos = rawEnd;
        f = fragEnd;
    }
    *After = pos;
    return TRUE;
}

ULONG BrucePolicyMatch(_In_ const BRUCE_POLICY* Policy, _In_reads_(Chars) const WCHAR* Path, _In_ SIZE_T Chars)
{
    if (Path == NULL) return BRUCE_NO_MATCH;
    // Every fragment starts with a separator, so only separators can begin a match. The guarded
    // directory itself matches too: its name may end the path with no separator after it.
    for (SIZE_T i = 0; i < Chars; i++)
    {
        if (Path[i] != L'\\') continue;
        for (ULONG p = 0; p < Policy->PrefixCount; p++)
        {
            SIZE_T after;
            ULONG count;
            if (i + 1 < Chars && Policy->Prefix[p][1] != L'\\' && BruceUpcase(Path[i + 1]) != Policy->Prefix[p][1]) continue;
            count = BruceFragmentComponents(Policy->Prefix[p], Policy->PrefixChars[p]);
            if (count > 0 && BruceMatchComponents(Path, Chars, i, Policy->Prefix[p], Policy->PrefixChars[p], count, &after))
                return p;
        }
    }
    return BRUCE_NO_MATCH;
}

ULONG BrucePolicyMatchAncestor(_In_ const BRUCE_POLICY* Policy, _In_reads_(Chars) const WCHAR* Path, _In_ SIZE_T Chars)
{
    if (Path == NULL) return BRUCE_NO_MATCH;
    // The directory carries a guarded tree when its trailing components are the leading
    // components of a fragment: renaming ...\Google\Chrome breaks \google\chrome\user data\.
    for (ULONG p = 0; p < Policy->PrefixCount; p++)
    {
        ULONG components = BruceFragmentComponents(Policy->Prefix[p], Policy->PrefixChars[p]);
        for (ULONG k = 1; k <= components; k++)
        {
            for (SIZE_T i = 0; i < Chars; i++)
            {
                SIZE_T after;
                if (Path[i] != L'\\') continue;
                if (BruceMatchComponents(Path, Chars, i, Policy->Prefix[p], Policy->PrefixChars[p], k, &after) &&
                    (after == Chars || (after + 1 == Chars && Path[after] == L'\\')))
                    return p;
            }
        }
    }
    return BRUCE_NO_MATCH;
}
BOOLEAN BrucePolicyIsTrusted(_In_ const BRUCE_POLICY* Policy, _In_ ULONG PrefixIndex,
    _In_reads_(Chars) const WCHAR* Image, _In_ SIZE_T Chars)
{
    if (Image == NULL || Chars == 0) return FALSE;
    for (ULONG t = 0; t < Policy->TrustedCount; t++)
    {
        ULONG scope = Policy->TrustedPrefix[t];
        if (scope != BRUCE_ANY_PREFIX && scope != PrefixIndex) continue;
        if (Policy->TrustedChars[t] == Chars && BruceEqualsUpcased(Image, Policy->Trusted[t], Chars)) return TRUE;
    }
    return FALSE;
}

BOOLEAN BrucePolicyMayHaveShortName(_In_reads_(Chars) const WCHAR* Path, _In_ SIZE_T Chars)
{
    if (Path == NULL) return FALSE;
    for (SIZE_T i = 0; i + 1 < Chars; i++)
        if (Path[i] == L'~' && Path[i + 1] >= L'0' && Path[i + 1] <= L'9') return TRUE;
    return FALSE;
}

// \name\ or \a\b\: a separator at each end and at least two named characters between them,
// because a bare word or a lone separator would match far too much.
static BOOLEAN BruceIsFragment(_In_reads_(Chars) const WCHAR* Text, _In_ SIZE_T Chars)
{
    SIZE_T named = 0;
    if (Chars < 2 || Text[0] != L'\\' || Text[Chars - 1] != L'\\') return FALSE;
    for (SIZE_T i = 1; i + 1 < Chars; i++) if (Text[i] != L'\\') named++;
    return named >= 2;
}

// A full NT image path (\Device\...), without parent references.
static BOOLEAN BruceIsImagePath(_In_reads_(Chars) const WCHAR* Text, _In_ SIZE_T Chars)
{
    static const WCHAR device[] = L"\\DEVICE\\";
    const SIZE_T deviceChars = (sizeof(device) / sizeof(WCHAR)) - 1;
    if (Chars <= deviceChars || !BruceEqualsUpcased(Text, device, deviceChars)) return FALSE;
    for (SIZE_T i = 0; i + 3 < Chars; i++)
        if (Text[i] == L'\\' && Text[i + 1] == L'.' && Text[i + 2] == L'.' && Text[i + 3] == L'\\') return FALSE;
    return Text[Chars - 1] != L'\\';
}

BRUCE_APPLY_RESULT BrucePolicyApply(_Inout_ BRUCE_POLICY* Staged, _In_ const BRUCE_MESSAGE* Message)
{
    // No terminator inside the field means the sender's text was cut short: never guess.
    SIZE_T chars = BruceLength(Message->Path, BRUCE_MAX_PATH);
    WCHAR upcased[BRUCE_MAX_PATH];

    switch (Message->Command)
    {
    case BruceClearPolicy:
        RtlZeroMemory(Staged, sizeof(*Staged));
        return BruceApplyOk;

    case BruceAddSensitivePath:
        if (chars >= BRUCE_MAX_PATH || !BruceIsFragment(Message->Path, chars)) return BruceApplyInvalid;
        BruceCopyUpcased(upcased, Message->Path, chars);
        for (ULONG p = 0; p < Staged->PrefixCount; p++)
            if (Staged->PrefixChars[p] == chars && BruceSameChars(Staged->Prefix[p], upcased, chars))
                return BruceApplyOk;
        if (Staged->PrefixCount >= BRUCE_MAX_ENTRIES) return BruceApplyFull;
        RtlCopyMemory(Staged->Prefix[Staged->PrefixCount], upcased, (chars + 1) * sizeof(WCHAR));
        Staged->PrefixChars[Staged->PrefixCount] = (USHORT)chars;
        Staged->PrefixCount++;
        return BruceApplyOk;

    case BruceAddTrustedImage:
        if (chars >= BRUCE_MAX_PATH || !BruceIsImagePath(Message->Path, chars)) return BruceApplyInvalid;
        if (Message->Flag != BRUCE_ANY_PREFIX && Message->Flag >= Staged->PrefixCount) return BruceApplyInvalid;
        BruceCopyUpcased(upcased, Message->Path, chars);
        for (ULONG t = 0; t < Staged->TrustedCount; t++)
            if (Staged->TrustedPrefix[t] == Message->Flag && Staged->TrustedChars[t] == chars &&
                BruceSameChars(Staged->Trusted[t], upcased, chars))
                return BruceApplyOk;
        if (Staged->TrustedCount >= BRUCE_MAX_TRUSTED) return BruceApplyFull;
        RtlCopyMemory(Staged->Trusted[Staged->TrustedCount], upcased, (chars + 1) * sizeof(WCHAR));
        Staged->TrustedChars[Staged->TrustedCount] = (USHORT)chars;
        Staged->TrustedPrefix[Staged->TrustedCount] = Message->Flag;
        Staged->TrustedCount++;
        return BruceApplyOk;

    default:
        return BruceApplyUnknown;
    }
}

// Blocking is read without the lock on every IRP, so a commit must never write it: copying the
// whole staged policy (Blocking FALSE) and restoring the flag afterwards left a window, on every
// commit, in which opens went unchecked. Only the tables after it are copied.
C_ASSERT(FIELD_OFFSET(BRUCE_POLICY, Blocking) == 0);
C_ASSERT(FIELD_OFFSET(BRUCE_POLICY, PrefixCount) > FIELD_OFFSET(BRUCE_POLICY, Blocking));

VOID BrucePolicyCommit(_Inout_ BRUCE_POLICY* Live, _In_ const BRUCE_POLICY* Staged)
{
    const SIZE_T start = FIELD_OFFSET(BRUCE_POLICY, PrefixCount);
    RtlCopyMemory((UCHAR*)Live + start, (const UCHAR*)Staged + start, sizeof(*Live) - start);
}

BOOLEAN BrucePolicyReadLinkTarget(_In_reads_bytes_(Length) const VOID* Buffer, _In_ ULONG Length,
    _Out_ HANDLE* RootDirectory, _Outptr_result_maybenull_ const WCHAR** Name, _Out_ ULONG* NameBytes)
{
    const ULONG header = (ULONG)FIELD_OFFSET(BRUCE_LINK_INFO, FileName);
    const BRUCE_LINK_INFO* info = (const BRUCE_LINK_INFO*)Buffer;

    *RootDirectory = NULL;
    *Name = NULL;
    *NameBytes = 0;
    if (Buffer == NULL || Length < header) return FALSE;
    if (info->FileNameLength == 0 || (info->FileNameLength % sizeof(WCHAR)) != 0) return FALSE;
    if (info->FileNameLength > Length - header) return FALSE;
    *RootDirectory = info->RootDirectory;
    *Name = info->FileName;
    *NameBytes = info->FileNameLength;
    return TRUE;
}

ULONGLONG BrucePolicyTrustMask(_In_ const BRUCE_POLICY* Policy, _In_reads_(Chars) const WCHAR* Image, _In_ SIZE_T Chars)
{
    ULONGLONG every = Policy->PrefixCount >= 64 ? ~0ull : ((1ull << Policy->PrefixCount) - 1);
    ULONGLONG mask = 0;
    if (Image == NULL || Chars == 0) return 0;
    for (ULONG t = 0; t < Policy->TrustedCount; t++)
    {
        ULONG scope = Policy->TrustedPrefix[t];
        if (Policy->TrustedChars[t] != Chars || !BruceEqualsUpcased(Image, Policy->Trusted[t], Chars)) continue;
        if (scope == BRUCE_ANY_PREFIX) mask |= every;
        else if (scope < Policy->PrefixCount) mask |= 1ull << scope;
    }
    return mask;
}

ACCESS_MASK BruceGuardAccess(_In_ const BRUCE_HANDLE_REQUEST* Request)
{
    ACCESS_MASK strip = Request->IsThread ? BRUCE_THREAD_STRIP : BRUCE_PROCESS_STRIP;
    ACCESS_MASK desired = Request->Desired;

    if (Request->KernelHandle || Request->TargetTrust == 0) return desired;
    if (Request->SameProcess || Request->ReceiverExempt) return desired;
    // Trusted for every store the target is trusted for: Chrome's browser and its renderers
    // are one image; Edge, or a backup agent trusted for another store, is not.
    if ((Request->TargetTrust & ~Request->ReceiverTrust) == 0) return desired;

    if ((desired & (BRUCE_ACCESS_GENERIC_ALL | BRUCE_ACCESS_MAXIMUM_ALLOWED)) != 0)
        desired = (desired & ~(BRUCE_ACCESS_GENERIC_ALL | BRUCE_ACCESS_MAXIMUM_ALLOWED)) | BRUCE_ACCESS_ALL;
    desired &= ~BRUCE_ACCESS_GENERIC_WRITE;
    return desired & ~strip;
}

BOOLEAN BruceGuardCares(_In_ BOOLEAN IsThread, _In_ ACCESS_MASK Desired)
{
    ACCESS_MASK strip = IsThread ? BRUCE_THREAD_STRIP : BRUCE_PROCESS_STRIP;
    return (Desired & (strip | BRUCE_ACCESS_GENERIC_ALL | BRUCE_ACCESS_GENERIC_WRITE | BRUCE_ACCESS_MAXIMUM_ALLOWED)) != 0;
}

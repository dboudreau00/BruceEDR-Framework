//
// User-mode tests for BruceFilterPolicy.c, the code the driver runs for every decision.
// ..\build.ps1 compiles this file against the same policy source and runs it.
//

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "..\BruceFilter.h"
#include "..\BruceFilterPolicy.h"

static int g_checks;
static int g_failures;

#define CHECK(cond)                                                              \
    do {                                                                         \
        g_checks++;                                                              \
        if (!(cond)) {                                                           \
            g_failures++;                                                        \
            printf("FAIL line %d: %s\n", __LINE__, #cond);                       \
        }                                                                        \
    } while (0)

// Policies are 66 KB each: keep them off the stack.
static BRUCE_POLICY g_staged;
static BRUCE_POLICY g_live;

static BRUCE_APPLY_RESULT Send(BRUCE_POLICY* policy, UINT32 command, UINT32 flag, const WCHAR* path)
{
    BRUCE_MESSAGE message;
    ZeroMemory(&message, sizeof(message));
    message.Command = command;
    message.Flag = flag;
    if (path != NULL) wcsncpy_s(message.Path, BRUCE_MAX_PATH, path, _TRUNCATE);
    return BrucePolicyApply(policy, &message);
}

static ULONG Match(const BRUCE_POLICY* policy, const WCHAR* path)
{
    return BrucePolicyMatch(policy, path, wcslen(path));
}

static ULONG Ancestor(const BRUCE_POLICY* policy, const WCHAR* path)
{
    return BrucePolicyMatchAncestor(policy, path, wcslen(path));
}

static BOOLEAN Trusted(const BRUCE_POLICY* policy, ULONG prefix, const WCHAR* image)
{
    return BrucePolicyIsTrusted(policy, prefix, image, wcslen(image));
}

static void Seed(BRUCE_POLICY* policy)
{
    CHECK(Send(policy, BruceClearPolicy, 0, NULL) == BruceApplyOk);
    CHECK(Send(policy, BruceAddSensitivePath, 0, L"\\google\\chrome\\user data\\") == BruceApplyOk);   // 0
    CHECK(Send(policy, BruceAddSensitivePath, 0, L"\\mozilla\\firefox\\profiles\\") == BruceApplyOk);  // 1
    CHECK(Send(policy, BruceAddSensitivePath, 0, L"\\exodus\\") == BruceApplyOk);                      // 2
}

// The wire layout, mirrored byte for byte by MinifilterClient.cs, whose tests pin the same
// numbers. Compile-time checks: a drift fails the build rather than a run.
C_ASSERT(sizeof(BRUCE_MESSAGE) == 528);
C_ASSERT(sizeof(BRUCE_STATUS) == 32);
C_ASSERT(sizeof(BRUCE_NOTIFICATION) == 1056);
C_ASSERT(FIELD_OFFSET(BRUCE_MESSAGE, Path) == 8);
C_ASSERT(FIELD_OFFSET(BRUCE_NOTIFICATION, Path) == 16);
C_ASSERT(FIELD_OFFSET(BRUCE_NOTIFICATION, Image) == 16 + 520);
// FILE_RENAME_INFORMATION and FILE_LINK_INFORMATION on x64.
C_ASSERT(FIELD_OFFSET(BRUCE_LINK_INFO, RootDirectory) == 8);
C_ASSERT(FIELD_OFFSET(BRUCE_LINK_INFO, FileNameLength) == 16);
C_ASSERT(FIELD_OFFSET(BRUCE_LINK_INFO, FileName) == 20);

static void TestMatching(void)
{
    Seed(&g_live);
    CHECK(Match(&g_live, L"\\Device\\HarddiskVolume3\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data") == 0);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\x.default\\logins.json") == 1);
    CHECK(Match(&g_live, L"\\USERS\\BOB\\APPDATA\\ROAMING\\EXODUS\\exodus.wallet\\seed.seco") == 2);
    // Any caller may open a path in lower case, the first letter of a fragment included.
    CHECK(Match(&g_live, L"\\users\\bob\\appdata\\local\\google\\chrome\\user data\\default\\login data") == 0);
    // The guarded directory itself, opened without a trailing separator.
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data") == 0);
    // A stream or a trailing separator still opens the same directory or file.
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus::$INDEX_ALLOCATION") == 2);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus:$I30:$INDEX_ALLOCATION") == 2);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus:hidden") == 2);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus\\") == 2);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco:Zone.Identifier") == 2);
    // A stream's own name is not a path component.
    CHECK(Match(&g_live, L"\\Users\\bob\\Documents\\notes.txt:Exodus") == BRUCE_NO_MATCH);
    // Whole names only: no partial words, no bare artifact names anywhere else.
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data2\\x") == BRUCE_NO_MATCH);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Dat") == BRUCE_NO_MATCH);
    CHECK(Match(&g_live, L"\\Users\\bob\\Documents\\exodus-notes.txt") == BRUCE_NO_MATCH);
    CHECK(Match(&g_live, L"\\Users\\bob\\Documents\\Login Data") == BRUCE_NO_MATCH);
    CHECK(Match(&g_live, L"") == BRUCE_NO_MATCH);
    CHECK(BrucePolicyMatch(&g_live, NULL, 0) == BRUCE_NO_MATCH);
    // A counted name is not read past its length.
    {
        const WCHAR* path = L"\\Users\\bob\\AppData\\Roaming\\Exodus\\x";
        CHECK(BrucePolicyMatch(&g_live, path, wcslen(path) - 9) == BRUCE_NO_MATCH);   // ends at ...\Roaming
    }
}

static void TestAncestors(void)
{
    Seed(&g_live);
    // Renaming any of these would carry the Chrome profile out from under its fragment.
    CHECK(Ancestor(&g_live, L"\\Device\\HarddiskVolume3\\Users\\bob\\AppData\\Local\\Google") == 0);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Google\\Chrome") == 0);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data") == 0);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus") == 2);
    // The same directories behind a stream or a trailing separator.
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Google::$INDEX_ALLOCATION") == 0);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Google\\Chrome\\") == 0);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus:$I30:$INDEX_ALLOCATION") == 2);
    // A folder above the fragment leaves it intact, and an unrelated folder is fine.
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local") == BRUCE_NO_MATCH);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Googleplex") == BRUCE_NO_MATCH);
    // Only whole components count: these names merely begin a fragment's components.
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Goo") == BRUCE_NO_MATCH);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Google\\Chr") == BRUCE_NO_MATCH);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Microsoft\\Chrome") == BRUCE_NO_MATCH);
    CHECK(Ancestor(&g_live, L"Google") == BRUCE_NO_MATCH);   // not separator-aligned
}

static BOOLEAN ShortName(const WCHAR* path)
{
    return BrucePolicyMayHaveShortName(path, wcslen(path));
}

static void TestShortNames(void)
{
    CHECK(ShortName(L"\\Users\\bob\\AppData\\Local\\Google\\Chrome\\USERDA~1\\Default") == TRUE);
    CHECK(ShortName(L"\\Users\\bob\\AppData\\Local\\GOOGLE~1\\Chrome") == TRUE);
    CHECK(ShortName(L"\\Users\\bob\\Documents\\~$report.docx") == FALSE);
    CHECK(ShortName(L"\\Users\\bob\\notes~") == FALSE);
    CHECK(BrucePolicyMayHaveShortName(NULL, 0) == FALSE);
}

static void TestFragmentRules(void)
{
    CHECK(Send(&g_staged, BruceClearPolicy, 0, NULL) == BruceApplyOk);
    // Bare words matched every file that merely contained them; only directory fragments go in.
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"login data") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\exodus") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"exodus\\") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\\\\\\\") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\a\\") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\\\a\\") == BruceApplyInvalid);   // one named character
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\a\\\\") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"") == BruceApplyInvalid);
    CHECK(g_staged.PrefixCount == 0);
    // The shortest fragments: two named characters, together or apart.
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\ab\\") == BruceApplyOk);
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\a\\b\\") == BruceApplyOk);
    CHECK(g_staged.PrefixCount == 2);
    CHECK(Send(&g_staged, BruceClearPolicy, 0, NULL) == BruceApplyOk);
    // Duplicates (any case) are accepted once.
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\exodus\\") == BruceApplyOk);
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\EXODUS\\") == BruceApplyOk);
    CHECK(g_staged.PrefixCount == 1);
    // A field with no terminator was cut short by the sender: refused, never truncated.
    {
        BRUCE_MESSAGE message;
        ZeroMemory(&message, sizeof(message));
        message.Command = BruceAddSensitivePath;
        message.Path[0] = L'\\';
        for (int i = 1; i < BRUCE_MAX_PATH - 1; i++) message.Path[i] = L'a';
        message.Path[BRUCE_MAX_PATH - 1] = L'\\';
        CHECK(BrucePolicyApply(&g_staged, &message) == BruceApplyInvalid);
        message.Path[BRUCE_MAX_PATH - 1] = L'\0';
        message.Path[BRUCE_MAX_PATH - 2] = L'\\';
        CHECK(BrucePolicyApply(&g_staged, &message) == BruceApplyOk);   // 259 characters fit
    }
    // The table fills, then refuses.
    CHECK(Send(&g_staged, BruceClearPolicy, 0, NULL) == BruceApplyOk);
    for (int i = 0; i < BRUCE_MAX_ENTRIES; i++)
    {
        WCHAR fragment[32];
        swprintf_s(fragment, 32, L"\\dir%02d\\", i);
        CHECK(Send(&g_staged, BruceAddSensitivePath, 0, fragment) == BruceApplyOk);
    }
    CHECK(Send(&g_staged, BruceAddSensitivePath, 0, L"\\one more\\") == BruceApplyFull);
    CHECK(g_staged.PrefixCount == BRUCE_MAX_ENTRIES);
    CHECK(Send(&g_staged, 99, 0, L"\\x\\") == BruceApplyUnknown);
}

static void TestTrust(void)
{
    const WCHAR* chrome = L"\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    const WCHAR* firefox = L"\\Device\\HarddiskVolume3\\Program Files\\Mozilla Firefox\\firefox.exe";
    const WCHAR* backup = L"\\Device\\HarddiskVolume3\\Program Files\\Backup\\agent.exe";

    Seed(&g_staged);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 0, chrome) == BruceApplyOk);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 1, firefox) == BruceApplyOk);
    CHECK(Send(&g_staged, BruceAddTrustedImage, BRUCE_ANY_PREFIX, backup) == BruceApplyOk);
    // Scoped: Chrome is trusted for Chrome's store and nothing else.
    CHECK(Trusted(&g_staged, 0, chrome) == TRUE);
    CHECK(Trusted(&g_staged, 1, chrome) == FALSE);
    CHECK(Trusted(&g_staged, 1, firefox) == TRUE);
    CHECK(Trusted(&g_staged, 2, firefox) == FALSE);
    CHECK(Trusted(&g_staged, 2, backup) == TRUE);
    // An unresolved name (BRUCE_ANY_PREFIX) is trusted only by an image trusted everywhere.
    CHECK(Trusted(&g_staged, BRUCE_ANY_PREFIX, chrome) == FALSE);
    CHECK(Trusted(&g_staged, BRUCE_ANY_PREFIX, backup) == TRUE);
    // Exact path, any case; a copy elsewhere, a prefix or a suffix is not the trusted image.
    CHECK(Trusted(&g_staged, 0, L"\\DEVICE\\HARDDISKVOLUME3\\PROGRAM FILES\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE") == TRUE);
    CHECK(Trusted(&g_staged, 0, L"\\Device\\HarddiskVolume3\\Users\\bob\\AppData\\Local\\Temp\\chrome.exe") == FALSE);
    CHECK(Trusted(&g_staged, 0, L"\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe.bak") == FALSE);
    CHECK(Trusted(&g_staged, 0, L"\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.ex") == FALSE);
    // Same length, one character apart: the last one, or another volume.
    CHECK(Trusted(&g_staged, 0, L"\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exf") == FALSE);
    CHECK(Trusted(&g_staged, 0, L"\\Device\\HarddiskVolume4\\Program Files\\Google\\Chrome\\Application\\chrome.exe") == FALSE);
    CHECK(Trusted(&g_staged, 0, L"") == FALSE);
    CHECK(BrucePolicyIsTrusted(&g_staged, 0, NULL, 0) == FALSE);
    // Entries must be NT image paths for a fragment that exists.
    CHECK(Send(&g_staged, BruceAddTrustedImage, 0, L"C:\\Program Files\\x.exe") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 0, L"\\Device\\") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 0, L"\\Device\\HarddiskVolume3\\Program Files\\") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 0, L"\\Device\\HarddiskVolume3\\Program Files\\..\\Temp\\x.exe") == BruceApplyInvalid);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 7, chrome) == BruceApplyInvalid);
    CHECK(g_staged.TrustedCount == 3);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 0, chrome) == BruceApplyOk);   // duplicate, once
    CHECK(g_staged.TrustedCount == 3);
}

static void TestCommit(void)
{
    Seed(&g_staged);
    ZeroMemory(&g_live, sizeof(g_live));
    g_live.Blocking = TRUE;
    BrucePolicyCommit(&g_live, &g_staged);
    // The policy swaps in whole; the live blocking flag is untouched.
    CHECK(g_live.Blocking == TRUE);
    CHECK(g_live.PrefixCount == 3);
    CHECK(Match(&g_live, L"\\x\\Exodus\\y") == 2);
    // Clearing the staged copy leaves the live one alone until the next commit.
    CHECK(Send(&g_staged, BruceClearPolicy, 0, NULL) == BruceApplyOk);
    CHECK(g_live.PrefixCount == 3);
}

static void TestLinkBuffer(void)
{
    BYTE buffer[64];
    BRUCE_LINK_INFO* info = (BRUCE_LINK_INFO*)buffer;
    HANDLE root;
    const WCHAR* name;
    ULONG bytes;
    const ULONG header = (ULONG)FIELD_OFFSET(BRUCE_LINK_INFO, FileName);

    ZeroMemory(buffer, sizeof(buffer));
    info->RootDirectory = (HANDLE)(ULONG_PTR)0x40;
    info->FileNameLength = 8;
    memcpy(info->FileName, L"abcd", 8);
    CHECK(BrucePolicyReadLinkTarget(buffer, header + 8, &root, &name, &bytes) == TRUE);
    CHECK(root == (HANDLE)(ULONG_PTR)0x40 && bytes == 8 && name == info->FileName);
    // A name longer than the buffer that carries it.
    CHECK(BrucePolicyReadLinkTarget(buffer, header + 6, &root, &name, &bytes) == FALSE);
    CHECK(name == NULL && bytes == 0 && root == NULL);
    info->FileNameLength = 0xFFFFFFF0;   // would wrap a naive header + length sum
    CHECK(BrucePolicyReadLinkTarget(buffer, sizeof(buffer), &root, &name, &bytes) == FALSE);
    info->FileNameLength = 7;            // half a character
    CHECK(BrucePolicyReadLinkTarget(buffer, sizeof(buffer), &root, &name, &bytes) == FALSE);
    info->FileNameLength = 0;
    CHECK(BrucePolicyReadLinkTarget(buffer, sizeof(buffer), &root, &name, &bytes) == FALSE);
    // Too short for the header, or for any name after it, however sound the length field.
    info->FileNameLength = 2;
    CHECK(BrucePolicyReadLinkTarget(buffer, header - 1, &root, &name, &bytes) == FALSE);
    CHECK(BrucePolicyReadLinkTarget(buffer, header, &root, &name, &bytes) == FALSE);
    CHECK(BrucePolicyReadLinkTarget(buffer, header + 2, &root, &name, &bytes) == TRUE);
    CHECK(BrucePolicyReadLinkTarget(NULL, 0, &root, &name, &bytes) == FALSE);
}

static void TestMidPathStreams(void)
{
    Seed(&g_live);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus::$INDEX_ALLOCATION\\exodus.wallet\\seed.seco") == 2);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus:$I30:$INDEX_ALLOCATION\\exodus.wallet\\seed.seco") == 2);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus:$I30:$INDEX_ALLOCATION\\") == 2);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Local\\Google\\Chrome::$INDEX_ALLOCATION\\User Data::$INDEX_ALLOCATION\\Default\\Login Data") == 0);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Local\\Google::$INDEX_ALLOCATION\\Chrome\\User Data\\Default\\Login Data") == 0);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Google\\Chrome:$I30:$INDEX_ALLOCATION\\") == 0);
    CHECK(Ancestor(&g_live, L"\\Users\\bob\\AppData\\Local\\Google::$INDEX_ALLOCATION\\Chrome") == 0);
    CHECK(Match(&g_live, L"\\Users\\bob\\AppData\\Roaming\\Exodus2::$INDEX_ALLOCATION\\x") == BRUCE_NO_MATCH);
    CHECK(Match(&g_live, L"\\Users\\bob\\Documents\\notes.txt:Exodus\\x") == BRUCE_NO_MATCH);
}

// The rights the process guard removes are the SDK's own, spelled out in the policy header.
// Compile-time checks, like the wire layout above.
C_ASSERT(BRUCE_PROCESS_CREATE_THREAD == PROCESS_CREATE_THREAD);
C_ASSERT(BRUCE_PROCESS_VM_OPERATION == PROCESS_VM_OPERATION);
C_ASSERT(BRUCE_PROCESS_VM_WRITE == PROCESS_VM_WRITE);
C_ASSERT(BRUCE_PROCESS_DUP_HANDLE == PROCESS_DUP_HANDLE);
C_ASSERT(BRUCE_PROCESS_CREATE_PROCESS == PROCESS_CREATE_PROCESS);
C_ASSERT(BRUCE_PROCESS_SET_INFORMATION == PROCESS_SET_INFORMATION);
C_ASSERT(BRUCE_PROCESS_SUSPEND_RESUME == PROCESS_SUSPEND_RESUME);
C_ASSERT(BRUCE_THREAD_SUSPEND_RESUME == THREAD_SUSPEND_RESUME);
C_ASSERT(BRUCE_THREAD_SET_CONTEXT == THREAD_SET_CONTEXT);
C_ASSERT(BRUCE_THREAD_SET_INFORMATION == THREAD_SET_INFORMATION);
C_ASSERT(BRUCE_THREAD_DIRECT_IMPERSONATION == THREAD_DIRECT_IMPERSONATION);
C_ASSERT(BRUCE_ACCESS_GENERIC_ALL == GENERIC_ALL);
C_ASSERT(BRUCE_ACCESS_GENERIC_WRITE == GENERIC_WRITE);
C_ASSERT(BRUCE_ACCESS_MAXIMUM_ALLOWED == MAXIMUM_ALLOWED);
C_ASSERT(BRUCE_ACCESS_ALL == PROCESS_ALL_ACCESS);
C_ASSERT(BRUCE_ACCESS_ALL == THREAD_ALL_ACCESS);
// What stays: terminate, memory reads, queries, quota, waiting, the thread's context read.
C_ASSERT((BRUCE_PROCESS_STRIP & (PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SET_LIMITED_INFORMATION | SYNCHRONIZE | READ_CONTROL)) == 0);
C_ASSERT((BRUCE_THREAD_STRIP & (THREAD_TERMINATE | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |
    THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION | SYNCHRONIZE | READ_CONTROL)) == 0);
C_ASSERT(BRUCE_PROCESS_STRIP == 0x0AEA);
C_ASSERT(BRUCE_THREAD_STRIP == 0x0232);

static void TestTrustMask(void)
{
    const WCHAR* chrome = L"\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    const WCHAR* firefox = L"\\Device\\HarddiskVolume3\\Program Files\\Mozilla Firefox\\firefox.exe";
    const WCHAR* backup = L"\\Device\\HarddiskVolume3\\Program Files\\Backup\\agent.exe";
    const WCHAR* both = L"\\Device\\HarddiskVolume3\\Program Files\\Both\\both.exe";

    Seed(&g_staged);   // three fragments: bits 0, 1, 2
    CHECK(Send(&g_staged, BruceAddTrustedImage, 0, chrome) == BruceApplyOk);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 1, firefox) == BruceApplyOk);
    CHECK(Send(&g_staged, BruceAddTrustedImage, BRUCE_ANY_PREFIX, backup) == BruceApplyOk);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 0, both) == BruceApplyOk);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 2, both) == BruceApplyOk);
    CHECK(BrucePolicyTrustMask(&g_staged, chrome, wcslen(chrome)) == 0x1);
    CHECK(BrucePolicyTrustMask(&g_staged, firefox, wcslen(firefox)) == 0x2);
    // Trusted for every store: every fragment of the policy, and no bit past them.
    CHECK(BrucePolicyTrustMask(&g_staged, backup, wcslen(backup)) == 0x7);
    // Two entries for one image add up.
    CHECK(BrucePolicyTrustMask(&g_staged, both, wcslen(both)) == 0x5);
    // Any case, nothing else: another file, a prefix, empty, null.
    CHECK(BrucePolicyTrustMask(&g_staged, L"\\DEVICE\\HARDDISKVOLUME3\\PROGRAM FILES\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE",
        wcslen(chrome)) == 0x1);
    CHECK(BrucePolicyTrustMask(&g_staged, L"\\Device\\HarddiskVolume3\\Users\\bob\\chrome.exe",
        wcslen(L"\\Device\\HarddiskVolume3\\Users\\bob\\chrome.exe")) == 0);
    CHECK(BrucePolicyTrustMask(&g_staged, chrome, wcslen(chrome) - 1) == 0);
    CHECK(BrucePolicyTrustMask(&g_staged, chrome, 0) == 0);
    CHECK(BrucePolicyTrustMask(&g_staged, NULL, 0) == 0);
    // An entry scoped to a fragment the policy does not have (the staging rules never make one)
    // trusts the image for nothing.
    g_staged.TrustedPrefix[0] = 40;
    CHECK(BrucePolicyTrustMask(&g_staged, chrome, wcslen(chrome)) == 0);
    // A full table of fragments: the any-store mask is all 64 bits, not a wrapped shift.
    CHECK(Send(&g_staged, BruceClearPolicy, 0, NULL) == BruceApplyOk);
    for (int i = 0; i < BRUCE_MAX_ENTRIES; i++)
    {
        WCHAR fragment[32];
        swprintf_s(fragment, 32, L"\\dir%02d\\", i);
        CHECK(Send(&g_staged, BruceAddSensitivePath, 0, fragment) == BruceApplyOk);
    }
    CHECK(Send(&g_staged, BruceAddTrustedImage, BRUCE_ANY_PREFIX, backup) == BruceApplyOk);
    CHECK(Send(&g_staged, BruceAddTrustedImage, 63, chrome) == BruceApplyOk);
    CHECK(BrucePolicyTrustMask(&g_staged, backup, wcslen(backup)) == ~0ull);
    CHECK(BrucePolicyTrustMask(&g_staged, chrome, wcslen(chrome)) == (1ull << 63));
    // No fragments: trusted for every store of nothing.
    CHECK(Send(&g_staged, BruceClearPolicy, 0, NULL) == BruceApplyOk);
    CHECK(BrucePolicyTrustMask(&g_staged, backup, wcslen(backup)) == 0);
}

static ACCESS_MASK Guard(BOOLEAN thread, ULONGLONG target, ULONGLONG receiver, ACCESS_MASK desired)
{
    BRUCE_HANDLE_REQUEST request;
    ZeroMemory(&request, sizeof(request));
    request.IsThread = thread;
    request.TargetTrust = target;
    request.ReceiverTrust = receiver;
    request.Desired = desired;
    return BruceGuardAccess(&request);
}

static void TestGuardAccess(void)
{
    const ACCESS_MASK all = PROCESS_ALL_ACCESS;
    const ACCESS_MASK keptProcess = PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | SYNCHRONIZE;
    BRUCE_HANDLE_REQUEST request;

    // An untrusted process asking for everything gets what the strip mask leaves.
    CHECK(Guard(FALSE, 0x1, 0, all) == (all & ~BRUCE_PROCESS_STRIP));
    CHECK((Guard(FALSE, 0x1, 0, all) & keptProcess) == keptProcess);
    CHECK((Guard(FALSE, 0x1, 0, all) & BRUCE_PROCESS_STRIP) == 0);
    // Each stripped right alone, and each kept one alone.
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_VM_WRITE) == 0);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_VM_OPERATION) == 0);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_CREATE_THREAD) == 0);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_DUP_HANDLE) == 0);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_CREATE_PROCESS) == 0);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_SET_INFORMATION) == 0);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_SUSPEND_RESUME) == 0);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_TERMINATE) == PROCESS_TERMINATE);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_VM_READ) == PROCESS_VM_READ);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_QUERY_LIMITED_INFORMATION) == PROCESS_QUERY_LIMITED_INFORMATION);
    CHECK(Guard(FALSE, 0x1, 0, PROCESS_VM_READ | PROCESS_VM_WRITE) == PROCESS_VM_READ);
    // Threads: the context write, suspend, set information and impersonation go; the rest stays.
    CHECK(Guard(TRUE, 0x1, 0, THREAD_ALL_ACCESS) == (THREAD_ALL_ACCESS & ~BRUCE_THREAD_STRIP));
    CHECK(Guard(TRUE, 0x1, 0, THREAD_SET_CONTEXT) == 0);
    CHECK(Guard(TRUE, 0x1, 0, THREAD_SUSPEND_RESUME) == 0);
    CHECK(Guard(TRUE, 0x1, 0, THREAD_SET_INFORMATION) == 0);
    CHECK(Guard(TRUE, 0x1, 0, THREAD_DIRECT_IMPERSONATION) == 0);
    CHECK(Guard(TRUE, 0x1, 0, THREAD_GET_CONTEXT) == THREAD_GET_CONTEXT);
    CHECK(Guard(TRUE, 0x1, 0, THREAD_TERMINATE) == THREAD_TERMINATE);
    CHECK(Guard(TRUE, 0x1, 0, THREAD_QUERY_LIMITED_INFORMATION) == THREAD_QUERY_LIMITED_INFORMATION);
    // A bit means different things on a process and a thread: each object uses its own mask.
    CHECK(Guard(FALSE, 0x1, 0, THREAD_SET_CONTEXT) == THREAD_SET_CONTEXT);   // 0x10 is PROCESS_VM_READ
    CHECK(Guard(TRUE, 0x1, 0, PROCESS_VM_READ) == 0);                        // 0x10 is THREAD_SET_CONTEXT
    // The target is not protected: nothing is touched.
    CHECK(Guard(FALSE, 0, 0, all) == all);
    CHECK(Guard(TRUE, 0, 0, THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS);
    // The receiver is trusted for every store the target is trusted for: Chrome and its renderers.
    CHECK(Guard(FALSE, 0x1, 0x1, all) == all);
    CHECK(Guard(FALSE, 0x1, 0x3, all) == all);               // more than enough
    CHECK(Guard(FALSE, 0x1, ~0ull, all) == all);             // trusted for every store
    CHECK(Guard(TRUE, 0x1, 0x1, THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS);
    // Trusted for another store only, or for some of the target's: not the same stores.
    CHECK(Guard(FALSE, 0x1, 0x2, all) == (all & ~BRUCE_PROCESS_STRIP));
    CHECK(Guard(FALSE, 0x5, 0x1, all) == (all & ~BRUCE_PROCESS_STRIP));
    CHECK(Guard(FALSE, 0x5, 0x4, all) == (all & ~BRUCE_PROCESS_STRIP));
    CHECK(Guard(FALSE, 0x5, 0x5, all) == all);
    CHECK(Guard(FALSE, 1ull << 63, 1ull << 62, all) == (all & ~BRUCE_PROCESS_STRIP));
    CHECK(Guard(FALSE, 1ull << 63, 1ull << 63, all) == all);
    // The target's own process, kernel handles and exempt receivers keep what they asked for.
    ZeroMemory(&request, sizeof(request));
    request.TargetTrust = 0x1;
    request.Desired = all;
    request.SameProcess = TRUE;
    CHECK(BruceGuardAccess(&request) == all);
    request.SameProcess = FALSE;
    request.KernelHandle = TRUE;
    CHECK(BruceGuardAccess(&request) == all);
    request.KernelHandle = FALSE;
    request.ReceiverExempt = TRUE;
    CHECK(BruceGuardAccess(&request) == all);
    request.ReceiverExempt = FALSE;
    CHECK(BruceGuardAccess(&request) == (all & ~BRUCE_PROCESS_STRIP));
    // A request that names no right is not left to be resolved afterwards.
    CHECK(Guard(FALSE, 0x1, 0, MAXIMUM_ALLOWED) == (PROCESS_ALL_ACCESS & ~BRUCE_PROCESS_STRIP));
    CHECK(Guard(FALSE, 0x1, 0, GENERIC_ALL) == (PROCESS_ALL_ACCESS & ~BRUCE_PROCESS_STRIP));
    CHECK(Guard(TRUE, 0x1, 0, MAXIMUM_ALLOWED | SYNCHRONIZE) == (THREAD_ALL_ACCESS & ~BRUCE_THREAD_STRIP));
    CHECK(Guard(FALSE, 0x1, 0, GENERIC_WRITE) == 0);
    CHECK(Guard(FALSE, 0x1, 0, GENERIC_READ) == GENERIC_READ);
    CHECK(Guard(FALSE, 0x1, 0x1, MAXIMUM_ALLOWED) == MAXIMUM_ALLOWED);
    CHECK(Guard(FALSE, 0, 0, MAXIMUM_ALLOWED) == MAXIMUM_ALLOWED);
    // The early exit agrees: only a request holding a stripped right or a wildcard needs a lookup.
    CHECK(BruceGuardCares(FALSE, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE) == FALSE);
    CHECK(BruceGuardCares(FALSE, PROCESS_VM_WRITE) == TRUE);
    CHECK(BruceGuardCares(FALSE, MAXIMUM_ALLOWED) == TRUE);
    CHECK(BruceGuardCares(FALSE, GENERIC_ALL) == TRUE);
    CHECK(BruceGuardCares(FALSE, GENERIC_WRITE) == TRUE);
    CHECK(BruceGuardCares(TRUE, THREAD_QUERY_LIMITED_INFORMATION | THREAD_GET_CONTEXT) == FALSE);
    CHECK(BruceGuardCares(TRUE, THREAD_SET_CONTEXT) == TRUE);
    CHECK(BruceGuardCares(FALSE, 0) == FALSE);
}

int main(void)
{
    TestMatching();
    TestAncestors();
    TestShortNames();
    TestFragmentRules();
    TestTrust();
    TestCommit();
    TestLinkBuffer();
    TestMidPathStreams();
    TestTrustMask();
    TestGuardAccess();
    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

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
    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

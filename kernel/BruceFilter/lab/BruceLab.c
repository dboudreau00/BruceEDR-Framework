//
// BruceLab: exercises the BruceFilter minifilter end to end in a test VM.
//
//   BruceLab.exe run <work> <trusted-copy> <untrusted-copy> [--report <file>] [--dry-run]
//   BruceLab.exe status [--report <file>]   the driver's protocol, live policy size and counters
//   BruceLab.exe reset [--report <file>]    empty policy, blocking off (after an interrupted run)
//   BruceLab.exe probe <op> <args...>   one file operation; the exit code is its Win32 error
//
// "run" must start as SYSTEM (the port admits SYSTEM only) from <trusted-copy>, a copy of this
// program the lab policy trusts: the harness sets the lab tree up and repairs it as that
// trusted program. It replaces the driver's live policy with one lab store,
// \brucelab\secret store\, then runs each scenario as a probe child of one copy or the other
// and checks both the outcome and the refusal report the driver sends. --dry-run never
// touches the driver and expects every operation to succeed: it checks the lab itself on a
// machine without BruceFilter. lab.ps1 drives all of this.
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fltUser.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#include "..\BruceFilter.h"

#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "advapi32.lib")

#define LAB_PATH       1024
#define LAB_MAX_NOTES  512
#define LAB_FRAGMENT   L"\\brucelab\\secret store\\"
#define EXIT_LAB_FAIL  1
#define EXIT_LAB_SETUP 2

// ------------------------------------------------------------------ output

static FILE* gReport;

static void Out(_Printf_format_string_ const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    vfwprintf(stdout, format, args);
    va_end(args);
    if (gReport != NULL)
    {
        va_start(args, format);
        vfwprintf(gReport, format, args);
        va_end(args);
        fflush(gReport);
    }
    fflush(stdout);
}

// ------------------------------------------------------------------ probe mode

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

// reparsePoint: open the junction or symlink itself instead of what it points at.
static DWORD ProbeOpen(_In_z_ const wchar_t* path, BOOL read, BOOL reparsePoint)
{
    DWORD error = ERROR_SUCCESS;
    HANDLE h = CreateFileW(path, GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | (reparsePoint ? FILE_FLAG_OPEN_REPARSE_POINT : 0), NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    if (read)
    {
        char buffer[16];
        DWORD n = 0;
        if (!ReadFile(h, buffer, sizeof(buffer), &n, NULL)) error = GetLastError();
    }
    CloseHandle(h);
    return error;
}

static DWORD ProbeList(_In_z_ const wchar_t* dir)
{
    wchar_t pattern[LAB_PATH];
    WIN32_FIND_DATAW found;
    HANDLE find;
    if (swprintf_s(pattern, LAB_PATH, L"%ls\\*", dir) < 0) return ERROR_BUFFER_OVERFLOW;
    find = FindFirstFileW(pattern, &found);
    if (find == INVALID_HANDLE_VALUE) return GetLastError();
    FindClose(find);
    return ERROR_SUCCESS;
}

static DWORD ProbeOpenById(_In_z_ const wchar_t* volumeHint, _In_z_ const wchar_t* idText)
{
    FILE_ID_DESCRIPTOR id;
    DWORD error = ERROR_SUCCESS;
    HANDLE file;
    HANDLE hint = CreateFileW(volumeHint, FILE_READ_ATTRIBUTES, SHARE_ALL, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hint == INVALID_HANDLE_VALUE) return GetLastError();
    ZeroMemory(&id, sizeof(id));
    id.dwSize = sizeof(id);
    id.Type = FileIdType;
    id.FileId.QuadPart = (LONGLONG)_wcstoui64(idText, NULL, 16);
    file = OpenFileById(hint, &id, GENERIC_READ, SHARE_ALL, NULL, FILE_FLAG_BACKUP_SEMANTICS);
    if (file == INVALID_HANDLE_VALUE) error = GetLastError();
    else CloseHandle(file);
    CloseHandle(hint);
    return error;
}

// Sets (or, with an empty name, removes) the short name of a file or folder: DELETE and backup
// semantics are all it takes since Windows 10 1903.
static DWORD SetShortName(_In_z_ const wchar_t* path, _In_z_ const wchar_t* name)
{
    DWORD error = ERROR_SUCCESS;
    HANDLE h = CreateFileW(path, DELETE, SHARE_ALL, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    if (!SetFileShortNameW(h, name)) error = GetLastError();
    CloseHandle(h);
    return error;
}

// ------------------------------------------------------------------ process probes

// Starts `<exe> probe hold <seconds>`: a copy of this program to be reached into.
static BOOL StartCopy(_In_z_ const wchar_t* exe, _In_z_ const wchar_t* seconds, BOOL suspended, _Out_ PROCESS_INFORMATION* pi)
{
    wchar_t command[LAB_PATH + 64];
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(pi, sizeof(*pi));
    swprintf_s(command, _countof(command), L"\"%ls\" probe hold %ls", exe, seconds);
    return CreateProcessW(exe, command, NULL, NULL, FALSE, CREATE_NO_WINDOW | (suspended ? CREATE_SUSPENDED : 0),
        NULL, NULL, &si, pi);
}

// The first step of an injection: a page in the other process, and one byte written to it.
static DWORD WriteInto(HANDLE process)
{
    static const char byte = 'x';
    DWORD error = ERROR_SUCCESS;
    void* page = VirtualAllocEx(process, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) return GetLastError();
    if (!WriteProcessMemory(process, page, &byte, 1, NULL)) error = GetLastError();
    VirtualFreeEx(process, page, 0, MEM_RELEASE);
    return error;
}

// `spawn <exe>`: CreateProcess of another copy, as Explorer or Task Scheduler starts a program.
static DWORD Spawn(_In_z_ const wchar_t* exe)
{
    PROCESS_INFORMATION pi;
    DWORD code = ERROR_SUCCESS;
    if (!StartCopy(exe, L"0", FALSE, &pi)) return GetLastError();
    if (WaitForSingleObject(pi.hProcess, 10000) != WAIT_OBJECT_0 || !GetExitCodeProcess(pi.hProcess, &code))
    {
        TerminateProcess(pi.hProcess, 0);
        code = ERROR_TIMEOUT;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

// `spawnwrite <exe>`: start a copy suspended, write into it and resume it, as an injector does
// with a program it starts itself.
static DWORD SpawnWrite(_In_z_ const wchar_t* exe)
{
    PROCESS_INFORMATION pi;
    DWORD error;
    if (!StartCopy(exe, L"30", TRUE, &pi)) return GetLastError();
    error = WriteInto(pi.hProcess);
    if (error == ERROR_SUCCESS && ResumeThread(pi.hThread) == (DWORD)-1) error = GetLastError();
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return error;
}

// `vmwrite <pid>`: open a running process for writing and write into it.
static DWORD VmWrite(_In_z_ const wchar_t* pidText)
{
    DWORD error;
    HANDLE h = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, wcstoul(pidText, NULL, 10));
    if (h == NULL) return GetLastError();
    error = WriteInto(h);
    CloseHandle(h);
    return error;
}

// `dup <pid>`: open a running process to copy its handles, and copy one. Without
// PROCESS_DUP_HANDLE the call fails before it looks at the handle value.
static DWORD DupFrom(_In_z_ const wchar_t* pidText)
{
    DWORD error = ERROR_SUCCESS;
    HANDLE copy = NULL;
    HANDLE h = OpenProcess(PROCESS_DUP_HANDLE, FALSE, wcstoul(pidText, NULL, 10));
    if (h == NULL) return GetLastError();
    if (!DuplicateHandle(h, (HANDLE)(ULONG_PTR)4, GetCurrentProcess(), &copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
        error = GetLastError();
    if (copy != NULL) CloseHandle(copy);
    CloseHandle(h);
    return error;
}

// `suspend <tid>`: open a thread to suspend it and set its context (a hijack), and suspend it.
static DWORD SuspendIt(_In_z_ const wchar_t* tidText)
{
    DWORD error = ERROR_SUCCESS;
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT, FALSE, wcstoul(tidText, NULL, 10));
    if (h == NULL) return GetLastError();
    if (SuspendThread(h) == (DWORD)-1) error = GetLastError();
    else ResumeThread(h);
    CloseHandle(h);
    return error;
}

static int Probe(int argc, _In_reads_(argc) wchar_t** argv)
{
    const wchar_t* op;
    DWORD error;
    if (argc < 4) return ERROR_INVALID_PARAMETER;
    op = argv[2];
    if (wcscmp(op, L"open") == 0) error = ProbeOpen(argv[3], FALSE, FALSE);
    else if (wcscmp(op, L"openrp") == 0) error = ProbeOpen(argv[3], FALSE, TRUE);
    else if (wcscmp(op, L"read") == 0) error = ProbeOpen(argv[3], TRUE, FALSE);
    else if (wcscmp(op, L"list") == 0) error = ProbeList(argv[3]);
    else if (wcscmp(op, L"delete") == 0) error = DeleteFileW(argv[3]) ? ERROR_SUCCESS : GetLastError();
    else if (wcscmp(op, L"hold") == 0) { Sleep(wcstoul(argv[3], NULL, 10) * 1000); error = ERROR_SUCCESS; }
    else if (wcscmp(op, L"spawn") == 0) error = Spawn(argv[3]);
    else if (wcscmp(op, L"spawnwrite") == 0) error = SpawnWrite(argv[3]);
    else if (wcscmp(op, L"vmwrite") == 0) error = VmWrite(argv[3]);
    else if (wcscmp(op, L"dup") == 0) error = DupFrom(argv[3]);
    else if (wcscmp(op, L"suspend") == 0) error = SuspendIt(argv[3]);
    else if (argc < 5) error = ERROR_INVALID_PARAMETER;
    else if (wcscmp(op, L"openid") == 0) error = ProbeOpenById(argv[3], argv[4]);
    else if (wcscmp(op, L"rename") == 0) error = MoveFileExW(argv[3], argv[4], 0) ? ERROR_SUCCESS : GetLastError();
    else if (wcscmp(op, L"link") == 0) error = CreateHardLinkW(argv[3], argv[4], NULL) ? ERROR_SUCCESS : GetLastError();
    else if (wcscmp(op, L"copy") == 0) error = CopyFileW(argv[3], argv[4], TRUE) ? ERROR_SUCCESS : GetLastError();
    else if (wcscmp(op, L"shortname") == 0) error = SetShortName(argv[3], argv[4]);
    else error = ERROR_INVALID_FUNCTION;
    return (int)error;
}

// ------------------------------------------------------------------ driver port

static HANDLE gPort = INVALID_HANDLE_VALUE;

static HRESULT Send(UINT32 command, UINT32 flag, _In_opt_z_ const wchar_t* path,
    _Out_writes_bytes_opt_(replySize) void* reply, DWORD replySize, _Out_opt_ DWORD* replied)
{
    BRUCE_MESSAGE message;
    DWORD got = 0;
    HRESULT hr;
    if (replied != NULL) *replied = 0;
    ZeroMemory(&message, sizeof(message));
    message.Command = command;
    message.Flag = flag;
    if (path != NULL && wcscpy_s(message.Path, BRUCE_MAX_PATH, path) != 0) return E_INVALIDARG;
    hr = FilterSendMessage(gPort, &message, sizeof(message), reply, replySize, &got);
    if (replied != NULL) *replied = got;
    return hr;
}

static BOOL QueryStatus(_Out_ BRUCE_STATUS* status)
{
    DWORD got = 0;
    ZeroMemory(status, sizeof(*status));
    return SUCCEEDED(Send(BruceQueryStatus, 0, NULL, status, sizeof(*status), &got)) &&
           got >= sizeof(*status) && status->Version == BRUCE_PROTOCOL_VERSION;
}

static BOOL Connect(void)
{
    HRESULT hr = FilterConnectCommunicationPort(BRUCE_PORT_NAME, 0, NULL, 0, NULL, &gPort);
    if (SUCCEEDED(hr)) return TRUE;
    gPort = INVALID_HANDLE_VALUE;
    Out(L"cannot connect to %ls: 0x%08X%ls\n", BRUCE_PORT_NAME, (unsigned)hr,
        hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ? L" (BruceFilter is not loaded: fltmc load BruceFilter)" :
        hr == E_ACCESSDENIED ? L" (the port admits SYSTEM only; lab.ps1 runs this as SYSTEM)" :
        hr == HRESULT_FROM_WIN32(ERROR_CONNECTION_COUNT_LIMIT) ? L" (another client holds the port: stop the BruceEDR service)" : L"");
    return FALSE;
}

static void Disconnect(void)
{
    if (gPort != INVALID_HANDLE_VALUE) CloseHandle(gPort);
    gPort = INVALID_HANDLE_VALUE;
}

static void ShowStatus(_In_ const BRUCE_STATUS* s)
{
    Out(L"driver: protocol %u, blocking %ls, %u store(s), %u trusted image(s); denied %u, rechecked %u, reports dropped %u; process guard %ls\n",
        s->Version, s->Blocking ? L"ON" : L"off", s->PrefixCount, s->TrustedCount, s->Denied, s->Rechecked, s->NotifyDropped,
        (s->ProcessGuard & BRUCE_GUARD_ACTIVE) == 0 ? L"OFF" :
        (s->ProcessGuard & BRUCE_GUARD_ENUMERATED) != 0 ? L"on" : L"on (running programs not covered)");
}

static BOOL ResetDriver(void)
{
    return SUCCEEDED(Send(BruceSetBlocking, 0, NULL, NULL, 0, NULL)) &&
           SUCCEEDED(Send(BruceClearPolicy, 0, NULL, NULL, 0, NULL)) &&
           SUCCEEDED(Send(BruceCommitPolicy, 0, NULL, NULL, 0, NULL));
}

// ------------------------------------------------------------------ refusal reports

typedef struct _LAB_MESSAGE {
    FILTER_MESSAGE_HEADER Header;
    BRUCE_NOTIFICATION    Note;
} LAB_MESSAGE;

static CRITICAL_SECTION   gNotesLock;
static BRUCE_NOTIFICATION gNotes[LAB_MAX_NOTES];
static LONG               gNoteCount;
static HANDLE             gStopReader;

// Reads kept waiting at once. The driver drops a report that finds none, and with a single
// read the lab VMs lost up to a third of the reports in a scenario's burst.
#define LAB_READS 8

static BOOL PostRead(_Out_ LAB_MESSAGE* message, _Out_ OVERLAPPED* overlapped, _In_ HANDLE ready)
{
    HRESULT hr;
    ZeroMemory(message, sizeof(*message));
    ZeroMemory(overlapped, sizeof(*overlapped));
    overlapped->hEvent = ready;
    ResetEvent(ready);
    hr = FilterGetMessage(gPort, &message->Header, sizeof(*message), overlapped);
    return SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING);
}

static DWORD WINAPI Reader(_In_opt_ LPVOID unused)
{
    LAB_MESSAGE* messages = (LAB_MESSAGE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LAB_MESSAGE) * LAB_READS);
    OVERLAPPED overlapped[LAB_READS];
    HANDLE waits[LAB_READS + 1];
    BOOL pending[LAB_READS];
    BOOL running = TRUE;
    DWORD bytes = 0;
    int i;
    UNREFERENCED_PARAMETER(unused);

    if (messages == NULL) return 1;
    ZeroMemory(overlapped, sizeof(overlapped));
    ZeroMemory(pending, sizeof(pending));
    waits[0] = gStopReader;   // first, so a stop wins over a read that completed at the same time
    for (i = 0; i < LAB_READS; i++)
    {
        waits[i + 1] = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (waits[i + 1] == NULL) running = FALSE;
    }
    for (i = 0; i < LAB_READS && running; i++)
    {
        running = PostRead(&messages[i], &overlapped[i], waits[i + 1]);
        pending[i] = running;
    }
    while (running)
    {
        DWORD signalled = WaitForMultipleObjects(LAB_READS + 1, waits, FALSE, INFINITE);
        DWORD slot;
        if (signalled == WAIT_OBJECT_0 || signalled > WAIT_OBJECT_0 + LAB_READS) break;
        slot = signalled - WAIT_OBJECT_0 - 1;
        pending[slot] = FALSE;
        if (!GetOverlappedResult(gPort, &overlapped[slot], &bytes, FALSE)) break;
        EnterCriticalSection(&gNotesLock);
        if (gNoteCount < LAB_MAX_NOTES) gNotes[gNoteCount++] = messages[slot].Note;
        LeaveCriticalSection(&gNotesLock);
        running = PostRead(&messages[slot], &overlapped[slot], waits[slot + 1]);
        pending[slot] = running;
    }
    // The kernel may write into a buffer until its read is over: cancel each and wait it out.
    for (i = 0; i < LAB_READS; i++)
    {
        if (!pending[i]) continue;
        CancelIoEx(gPort, &overlapped[i]);
        GetOverlappedResult(gPort, &overlapped[i], &bytes, TRUE);   // returns once the cancel lands
    }
    for (i = 0; i < LAB_READS; i++)
        if (waits[i + 1] != NULL) CloseHandle(waits[i + 1]);
    HeapFree(GetProcessHeap(), 0, messages);
    return 0;
}

// The operations reported for one probe, as a bit mask (1 << BRUCE_OPERATION), waiting up to
// timeoutMs for the first report and a moment longer for the rest of its burst. anyPid takes
// reports from every process: a refusal made on behalf of a server (SMB) names the server's
// process, not the probe. *firstPid is the process of the first report found.
static UINT32 CollectNotes(DWORD pid, BOOL anyPid, DWORD timeoutMs, _Out_ DWORD* firstPid)
{
    ULONGLONG until = GetTickCount64() + timeoutMs;
    UINT32 mask = 0;
    BOOL settled = FALSE;
    *firstPid = 0;
    for (;;)
    {
        LONG i;
        mask = 0;
        EnterCriticalSection(&gNotesLock);
        for (i = 0; i < gNoteCount; i++)
        {
            if ((anyPid || gNotes[i].ProcessId == pid) && gNotes[i].Operation < 32)
            {
                if (mask == 0) *firstPid = gNotes[i].ProcessId;
                mask |= 1u << gNotes[i].Operation;
            }
        }
        LeaveCriticalSection(&gNotesLock);
        if (mask != 0 && settled) return mask;
        if (mask != 0) { settled = TRUE; Sleep(250); continue; }
        if (GetTickCount64() >= until) return 0;
        Sleep(50);
    }
}

// ------------------------------------------------------------------ the lab tree

typedef struct _LAB_TREE {
    wchar_t Data[LAB_PATH];            // <work>\data
    wchar_t Above[LAB_PATH];           // <work>\data\BruceLab          (begins the fragment)
    wchar_t Store[LAB_PATH];           // <work>\data\BruceLab\Secret Store
    wchar_t Secret[LAB_PATH];          //   ...\Secret Store\secret.txt
    wchar_t NearMiss[LAB_PATH];        // <work>\data\BruceLab\Secret Store2\near.txt
    wchar_t Outside[LAB_PATH];         // <work>\data\outside
    wchar_t Plain[LAB_PATH];           //   ...\outside\plain.txt
    wchar_t PreLinked[LAB_PATH];       //   ...\outside\prelinked.txt, hard link to secret.txt made before blocking
    wchar_t Junction[LAB_PATH];        //   ...\outside\jstore -> Secret Store
    wchar_t Symlink[LAB_PATH];         //   ...\outside\slink.txt -> secret.txt
    wchar_t DirSymlink[LAB_PATH];      //   ...\outside\sdir -> Secret Store (a directory symlink)
    wchar_t Alias[LAB_PATH];           //   ...\outside\Secret Store, a FILE named like the store
    wchar_t OverMatch[LAB_PATH];       //   ...\outside\BruceLab\Secret Store, a FILE the fragment matches by design
    wchar_t TrustedJunction[LAB_PATH]; //   ...\outside\tjunction -> the trusted copy's folder
    wchar_t TrustedViaJunction[LAB_PATH]; // the trusted copy, named through that junction
    wchar_t ShortSecret[LAB_PATH];     // secret.txt by its 8.3 path, if the volume makes 8.3 names
    wchar_t ShortStore[LAB_PATH];      // the store folder by its 8.3 path
    wchar_t VolumeRoot[LAB_PATH];      // C:\, the hint for an open by id
    wchar_t SmbSecret[LAB_PATH];       // secret.txt as \\localhost\C$\...
    wchar_t ShadowSecret[LAB_PATH];    // secret.txt inside a Volume Shadow Copy, once one exists
    wchar_t SecretId[32];              // file id of secret.txt, hex
    wchar_t NearId[32];                // file id of near.txt, hex
    wchar_t HeldPid[16];               // a trusted copy the harness keeps running, for the process guard
    wchar_t HeldTid[16];               //   and its first thread
    BOOL HasJunction, HasSymlink, HasDirSymlink, HasTrustedJunction, HasShortName, HasTraverseDeny, HasSmb, HasShadow, HasHeld;
} LAB_TREE;

static const char gSecretText[] = "lab secret: whoever reads this got past the guard\r\n";

static wchar_t gTrusted[LAB_PATH];
static wchar_t gUntrusted[LAB_PATH];
static wchar_t gShadowId[64];      // set while the harness holds a shadow copy it must delete
static wchar_t gShadowScriptPath[LAB_PATH];
static wchar_t gShadowOut[LAB_PATH];
static BOOL    gDryRun;

static BOOL WriteText(_In_z_ const wchar_t* path, _In_z_ const char* text)
{
    DWORD written = 0;
    BOOL ok;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile(h, text, (DWORD)strlen(text), &written, NULL);
    CloseHandle(h);
    return ok;
}

// Deletes a tree without ever following a junction or symlink out of it.
static void DeleteTree(_In_z_ const wchar_t* dir)
{
    wchar_t pattern[LAB_PATH], child[LAB_PATH];
    WIN32_FIND_DATAW found;
    HANDLE find;
    if (swprintf_s(pattern, LAB_PATH, L"%ls\\*", dir) < 0) return;
    find = FindFirstFileW(pattern, &found);
    if (find != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (wcscmp(found.cFileName, L".") == 0 || wcscmp(found.cFileName, L"..") == 0) continue;
            if (swprintf_s(child, LAB_PATH, L"%ls\\%ls", dir, found.cFileName) < 0) continue;
            if (found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            {
                if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(child);
                else DeleteFileW(child);
            }
            else if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                DeleteTree(child);
            }
            else
            {
                DeleteFileW(child);
            }
        } while (FindNextFileW(find, &found));
        FindClose(find);
    }
    RemoveDirectoryW(dir);
}

// This process's token without SeChangeNotifyPrivilege (bypass traverse checking), for a probe
// that must pass the traverse check itself. https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
static HANDLE TokenWithoutTraverse(void)
{
    HANDLE token = NULL, restricted = NULL;
    LUID_AND_ATTRIBUTES drop;
    ZeroMemory(&drop, sizeof(drop));
    if (!LookupPrivilegeValueW(NULL, SE_CHANGE_NOTIFY_NAME, &drop.Luid)) return NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &token)) return NULL;
    if (!CreateRestrictedToken(token, 0, 0, NULL, 1, &drop, 0, NULL, &restricted)) restricted = NULL;
    CloseHandle(token);
    return restricted;
}

static DWORD RunHidden(_Inout_z_ wchar_t* commandLine, DWORD timeoutMs, _Out_opt_ DWORD* pid, BOOL noTraverse)
{
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD code = ERROR_GEN_FAILURE;
    BOOL started;
    HANDLE token = NULL;
    if (pid != NULL) *pid = 0;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));
    if (noTraverse)
    {
        token = TokenWithoutTraverse();
        if (token == NULL) return GetLastError();
        started = CreateProcessAsUserW(token, NULL, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process);
        if (!started) code = GetLastError();
        CloseHandle(token);
        if (!started) return code;
    }
    else if (!CreateProcessW(NULL, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
    {
        return GetLastError();
    }
    if (pid != NULL) *pid = process.dwProcessId;
    if (WaitForSingleObject(process.hProcess, timeoutMs) != WAIT_OBJECT_0)
    {
        TerminateProcess(process.hProcess, WAIT_TIMEOUT);
        code = WAIT_TIMEOUT;
    }
    else if (!GetExitCodeProcess(process.hProcess, &code))
    {
        code = GetLastError();
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return code;
}

static BOOL Mklink(_In_z_ const wchar_t* option, _In_z_ const wchar_t* link, _In_z_ const wchar_t* target)
{
    wchar_t command[LAB_PATH * 3];
    if (swprintf_s(command, _countof(command), L"cmd.exe /c mklink %ls \"%ls\" \"%ls\" >nul 2>nul", option, link, target) < 0)
        return FALSE;
    return RunHidden(command, 15000, NULL, FALSE) == 0;
}

// Adds an ACE that denies Everyone FILE_TRAVERSE on this one directory (not inherited). A
// token with SeChangeNotifyPrivilege, which every ordinary token has, never gets the check.
static BOOL DenyTraverse(_In_z_ const wchar_t* dir)
{
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    PSID everyone = NULL;
    PACL oldAcl = NULL, newAcl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    EXPLICIT_ACCESSW access;
    BOOL ok = FALSE;

    if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone)) return FALSE;
    if (GetNamedSecurityInfoW(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &oldAcl, NULL, &descriptor) == ERROR_SUCCESS)
    {
        ZeroMemory(&access, sizeof(access));
        access.grfAccessPermissions = FILE_TRAVERSE;
        access.grfAccessMode = DENY_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        access.Trustee.ptstrName = (LPWSTR)everyone;
        if (SetEntriesInAclW(1, &access, oldAcl, &newAcl) == ERROR_SUCCESS)
        {
            ok = SetNamedSecurityInfoW((LPWSTR)dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, newAcl, NULL) == ERROR_SUCCESS;
            LocalFree(newAcl);
        }
        LocalFree(descriptor);
    }
    FreeSid(everyone);
    return ok;
}

static BOOL FileIdOf(_In_z_ const wchar_t* path, _Out_writes_(chars) wchar_t* text, size_t chars)
{
    BY_HANDLE_FILE_INFORMATION info;
    HANDLE h = CreateFileW(path, FILE_READ_ATTRIBUTES, SHARE_ALL, NULL, OPEN_EXISTING, 0, NULL);
    text[0] = L'\0';
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileInformationByHandle(h, &info))
    {
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);
    swprintf_s(text, chars, L"%I64x", ((ULONGLONG)info.nFileIndexHigh << 32) | info.nFileIndexLow);
    return TRUE;
}

// One argument, quoted for the child's command-line parser: a trailing backslash (C:\) would
// otherwise escape the closing quote.
static void Quote(_Out_writes_(chars) wchar_t* out, size_t chars, _In_z_ const wchar_t* arg)
{
    size_t n = wcslen(arg);
    BOOL trailing = n > 0 && arg[n - 1] == L'\\';
    if (swprintf_s(out, chars, trailing ? L"\"%ls\\\"" : L"\"%ls\"", arg) < 0) out[0] = L'\0';
}

static BOOL BuildTree(_In_z_ const wchar_t* work, _Out_ LAB_TREE* t)
{
    wchar_t sub[LAB_PATH], deep[LAB_PATH], nearDir[LAB_PATH], overDir[LAB_PATH], stream[LAB_PATH], trustedDir[LAB_PATH];
    wchar_t* slash;
    HANDLE h;
    BOOL ok = TRUE;

    ZeroMemory(t, sizeof(*t));
    ok &= swprintf_s(t->Data, LAB_PATH, L"%ls\\data", work) > 0;
    ok &= swprintf_s(t->Above, LAB_PATH, L"%ls\\BruceLab", t->Data) > 0;
    ok &= swprintf_s(t->Store, LAB_PATH, L"%ls\\Secret Store", t->Above) > 0;
    ok &= swprintf_s(t->Secret, LAB_PATH, L"%ls\\secret.txt", t->Store) > 0;
    ok &= swprintf_s(nearDir, LAB_PATH, L"%ls\\Secret Store2", t->Above) > 0;
    ok &= swprintf_s(t->NearMiss, LAB_PATH, L"%ls\\near.txt", nearDir) > 0;
    ok &= swprintf_s(t->Outside, LAB_PATH, L"%ls\\outside", t->Data) > 0;
    ok &= swprintf_s(t->Plain, LAB_PATH, L"%ls\\plain.txt", t->Outside) > 0;
    ok &= swprintf_s(t->PreLinked, LAB_PATH, L"%ls\\prelinked.txt", t->Outside) > 0;
    ok &= swprintf_s(t->Junction, LAB_PATH, L"%ls\\jstore", t->Outside) > 0;
    ok &= swprintf_s(t->Symlink, LAB_PATH, L"%ls\\slink.txt", t->Outside) > 0;
    ok &= swprintf_s(t->DirSymlink, LAB_PATH, L"%ls\\sdir", t->Outside) > 0;
    ok &= swprintf_s(t->Alias, LAB_PATH, L"%ls\\Secret Store", t->Outside) > 0;
    ok &= swprintf_s(overDir, LAB_PATH, L"%ls\\BruceLab", t->Outside) > 0;
    ok &= swprintf_s(t->OverMatch, LAB_PATH, L"%ls\\Secret Store", overDir) > 0;
    ok &= swprintf_s(t->TrustedJunction, LAB_PATH, L"%ls\\tjunction", t->Outside) > 0;
    ok &= swprintf_s(sub, LAB_PATH, L"%ls\\sub", t->Store) > 0;
    ok &= swprintf_s(deep, LAB_PATH, L"%ls\\deep.txt", sub) > 0;
    if (!ok) return FALSE;

    DeleteTree(t->Data);
    CreateDirectoryW(work, NULL);
    if (!CreateDirectoryW(t->Data, NULL) || !CreateDirectoryW(t->Above, NULL) || !CreateDirectoryW(t->Store, NULL) ||
        !CreateDirectoryW(sub, NULL) || !CreateDirectoryW(nearDir, NULL) || !CreateDirectoryW(t->Outside, NULL) ||
        !CreateDirectoryW(overDir, NULL))
    {
        Out(L"setup: cannot create the lab folders under %ls (error %lu)\n", work, GetLastError());
        return FALSE;
    }
    if (!WriteText(t->Secret, gSecretText) || !WriteText(deep, "deeper secret\r\n") ||
        !WriteText(t->NearMiss, "not guarded: Secret Store2 is another name\r\n") || !WriteText(t->Plain, "plain\r\n") ||
        !WriteText(t->Alias, "not guarded: only the name Secret Store, in the wrong folder\r\n") ||
        !WriteText(t->OverMatch, "matched by design: a file with the store's two-part name\r\n"))
    {
        Out(L"setup: cannot write the lab files (error %lu)\n", GetLastError());
        return FALSE;
    }
    if (swprintf_s(stream, LAB_PATH, L"%ls:extra", t->Secret) > 0) WriteText(stream, "a stream of the secret\r\n");
    if (swprintf_s(stream, LAB_PATH, L"%ls:hidden", t->Store) > 0) WriteText(stream, "a stream on the store folder\r\n");
    if (!CreateHardLinkW(t->PreLinked, t->Secret, NULL))
    {
        Out(L"setup: cannot hard link %ls (error %lu)\n", t->PreLinked, GetLastError());
        return FALSE;
    }
    t->HasJunction = Mklink(L"/J", t->Junction, t->Store);
    t->HasSymlink = Mklink(L"", t->Symlink, t->Secret);
    t->HasDirSymlink = Mklink(L"/D", t->DirSymlink, t->Store);

    // The trusted copy's folder, reached through a junction.
    if (wcscpy_s(trustedDir, LAB_PATH, gTrusted) == 0 && (slash = wcsrchr(trustedDir, L'\\')) != NULL)
    {
        *slash = L'\0';
        t->HasTrustedJunction = Mklink(L"/J", t->TrustedJunction, trustedDir) &&
            swprintf_s(t->TrustedViaJunction, LAB_PATH, L"%ls\\%ls", t->TrustedJunction, slash + 1) > 0;
    }

    if (GetShortPathNameW(t->Secret, t->ShortSecret, LAB_PATH) > 0 && _wcsicmp(t->ShortSecret, t->Secret) != 0 &&
        GetShortPathNameW(t->Store, t->ShortStore, LAB_PATH) > 0 && _wcsicmp(t->ShortStore, t->Store) != 0)
        t->HasShortName = TRUE;

    // Opens by file id work through a token without the traverse privilege only if nothing on the
    // path denies traverse: the deny ACE on the folder above the store is what makes the filter
    // manager's name query fail for it.
    t->HasTraverseDeny = DenyTraverse(t->Above);

    // The same file as the local SMB server sees it. Checked now, with blocking off, so a
    // volume without the share (or a VM where SYSTEM cannot use it) skips the rows.
    if (t->Secret[0] != L'\0' && t->Secret[1] == L':' && t->Secret[2] == L'\\' &&
        swprintf_s(t->SmbSecret, LAB_PATH, L"\\\\localhost\\%lc$\\%ls", t->Secret[0], t->Secret + 3) > 0)
    {
        h = CreateFileW(t->SmbSecret, GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            t->HasSmb = TRUE;
            CloseHandle(h);
        }
    }

    if (!GetVolumePathNameW(work, t->VolumeRoot, LAB_PATH)) return FALSE;
    if (!FileIdOf(t->Secret, t->SecretId, _countof(t->SecretId)) || !FileIdOf(t->NearMiss, t->NearId, _countof(t->NearId)))
        return FALSE;

    Out(L"lab tree: %ls\n  junction %ls, symlink %ls, directory symlink %ls, 8.3 name %ls, file id %ls\n", t->Store,
        t->HasJunction ? L"yes" : L"NO", t->HasSymlink ? L"yes" : L"NO", t->HasDirSymlink ? L"yes" : L"NO",
        t->HasShortName ? t->ShortSecret : L"NONE (8.3 names are off on this volume)", t->SecretId);
    Out(L"  traverse deny %ls, SMB loopback %ls\n", t->HasTraverseDeny ? L"yes" : L"NO", t->HasSmb ? L"reachable" : L"NOT reachable");
    return TRUE;
}

// The deny ACE must really stop a token without the privilege, or the rows that depend on it test
// nothing: open the secret by its path with such a token (blocking is off now, so only the file
// system can refuse).
static BOOL TraverseDenyWorks(_In_ const LAB_TREE* t)
{
    wchar_t command[LAB_PATH * 3], exeArg[LAB_PATH + 4], arg[LAB_PATH + 4];
    DWORD code;
    Quote(exeArg, _countof(exeArg), gUntrusted);
    Quote(arg, _countof(arg), t->Secret);
    if (swprintf_s(command, _countof(command), L"%ls probe open %ls", exeArg, arg) < 0) return FALSE;
    code = RunHidden(command, 30000, NULL, TRUE);
    if (code != ERROR_ACCESS_DENIED)
        Out(L"  traverse deny: a path open without the privilege gave error %lu, not access denied: its rows are skipped\n", code);
    else
        Out(L"  traverse deny: a path open without the privilege is refused by the file system, as the rows need\n");
    return code == ERROR_ACCESS_DENIED;
}

// ------------------------------------------------------------------ shadow copy

// A Volume Shadow Copy of the lab volume, made as SYSTEM through Win32_ShadowCopy (a CIM class,
// so no VSS COM code here) and deleted at the end. The device object is the root of the copy:
// https://learn.microsoft.com/windows/win32/vss/requestor-access-to-shadow-copied-data
static const char kShadowScript[] =
    "param([string]$Action, [string]$Arg, [string]$Out)\r\n"
    "$ErrorActionPreference = 'Stop'\r\n"
    "try {\r\n"
    "  if ($Action -eq 'create') {\r\n"
    "    $r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{ Volume = $Arg; Context = 'ClientAccessible' }\r\n"
    "    if ($r.ReturnValue -ne 0) { exit 3 }\r\n"
    "    $s = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $r.ShadowID }\r\n"
    "    Set-Content -Path $Out -Value @($s.DeviceObject, $s.ID) -Encoding ASCII\r\n"
    "  } elseif ($Action -eq 'delete') {\r\n"
    "    Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $Arg } | Remove-CimInstance\r\n"
    "  }\r\n"
    "} catch { exit 2 }\r\n";

static DWORD RunShadowScript(_In_z_ const wchar_t* action, _In_z_ const wchar_t* argument)
{
    wchar_t command[LAB_PATH * 4], script[LAB_PATH + 4], arg[LAB_PATH + 4], out[LAB_PATH + 4];
    Quote(script, _countof(script), gShadowScriptPath);
    Quote(arg, _countof(arg), argument);
    Quote(out, _countof(out), gShadowOut);
    if (swprintf_s(command, _countof(command),
            L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File %ls %ls %ls %ls",
            script, action, arg, out) < 0)
        return ERROR_BUFFER_OVERFLOW;
    return RunHidden(command, 300000, NULL, FALSE);
}

static BOOL IsShadowId(_In_z_ const wchar_t* id)
{
    size_t i, n = wcslen(id);
    if (n < 36 || n > 40 || id[0] != L'{' || id[n - 1] != L'}') return FALSE;
    for (i = 1; i + 1 < n; i++)
        if (!(id[i] == L'-' || (id[i] >= L'0' && id[i] <= L'9') || (id[i] >= L'a' && id[i] <= L'f') ||
              (id[i] >= L'A' && id[i] <= L'F')))
            return FALSE;
    return TRUE;
}

static void DeleteShadow(void)
{
    DWORD code;
    if (gShadowId[0] != L'\0')
    {
        code = RunShadowScript(L"delete", gShadowId);
        if (code != 0)
        {
            Out(L"WARNING: the shadow copy %ls could not be deleted (exit %lu); it is named in %ls, and lab.ps1 reset deletes it\n",
                gShadowId, code, gShadowOut);
            return;
        }
        gShadowId[0] = L'\0';
    }
    if (gShadowOut[0] != L'\0') DeleteFileW(gShadowOut);
    if (gShadowScriptPath[0] != L'\0') DeleteFileW(gShadowScriptPath);
}

static void PrepareShadow(_In_z_ const wchar_t* work, _Inout_ LAB_TREE* t)
{
    static const wchar_t prefix[] = L"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy";
    wchar_t device[LAB_PATH], id[64];
    FILE* f = NULL;
    DWORD code;

    if (t->Secret[1] != L':') return;
    if (swprintf_s(gShadowScriptPath, LAB_PATH, L"%ls\\vss.ps1", work) < 0 ||
        swprintf_s(gShadowOut, LAB_PATH, L"%ls\\vss.txt", work) < 0 || !WriteText(gShadowScriptPath, kShadowScript))
        return;
    DeleteFileW(gShadowOut);
    Out(L"shadow copy: creating one of %ls (can take a minute)\n", t->VolumeRoot);
    code = RunShadowScript(L"create", t->VolumeRoot);
    device[0] = L'\0';
    id[0] = L'\0';
    if (code == 0 && _wfopen_s(&f, gShadowOut, L"r") == 0 && f != NULL)
    {
        if (fgetws(device, _countof(device), f) != NULL) device[wcscspn(device, L"\r\n")] = L'\0';
        if (fgetws(id, _countof(id), f) != NULL) id[wcscspn(id, L"\r\n")] = L'\0';
        fclose(f);
    }
    if (IsShadowId(id)) wcscpy_s(gShadowId, _countof(gShadowId), id);
    if (code != 0 || !IsShadowId(id) || _wcsnicmp(device, prefix, wcslen(prefix)) != 0)
    {
        Out(L"shadow copy: not made (script exit %lu), so its rows are skipped\n", code);
        DeleteShadow();
        return;
    }
    if (swprintf_s(t->ShadowSecret, LAB_PATH, L"%ls%ls", device, t->Secret + 2) > 0) t->HasShadow = TRUE;
    Out(L"shadow copy: %ls\n", device);
}

// ------------------------------------------------------------------ scenarios

typedef enum _LAB_EXPECT {
    ExpectAllowed,
    ExpectRefused,
    ExpectResidual,   // allowed, and documented as a hole the design does not close
    ExpectByDesign,   // refused, and documented as more than the guard strictly needs to refuse
    ExpectObserve     // what happens is recorded, not judged: the behaviour depends on the OS
} LAB_EXPECT;

typedef struct _LAB_SCENARIO {
    const wchar_t* Name;
    BOOL           Trusted;      // run from the trusted copy
    LAB_EXPECT     Expect;       // with blocking on
    UINT32         Report;       // the one BRUCE_OPERATION every report of the refusal must carry; 0 = any
    const wchar_t* Op;           // probe operation
    wchar_t        Arg1[LAB_PATH];
    wchar_t        Arg2[LAB_PATH];
    wchar_t        Exe[LAB_PATH];      // run this program instead of the trusted or untrusted copy
    wchar_t        Restore[LAB_PATH];  // where Undo puts a renamed item back (default: Arg1)
    BOOL           Skip;         // what it needs could not be set up
    BOOL           BlockingOff;  // run with blocking switched off
    BOOL           NoTraverse;   // the probe's token has no bypass-traverse privilege
    BOOL           AnyPid;       // the refusal is reported under another process (a server's)
    DWORD          DryError;     // in a dry run this Win32 error counts as success too (the name is taken)
} LAB_SCENARIO;

typedef struct _LAB_TOTALS {
    int Pass, Fail, Skip, Residual, Observed;
} LAB_TOTALS;

// Puts the tree back after an operation that went through (expected or not).
static void Undo(_In_ const LAB_SCENARIO* s)
{
    if (wcscmp(s->Op, L"rename") == 0) MoveFileExW(s->Arg2, s->Restore[0] != L'\0' ? s->Restore : s->Arg1, 0);
    else if (wcscmp(s->Op, L"link") == 0 || wcscmp(s->Op, L"copy") == 0)
        DeleteFileW(wcscmp(s->Op, L"link") == 0 ? s->Arg1 : s->Arg2);
    else if (wcscmp(s->Op, L"delete") == 0) WriteText(s->Arg1, gSecretText);
    else if (wcscmp(s->Op, L"shortname") == 0) SetShortName(s->Arg1, L"");
}

static const wchar_t* OperationName(UINT32 operation)
{
    switch (operation)
    {
    case BruceOpOpen:   return L"open";
    case BruceOpRename: return L"rename";
    case BruceOpLink:   return L"link";
    case BruceOpReopen: return L"reopen";
    case BruceOpProcessHandle: return L"process";
    case BruceOpThreadHandle:  return L"thread";
    default:            return L"?";
    }
}

static void OperationNames(UINT32 mask, _Out_writes_(chars) wchar_t* out, size_t chars)
{
    UINT32 operation;
    out[0] = L'\0';
    for (operation = 1; operation < 32; operation++)
    {
        if ((mask & (1u << operation)) == 0) continue;
        if (out[0] != L'\0') wcscat_s(out, chars, L"+");
        wcscat_s(out, chars, OperationName(operation));
    }
    if (out[0] == L'\0') wcscpy_s(out, chars, L"-");
}

static LAB_EXPECT EffectiveExpect(_In_ const LAB_SCENARIO* s)
{
    if (gDryRun || s->BlockingOff) return s->Expect == ExpectResidual ? ExpectResidual : ExpectAllowed;
    return s->Expect;
}

static void RunScenario(int number, _In_ const LAB_SCENARIO* s, _Inout_ LAB_TOTALS* totals)
{
    wchar_t command[LAB_PATH * 3], exeArg[LAB_PATH + 4], arg1[LAB_PATH + 4], arg2[LAB_PATH + 4], report[48];
    const wchar_t* exe = s->Exe[0] != L'\0' ? s->Exe : s->Trusted ? gTrusted : gUntrusted;
    const wchar_t* expected;
    const wchar_t* verdict;
    LAB_EXPECT expect = EffectiveExpect(s);
    BRUCE_STATUS before, after;
    BOOL haveCounters = FALSE, refused, pass, judgesReport;
    UINT32 seen = 0, wanted = s->Report != 0 ? 1u << s->Report : 0;
    DWORD pid = 0, reporter = 0, code;

    ZeroMemory(&before, sizeof(before));
    ZeroMemory(&after, sizeof(after));
    if (s->Skip)
    {
        totals->Skip++;
        Out(L"%2d  %-52ls %-9ls %-8ls %-8ls %-12ls SKIP\n", number, s->Name, s->Trusted ? L"trusted" : L"untrusted", L"-", L"-", L"-");
        return;
    }
    if (s->BlockingOff && !gDryRun) Send(BruceSetBlocking, 0, NULL, NULL, 0, NULL);
    if (!gDryRun)
    {
        // Only reports from this probe count: a recycled pid must not match an older one.
        EnterCriticalSection(&gNotesLock);
        gNoteCount = 0;
        LeaveCriticalSection(&gNotesLock);
        if (s->Report == BruceOpReopen) haveCounters = QueryStatus(&before);
    }

    Quote(exeArg, _countof(exeArg), exe);
    Quote(arg1, _countof(arg1), s->Arg1);
    Quote(arg2, _countof(arg2), s->Arg2);
    swprintf_s(command, _countof(command), L"%ls probe %ls %ls %ls", exeArg, s->Op, arg1, s->Arg2[0] != L'\0' ? arg2 : L"");
    code = RunHidden(command, 30000, &pid, s->NoTraverse);

    if (s->BlockingOff && !gDryRun) Send(BruceSetBlocking, 1, NULL, NULL, 0, NULL);
    if (code == ERROR_SUCCESS) Undo(s);

    refused = (code == ERROR_ACCESS_DENIED);
    judgesReport = expect == ExpectRefused || expect == ExpectByDesign;
    if (!gDryRun && !s->BlockingOff && refused && (judgesReport || expect == ExpectObserve))
        seen = CollectNotes(pid, s->AnyPid, 3000, &reporter);
    if (haveCounters && !QueryStatus(&after)) haveCounters = FALSE;

    if (judgesReport)
        // Every refusal must reach the agent, and as the operation this row says: a row that
        // passes because another hook refused it first is a different test.
        pass = refused && seen != 0 && (wanted == 0 || seen == wanted);
    else if (expect == ExpectObserve)
        pass = TRUE;
    else
        pass = code == ERROR_SUCCESS || (gDryRun && s->DryError != 0 && code == s->DryError);

    OperationNames(seen, report, _countof(report));
    if (!pass) { verdict = L"FAIL"; totals->Fail++; }
    else if (expect == ExpectObserve) { verdict = L"OBSERVED"; totals->Observed++; }
    else if (expect == ExpectResidual) { verdict = L"PASS (known limit)"; totals->Residual++; totals->Pass++; }
    else if (expect == ExpectByDesign) { verdict = L"PASS (by design)"; totals->Residual++; totals->Pass++; }
    else { verdict = L"PASS"; totals->Pass++; }

    expected = judgesReport ? L"refused" : expect == ExpectObserve ? L"observe" : L"allowed";
    Out(L"%2d  %-52ls %-9ls %-8ls %-8ls %-12ls %ls", number, s->Name, s->Trusted ? L"trusted" : L"untrusted", expected,
        code == ERROR_SUCCESS ? L"allowed" : refused ? L"refused" : L"error", report, verdict);
    if (code != ERROR_SUCCESS && !refused) Out(L"  (error %lu)", code);
    if (judgesReport && refused && seen == 0) Out(L"  (refused, but the driver sent no report: not by this driver)");
    if (judgesReport && refused && seen != 0 && wanted != 0 && seen != wanted)
        Out(L"  (this row expects only a %ls report)", OperationName(s->Report));
    if (judgesReport && !refused && code == ERROR_SUCCESS) Out(L"  (the operation was allowed)");
    if (seen != 0 && s->AnyPid && reporter != pid) Out(L"  (reported under pid %lu, not the probe's)", reporter);
    if (haveCounters) Out(L"  (rechecked +%u)", after.Rechecked - before.Rechecked);
    Out(L"\n");
}

static int AddScenario(_Inout_updates_(max) LAB_SCENARIO* list, int count, int max, _In_z_ const wchar_t* name, BOOL trusted,
    LAB_EXPECT expect, UINT32 report, _In_z_ const wchar_t* op, _In_z_ const wchar_t* arg1, _In_opt_z_ const wchar_t* arg2)
{
    LAB_SCENARIO* s;
    if (count >= max) return count;
    s = &list[count];
    ZeroMemory(s, sizeof(*s));
    s->Name = name;
    s->Trusted = trusted;
    s->Expect = expect;
    s->Report = report;
    s->Op = op;
    wcscpy_s(s->Arg1, LAB_PATH, arg1);
    if (arg2 != NULL) wcscpy_s(s->Arg2, LAB_PATH, arg2);
    return count + 1;
}

// Every refusal row names the report it must produce, and the IRP that makes it. In short: an
// open (BruceOpOpen) is refused by the pre-create callback, the filter manager's name for an
// open by id included; the set-information hook (BruceOpRename, BruceOpLink) only sees what
// the I/O manager's own open of the target folder let through, and that open is named for the
// folder's parent; BruceOpReopen is the post-create recheck. See README.md.
static int Scenarios(_In_ const LAB_TREE* t, _Out_writes_(max) LAB_SCENARIO* list, int max)
{
    wchar_t a[LAB_PATH], b[LAB_PATH];
    int n = 0;
    LAB_SCENARIO* last;

    ZeroMemory(list, sizeof(LAB_SCENARIO) * (size_t)max);
    n = AddScenario(list, n, max, L"untrusted reads the guarded file", FALSE, ExpectRefused, BruceOpOpen, L"read", t->Secret, NULL);
    n = AddScenario(list, n, max, L"trusted program reads it", TRUE, ExpectAllowed, 0, L"read", t->Secret, NULL);
    n = AddScenario(list, n, max, L"opens the store folder itself", FALSE, ExpectRefused, BruceOpOpen, L"open", t->Store, NULL);
    n = AddScenario(list, n, max, L"lists the store folder", FALSE, ExpectRefused, BruceOpOpen, L"list", t->Store, NULL);
    swprintf_s(a, LAB_PATH, L"%ls::$INDEX_ALLOCATION", t->Store);
    n = AddScenario(list, n, max, L"store folder as ::$INDEX_ALLOCATION", FALSE, ExpectRefused, BruceOpOpen, L"open", a, NULL);
    swprintf_s(a, LAB_PATH, L"%ls:hidden", t->Store);
    n = AddScenario(list, n, max, L"a stream on the store folder", FALSE, ExpectRefused, BruceOpOpen, L"read", a, NULL);
    swprintf_s(a, LAB_PATH, L"%ls:extra", t->Secret);
    n = AddScenario(list, n, max, L"a stream of the guarded file", FALSE, ExpectRefused, BruceOpOpen, L"read", a, NULL);
    wcscpy_s(a, LAB_PATH, t->Secret);
    _wcsupr_s(a, LAB_PATH);
    n = AddScenario(list, n, max, L"the guarded file in upper case", FALSE, ExpectRefused, BruceOpOpen, L"read", a, NULL);

    // Junction and symlink: the first open succeeds with STATUS_REPARSE, which the post-create
    // callback ignores; the I/O manager reissues it under the target's name, and that open is
    // refused in pre-create.
    swprintf_s(a, LAB_PATH, L"%ls\\secret.txt", t->Junction);
    n = AddScenario(list, n, max, L"through a junction to the store", FALSE, ExpectRefused, BruceOpOpen, L"read", a, NULL);
    list[n - 1].Skip = !t->HasJunction;
    n = AddScenario(list, n, max, L"through a symlink to the file", FALSE, ExpectRefused, BruceOpOpen, L"read", t->Symlink, NULL);
    list[n - 1].Skip = !t->HasSymlink;
    // Pre-create too: the name has "~1", and the normalized name (one query) is the guarded one.
    n = AddScenario(list, n, max, L"through 8.3 short names", FALSE, ExpectRefused, BruceOpOpen, L"read", t->ShortSecret, NULL);
    list[n - 1].Skip = !t->HasShortName;
    // Pre-create as well: the filter manager resolves the name of an open by id itself. Row 29
    // is the one that reaches the recheck.
    n = AddScenario(list, n, max, L"open by file id", FALSE, ExpectRefused, BruceOpOpen, L"openid", t->VolumeRoot, t->SecretId);

    swprintf_s(b, LAB_PATH, L"%ls\\copied.txt", t->Outside);
    n = AddScenario(list, n, max, L"copies the guarded file out", FALSE, ExpectRefused, BruceOpOpen, L"copy", t->Secret, b);
    n = AddScenario(list, n, max, L"deletes the guarded file", FALSE, ExpectRefused, BruceOpOpen, L"delete", t->Secret, NULL);
    swprintf_s(a, LAB_PATH, L"%ls\\stolen.txt", t->Outside);
    n = AddScenario(list, n, max, L"hard links the guarded file out", FALSE, ExpectRefused, BruceOpOpen, L"link", a, t->Secret);
    // Into the store: the I/O manager first opens the target's parent folder (SL_OPEN_TARGET_
    // DIRECTORY), and the filter manager names that open for the parent, which is the store.
    // The set-information hook is never reached: rows 25 to 27 are the ones that reach it.
    swprintf_s(b, LAB_PATH, L"%ls\\planted.txt", t->Store);
    n = AddScenario(list, n, max, L"renames a file into the store", FALSE, ExpectRefused, BruceOpOpen, L"rename", t->Plain, b);
    swprintf_s(a, LAB_PATH, L"%ls\\planted2.txt", t->Store);
    n = AddScenario(list, n, max, L"hard links a file into the store", FALSE, ExpectRefused, BruceOpOpen, L"link", a, t->Plain);
    swprintf_s(b, LAB_PATH, L"%ls\\Moved Store", t->Above);
    n = AddScenario(list, n, max, L"renames the store folder", FALSE, ExpectRefused, BruceOpOpen, L"rename", t->Store, b);
    swprintf_s(b, LAB_PATH, L"%ls\\MovedAbove", t->Data);
    n = AddScenario(list, n, max, L"renames a folder above the store", FALSE, ExpectRefused, BruceOpRename, L"rename", t->Above, b);

    swprintf_s(b, LAB_PATH, L"%ls\\renamed.txt", t->Store);
    n = AddScenario(list, n, max, L"trusted program renames inside the store", TRUE, ExpectAllowed, 0, L"rename", t->Secret, b);
    n = AddScenario(list, n, max, L"untrusted reads an unguarded file", FALSE, ExpectAllowed, 0, L"read", t->Plain, NULL);
    n = AddScenario(list, n, max, L"untrusted reads a near-miss folder", FALSE, ExpectAllowed, 0, L"read", t->NearMiss, NULL);
    n = AddScenario(list, n, max, L"reads a hard link made before blocking", FALSE, ExpectResidual, 0, L"read", t->PreLinked, NULL);
    n = AddScenario(list, n, max, L"untrusted reads it with blocking off", FALSE, ExpectAllowed, 0, L"read", t->Secret, NULL);
    last = &list[n - 1];
    last->BlockingOff = TRUE;

    // Rows 25 to 27 reach the set-information hook. A rename or link onto the store folder's own
    // name has the parent of the store (no match) as its target folder, so the open passes and
    // the hook sees the destination. The name exists, so with no driver the file system answers
    // "already exists": that counts in a dry run.
    n = AddScenario(list, n, max, L"renames a file onto the store folder's name", FALSE, ExpectRefused, BruceOpRename, L"rename", t->Plain, t->Store);
    list[n - 1].DryError = ERROR_ALREADY_EXISTS;
    n = AddScenario(list, n, max, L"hard links a file onto the store folder's name", FALSE, ExpectRefused, BruceOpLink, L"link", t->Store, t->Plain);
    list[n - 1].DryError = ERROR_ALREADY_EXISTS;
    // The same through the 8.3 name. In both lab VMs the normalized destination name kept the final
    // component as written, so the hook did not refuse it, and NTFS then refused the existing name
    // (error 183). Not a way in: an 8.3 name exists only for an item that exists, and a folder
    // cannot be replaced. Recorded, not judged.
    n = AddScenario(list, n, max, L"renames a file onto the store by its 8.3 name", FALSE, ExpectObserve, BruceOpRename, L"rename", t->Plain, t->ShortStore);
    list[n - 1].DryError = ERROR_ALREADY_EXISTS;
    list[n - 1].Skip = !t->HasShortName;
    // The source side: the open of the folder being moved, named through "~1" and expanded.
    swprintf_s(b, LAB_PATH, L"%ls\\Moved Store", t->Above);
    n = AddScenario(list, n, max, L"renames the store folder by its 8.3 name", FALSE, ExpectRefused, BruceOpOpen, L"rename", t->ShortStore, b);
    wcscpy_s(list[n - 1].Restore, LAB_PATH, t->Store);
    list[n - 1].Skip = !t->HasShortName;

    // Rows 29 to 31: an open by id whose name the filter manager cannot give, because the
    // caller has no traverse privilege and a folder on the path denies traverse. The pre-create
    // name query then fails with STATUS_ACCESS_DENIED
    // (https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetfilenameinformation),
    // BrucePreCreate sets the recheck for an open by id, and the post-create callback decides:
    // the guarded file is cancelled (BruceOpReopen, FltCancelFileOpen).
    n = AddScenario(list, n, max, L"open by id without the traverse right", FALSE, ExpectRefused, BruceOpReopen, L"openid", t->VolumeRoot, t->SecretId);
    list[n - 1].NoTraverse = TRUE;
    list[n - 1].Skip = !t->HasTraverseDeny;
    // If the name is still unknown after the open, only an image trusted for every store passes,
    // and this one is trusted for the lab store alone: refused. If the post-create query does
    // return the name, it is allowed. Which of the two happens is the OS's, so it is recorded.
    n = AddScenario(list, n, max, L"same, by the program this store trusts", TRUE, ExpectObserve, BruceOpReopen, L"openid", t->VolumeRoot, t->SecretId);
    list[n - 1].NoTraverse = TRUE;
    list[n - 1].Skip = !t->HasTraverseDeny;
    // An unguarded file under the same folder: refused too (fail closed) if the name is still unknown after the open.
    n = AddScenario(list, n, max, L"by id, a near-miss file, no traverse right", FALSE, ExpectObserve, BruceOpReopen, L"openid", t->VolumeRoot, t->NearId);
    list[n - 1].NoTraverse = TRUE;
    list[n - 1].Skip = !t->HasTraverseDeny;

    n = AddScenario(list, n, max, L"lists the store through the junction", FALSE, ExpectRefused, BruceOpOpen, L"list", t->Junction, NULL);
    list[n - 1].Skip = !t->HasJunction;
    swprintf_s(a, LAB_PATH, L"%ls\\secret.txt", t->DirSymlink);
    n = AddScenario(list, n, max, L"through a directory symlink to the store", FALSE, ExpectRefused, BruceOpOpen, L"read", a, NULL);
    list[n - 1].Skip = !t->HasDirSymlink;
    // FILE_FLAG_OPEN_REPARSE_POINT opens the junction itself, named ...\outside\jstore, which is
    // not guarded; no file data can be read through it, only its reparse data.
    n = AddScenario(list, n, max, L"opens the junction itself (OPEN_REPARSE_POINT)", FALSE, ExpectAllowed, 0, L"openrp", t->Junction, NULL);
    list[n - 1].Skip = !t->HasJunction;
    n = AddScenario(list, n, max, L"a file called Secret Store in another folder", FALSE, ExpectAllowed, 0, L"read", t->Alias, NULL);
    n = AddScenario(list, n, max, L"a file called BruceLab\\Secret Store elsewhere", FALSE, ExpectByDesign, BruceOpOpen, L"read", t->OverMatch, NULL);
    // The image is named by the open the I/O manager reissues after the junction, so it is the
    // trusted copy's own path.
    n = AddScenario(list, n, max, L"trusted copy started through a junction", TRUE, ExpectAllowed, 0, L"read", t->Secret, NULL);
    wcscpy_s(list[n - 1].Exe, LAB_PATH, t->TrustedViaJunction);
    list[n - 1].Skip = !t->HasTrustedJunction;

    n = AddScenario(list, n, max, L"untrusted reads it in a shadow copy", FALSE, ExpectRefused, BruceOpOpen, L"read", t->ShadowSecret, NULL);
    list[n - 1].Skip = !t->HasShadow;
    n = AddScenario(list, n, max, L"trusted program reads it in a shadow copy", TRUE, ExpectAllowed, 0, L"read", t->ShadowSecret, NULL);
    list[n - 1].Skip = !t->HasShadow;
    // The SMB server opens the local file in its own (System) process, so the open is attributed to it.
    n = AddScenario(list, n, max, L"untrusted reads it over SMB loopback", FALSE, ExpectRefused, BruceOpOpen, L"read", t->SmbSecret, NULL);
    list[n - 1].AnyPid = TRUE;
    list[n - 1].Skip = !t->HasSmb;
    n = AddScenario(list, n, max, L"trusted program reads it over SMB loopback", TRUE, ExpectByDesign, BruceOpOpen, L"read", t->SmbSecret, NULL);
    list[n - 1].AnyPid = TRUE;
    list[n - 1].Skip = !t->HasSmb;

    // Since Windows 10 1903 a caller with DELETE access may set any short name, and one without
    // ~digit is never expanded: ...\data\BLSHORT\Secret Store\ would not carry the fragment.
    n = AddScenario(list, n, max, L"gives a folder above the store a short name", FALSE, ExpectRefused, BruceOpRename,
        L"shortname", t->Above, L"BLSHORT");

    // The process guard. A program that starts the trusted copy must be able to (Task Scheduler
    // could not, before the creator kept THREAD_SUSPEND_RESUME), but no longer write into it:
    // residual 1. Whether the write is refused depends on Windows making the creator's process
    // handle after the notify routine, so row 44 is observed, not judged, until a VM shows it
    // refused (and a creator's strips send no report). The harness started the held copy, so
    // the probes reaching into it are not its creator.
    n = AddScenario(list, n, max, L"untrusted starts the trusted copy", FALSE, ExpectAllowed, 0, L"spawn", gTrusted, NULL);
    n = AddScenario(list, n, max, L"untrusted starts the trusted copy, writes into it", FALSE, ExpectObserve, 0,
        L"spawnwrite", gTrusted, NULL);
    n = AddScenario(list, n, max, L"untrusted writes into a running trusted copy", FALSE, ExpectRefused, BruceOpProcessHandle,
        L"vmwrite", t->HeldPid, NULL);
    list[n - 1].Skip = !t->HasHeld;
    n = AddScenario(list, n, max, L"untrusted copies a handle out of it", FALSE, ExpectRefused, BruceOpProcessHandle,
        L"dup", t->HeldPid, NULL);
    list[n - 1].Skip = !t->HasHeld;
    list[n - 1].DryError = ERROR_INVALID_HANDLE;   // with the right granted, handle 4 may not exist there
    n = AddScenario(list, n, max, L"untrusted suspends one of its threads", FALSE, ExpectRefused, BruceOpThreadHandle,
        L"suspend", t->HeldTid, NULL);
    list[n - 1].Skip = !t->HasHeld;
    n = AddScenario(list, n, max, L"the trusted copy writes into another trusted copy", TRUE, ExpectAllowed, 0,
        L"vmwrite", t->HeldPid, NULL);
    list[n - 1].Skip = !t->HasHeld;
    n = AddScenario(list, n, max, L"untrusted writes into it, blocking off", FALSE, ExpectAllowed, 0, L"vmwrite", t->HeldPid, NULL);
    list[n - 1].Skip = !t->HasHeld;
    list[n - 1].BlockingOff = TRUE;
    return n;
}

// ------------------------------------------------------------------ teardown

// FilterUnload and FilterDetach need SeLoadDriverPrivilege, which a SYSTEM token holds but may
// not have enabled; fltmc enables it for itself, so the harness does too.
static BOOL EnableLoadDriverPrivilege(void)
{
    HANDLE token;
    TOKEN_PRIVILEGES privileges;
    BOOL ok = FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return FALSE;
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, SE_LOAD_DRIVER_NAME, &privileges.Privileges[0].Luid))
        ok = AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

// While blocking is on the driver must refuse a non-mandatory unload (fltmc unload) and a manual
// detach (fltmc detach) with STATUS_FLT_DO_NOT_DETACH, which user mode sees as
// ERROR_FLT_DO_NOT_DETACH (0x801F0010) or the same status as an HRESULT. Any other result,
// above all success, means the filter is gone or never refused: the check fails. A mandatory
// unload (a service stop) is not tried: it cannot be refused and would end the run.
static void RunTeardownCheck(int number, _In_z_ const wchar_t* name, HRESULT hr, _Inout_ LAB_TOTALS* totals)
{
    BOOL pass = (hr == (HRESULT)0x801F0010L || hr == (HRESULT)0xD01C0010L);
    Out(L"%2d  %-44ls %-9ls %-8ls %-8ls %-7ls %ls", number, name, L"SYSTEM", L"refused",
        SUCCEEDED(hr) ? L"allowed" : pass ? L"refused" : L"error", L"-", pass ? L"PASS" : L"FAIL");
    if (!pass) Out(L"  (0x%08X)", (unsigned)hr);
    Out(L"\n");
    if (pass) totals->Pass++;
    else totals->Fail++;
}

static void TeardownChecks(int firstNumber, _Inout_ LAB_TOTALS* totals)
{
    wchar_t system[MAX_PATH];
    HRESULT hr;

    if (!EnableLoadDriverPrivilege())
        Out(L"note: SeLoadDriverPrivilege could not be enabled; the teardown checks may fail for that reason\n");
    if (GetSystemDirectoryW(system, _countof(system)) < 3) wcscpy_s(system, _countof(system), L"C:");
    system[2] = L'\\';
    system[3] = L'\0';   // "C:\", the volume Windows is on

    hr = FilterUnload(L"BruceFilter");
    RunTeardownCheck(firstNumber, L"unload while blocking (fltmc unload)", hr, totals);
    hr = FilterDetach(L"BruceFilter", system, NULL);
    RunTeardownCheck(firstNumber + 1, L"detach while blocking (fltmc detach)", hr, totals);
}

// ------------------------------------------------------------------ run

static BOOL NtPathOf(_In_z_ const wchar_t* path, _Out_writes_(chars) wchar_t* nt, DWORD chars)
{
    DWORD n;
    HANDLE h = CreateFileW(path, FILE_READ_ATTRIBUTES, SHARE_ALL, NULL, OPEN_EXISTING, 0, NULL);
    nt[0] = L'\0';
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    n = GetFinalPathNameByHandleW(h, nt, chars, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
    CloseHandle(h);
    return n > 0 && n < chars;
}

static int Run(_In_z_ const wchar_t* work)
{
    static LAB_SCENARIO scenarios[64];
    static LAB_TREE tree;   // 50 KB of paths: off the stack
    LAB_TOTALS totals;
    BRUCE_STATUS before, after;
    wchar_t trustedNt[LAB_PATH], self[LAB_PATH], selfNt[LAB_PATH];
    HANDLE reader = NULL;
    PROCESS_INFORMATION held = { 0 };
    int count, i, exitCode;

    ZeroMemory(&totals, sizeof(totals));
    ZeroMemory(&before, sizeof(before));
    ZeroMemory(&after, sizeof(after));
    if (!NtPathOf(gTrusted, trustedNt, LAB_PATH) || GetFileAttributesW(gUntrusted) == INVALID_FILE_ATTRIBUTES)
    {
        Out(L"setup: both copies of BruceLab.exe must exist (%ls, %ls)\n", gTrusted, gUntrusted);
        return EXIT_LAB_SETUP;
    }
    if (GetModuleFileNameW(NULL, self, LAB_PATH) == 0 || !NtPathOf(self, selfNt, LAB_PATH) || _wcsicmp(selfNt, trustedNt) != 0)
        Out(L"note: this harness is not running as the trusted copy, so repairs inside the store may be refused\n");

    if (!gDryRun)
    {
        if (!Connect()) return EXIT_LAB_SETUP;
        if (!QueryStatus(&before))
        {
            Out(L"the driver does not answer with protocol %u: install the BruceFilter.sys built with this lab\n", BRUCE_PROTOCOL_VERSION);
            Disconnect();
            return EXIT_LAB_SETUP;
        }
        ShowStatus(&before);
        if (!ResetDriver())   // blocking off while the tree is built
        {
            Out(L"the driver refused the reset\n");
            Disconnect();
            return EXIT_LAB_SETUP;
        }
    }
    else
    {
        Out(L"DRY RUN: the driver is not used; every operation is expected to succeed\n");
    }

    if (!BuildTree(work, &tree))
    {
        if (!gDryRun) Disconnect();
        return EXIT_LAB_SETUP;
    }
    if (tree.HasTraverseDeny) tree.HasTraverseDeny = TraverseDenyWorks(&tree);
    // A shadow copy is a change to the machine (made and deleted again), so a dry run, which
    // may run anywhere, leaves it out.
    if (!gDryRun) PrepareShadow(work, &tree);

    if (!gDryRun)
    {
        InitializeCriticalSection(&gNotesLock);
        gStopReader = CreateEventW(NULL, TRUE, FALSE, NULL);
        reader = gStopReader != NULL ? CreateThread(NULL, 0, Reader, NULL, 0, NULL) : NULL;
        if (reader == NULL ||
            FAILED(Send(BruceClearPolicy, 0, NULL, NULL, 0, NULL)) ||
            FAILED(Send(BruceAddSensitivePath, 0, LAB_FRAGMENT, NULL, 0, NULL)) ||
            FAILED(Send(BruceAddTrustedImage, 0, trustedNt, NULL, 0, NULL)) ||
            FAILED(Send(BruceCommitPolicy, 0, NULL, NULL, 0, NULL)) ||
            FAILED(Send(BruceSetBlocking, 1, NULL, NULL, 0, NULL)))
        {
            Out(L"could not push the lab policy\n");
            exitCode = EXIT_LAB_SETUP;
            goto teardown;
        }
        Out(L"lab policy: %ls guarded, trusted: %ls\n", LAB_FRAGMENT, trustedNt);
    }

    // Started once the policy trusts its image, so the guard counts it as protected from the start.
    if (StartCopy(gTrusted, L"600", FALSE, &held))
    {
        swprintf_s(tree.HeldPid, _countof(tree.HeldPid), L"%lu", held.dwProcessId);
        swprintf_s(tree.HeldTid, _countof(tree.HeldTid), L"%lu", held.dwThreadId);
        tree.HasHeld = TRUE;
    }
    else Out(L"note: the trusted copy to hold could not be started (error %lu); its rows are skipped\n", GetLastError());

    count = Scenarios(&tree, scenarios, _countof(scenarios));
    Out(L"\n #  %-52ls %-9ls %-8ls %-8ls %-12ls verdict\n", L"scenario", L"as", L"expected", L"got", L"report");
    for (i = 0; i < count; i++) RunScenario(i + 1, &scenarios[i], &totals);
    if (!gDryRun) TeardownChecks(count + 1, &totals);
    exitCode = totals.Fail == 0 ? 0 : EXIT_LAB_FAIL;

teardown:
    if (held.hProcess != NULL)
    {
        TerminateProcess(held.hProcess, 0);
        WaitForSingleObject(held.hProcess, 5000);
        CloseHandle(held.hProcess);
    }
    if (held.hThread != NULL) CloseHandle(held.hThread);
    tree.HasHeld = FALSE;
    if (!gDryRun)
    {
        if (QueryStatus(&after))
        {
            Out(L"\n");
            ShowStatus(&after);
            Out(L"this run: %u refusal(s) counted, %u recheck(s), %u report(s) dropped\n",
                after.Denied - before.Denied, after.Rechecked - before.Rechecked, after.NotifyDropped - before.NotifyDropped);
        }
        if (!ResetDriver()) Out(L"WARNING: the driver refused the final reset; run BruceLab.exe reset\n");
        if (reader != NULL)
        {
            SetEvent(gStopReader);
            WaitForSingleObject(reader, 10000);
            CloseHandle(reader);
        }
        Disconnect();
        DeleteShadow();
    }
    DeleteTree(tree.Data);
    Out(L"\nsummary: %d passed (%d of them known limits or by design), %d failed, %d skipped, %d observed only\n",
        totals.Pass, totals.Residual, totals.Fail, totals.Skip, totals.Observed);
    Out(L"%ls\n", exitCode == 0 ? L"LAB PASSED" : L"LAB FAILED");
    return exitCode;
}

static void Usage(void)
{
    Out(L"usage:\n"
        L"  BruceLab.exe run <work> <trusted-copy> <untrusted-copy> [--report <file>] [--dry-run]\n"
        L"  BruceLab.exe status [--report <file>]\n"
        L"  BruceLab.exe reset [--report <file>]\n"
        L"  BruceLab.exe probe <open|openrp|read|list|delete> <path>\n"
        L"  BruceLab.exe probe <rename|copy> <from> <to>\n"
        L"  BruceLab.exe probe link <new-link> <existing-file>\n"
        L"  BruceLab.exe probe openid <volume-root> <file-id-hex>\n"
        L"  BruceLab.exe probe hold <seconds>\n"
        L"  BruceLab.exe probe <spawn|spawnwrite> <exe>\n"
        L"  BruceLab.exe probe <vmwrite|dup> <pid>\n"
        L"  BruceLab.exe probe suspend <tid>\n");
}

static int Command(int argc, _In_reads_(argc) wchar_t** argv)
{
    BRUCE_STATUS status;

    if (argc >= 2 && (wcscmp(argv[1], L"status") == 0 || wcscmp(argv[1], L"reset") == 0))
    {
        BOOL reset = wcscmp(argv[1], L"reset") == 0;
        BOOL answered;
        if (!Connect()) return EXIT_LAB_SETUP;
        if (reset && !ResetDriver()) Out(L"the driver refused the reset\n");
        answered = QueryStatus(&status);
        if (answered) ShowStatus(&status);
        else Out(L"the driver does not answer with protocol %u\n", BRUCE_PROTOCOL_VERSION);
        Disconnect();
        return answered ? 0 : EXIT_LAB_SETUP;
    }
    if (argc >= 5 && wcscmp(argv[1], L"run") == 0)
    {
        if (wcscpy_s(gTrusted, LAB_PATH, argv[3]) != 0 || wcscpy_s(gUntrusted, LAB_PATH, argv[4]) != 0) return EXIT_LAB_SETUP;
        return Run(argv[2]);
    }
    Usage();
    return EXIT_LAB_SETUP;
}

int wmain(int argc, wchar_t** argv)
{
    int i, result;

    if (argc >= 2 && wcscmp(argv[1], L"probe") == 0) return Probe(argc, argv);

    // Options for every other mode. A scheduled task running as SYSTEM has no console, so
    // --report is where its output goes.
    for (i = 2; i < argc; i++)
    {
        if (wcscmp(argv[i], L"--dry-run") == 0) gDryRun = TRUE;
        else if (wcscmp(argv[i], L"--report") == 0 && i + 1 < argc && gReport == NULL)
        {
            if (_wfopen_s(&gReport, argv[i + 1], L"w, ccs=UTF-8") != 0) gReport = NULL;
        }
    }
    result = Command(argc, argv);
    if (gReport != NULL) fclose(gReport);
    return result;
}

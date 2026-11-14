#pragma once

//
// Shared between the BruceFilter minifilter and the user-mode MinifilterClient.cs. Every
// struct here is byte-identical to its managed mirror (sequential layout, default packing),
// and the sizes are pinned below and by the managed tests. Change a layout and you change
// BRUCE_PROTOCOL_VERSION with it.
//

#define BRUCE_PORT_NAME        L"\\BruceFilterPort"
#define BRUCE_PROTOCOL_VERSION 2
#define BRUCE_MAX_PATH         260
#define BRUCE_MAX_ENTRIES      64          // guarded path fragments
#define BRUCE_MAX_TRUSTED      64          // trusted process images
#define BRUCE_ANY_PREFIX       0xFFFFFFFFu // a trusted image that may open every guarded path

typedef enum _BRUCE_COMMAND {
    BruceSetBlocking      = 1,   // Flag = 0 or 1. Applies to the live policy at once.
    BruceAddSensitivePath = 2,   // Path = directory fragment such as \google\chrome\user data\ (staged)
    BruceClearPolicy      = 3,   // empties the staged policy
    BruceAddTrustedImage  = 4,   // Path = full NT image path; Flag = fragment index or BRUCE_ANY_PREFIX (staged)
    BruceCommitPolicy     = 5,   // swaps the staged policy in, keeping the live blocking flag
    BruceQueryStatus      = 6    // reply: BRUCE_STATUS
} BRUCE_COMMAND;

typedef struct _BRUCE_MESSAGE {
    UINT32 Command;
    UINT32 Flag;
    WCHAR  Path[BRUCE_MAX_PATH];
} BRUCE_MESSAGE, *PBRUCE_MESSAGE;

typedef struct _BRUCE_STATUS {
    UINT32 Version;          // BRUCE_PROTOCOL_VERSION; a version 1 driver replies with nothing
    UINT32 Blocking;
    UINT32 PrefixCount;      // live policy
    UINT32 TrustedCount;     // live policy
    UINT32 Denied;           // operations refused since load
    UINT32 Rechecked;        // opens decided after the file system opened them
    UINT32 NotifyDropped;    // denials no reader was waiting for
    UINT32 ProcessGuard;     // BRUCE_GUARD_* flags; 0 when the process guard is not running
} BRUCE_STATUS, *PBRUCE_STATUS;

// BRUCE_STATUS.ProcessGuard. Absent bits mean the file guard runs alone, as before.
#define BRUCE_GUARD_ACTIVE     0x00000001u   // the handle callbacks are registered
#define BRUCE_GUARD_ENUMERATED 0x00000002u   // processes running at load were enumerated

typedef enum _BRUCE_OPERATION {
    BruceOpOpen   = 1,   // an open refused before the file system saw it
    BruceOpRename = 2,   // a rename onto a guarded path
    BruceOpLink   = 3,   // a hard link onto a guarded path
    BruceOpReopen = 4,   // an open cancelled once its name was certain
    // Process guard. No layout changes: ProcessId is the process that asked for the handle (the
    // one that would receive a duplicate), PrefixIndex the first store the target is trusted
    // for, Path the target's image and Image the requester's. An agent that predates these
    // values drops them.
    BruceOpProcessHandle = 5,   // dangerous access removed from a handle to a trusted process
    BruceOpThreadHandle  = 6    // the same for a handle to one of its threads
} BRUCE_OPERATION;

// Sent to user mode for every refusal, without waiting: a slow or absent reader drops it.
typedef struct _BRUCE_NOTIFICATION {
    UINT32 Version;
    UINT32 Operation;                // BRUCE_OPERATION
    UINT32 ProcessId;
    UINT32 PrefixIndex;              // the guarded fragment that matched
    WCHAR  Path[BRUCE_MAX_PATH];     // target, NUL-terminated, truncated if longer
    WCHAR  Image[BRUCE_MAX_PATH];    // requester's image (NT path), may be empty
} BRUCE_NOTIFICATION, *PBRUCE_NOTIFICATION;

// Compile-time size pins, valid in kernel and user mode alike.
typedef char BruceSizeMessage[(sizeof(BRUCE_MESSAGE) == 528) ? 1 : -1];
typedef char BruceSizeStatus[(sizeof(BRUCE_STATUS) == 32) ? 1 : -1];
typedef char BruceSizeNotification[(sizeof(BRUCE_NOTIFICATION) == 1056) ? 1 : -1];

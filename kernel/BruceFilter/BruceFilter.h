#pragma once

//
// Shared definitions between the BruceFilter minifilter and the user-mode
// MinifilterClient.cs. The BRUCE_MESSAGE layout MUST stay byte-identical to the
// managed struct (sequential, default packing): UINT32, UINT32, WCHAR[260].
//

#define BRUCE_PORT_NAME    L"\\BruceFilterPort"
#define BRUCE_MAX_PATH     260
#define BRUCE_MAX_ENTRIES  64

typedef enum _BRUCE_COMMAND {
    BruceSetBlocking      = 1,   // Flag = 0/1
    BruceAddSensitivePath = 2,   // Path = fragment to match (case-insensitive)
    BruceClearPolicy      = 3
} BRUCE_COMMAND;

typedef struct _BRUCE_MESSAGE {
    UINT32 Command;
    UINT32 Flag;
    WCHAR  Path[BRUCE_MAX_PATH];
} BRUCE_MESSAGE, *PBRUCE_MESSAGE;

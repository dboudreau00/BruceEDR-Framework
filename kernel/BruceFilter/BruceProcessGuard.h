#pragma once

//
// The process guard: keeps code running as the same user from reaching a trusted program
// through its process or its threads instead of through its files. While blocking is on, a
// handle to a process whose image is trusted for a store loses its dangerous access rights
// (BruceFilterPolicy.h, BRUCE_PROCESS_STRIP and BRUCE_THREAD_STRIP) unless the process
// receiving the handle is trusted for the same stores. See docs\process-guard.md.
//
// Linked with /INTEGRITYCHECK: ObRegisterCallbacks and PsSetCreateProcessNotifyRoutineEx
// refuse an image that does not carry the flag (STATUS_ACCESS_DENIED).
//

// Registers the process notify and handle callbacks and enumerates the running processes.
// A failure leaves the file guard running alone; BruceProcessGuardFlags says what is active.
// The lock and the live policy belong to BruceFilter.c and must outlive the guard.
NTSTATUS BruceProcessGuardStart(_In_ PFLT_FILTER Filter, _In_ PEX_PUSH_LOCK PolicyLock, _In_ const BRUCE_POLICY* Live);

// Unregisters everything and waits for the callbacks and queued reports to finish.
VOID BruceProcessGuardStop(VOID);

// Re-evaluates which processes are trusted after a policy commit. Takes the policy lock
// itself: call it with the lock released.
VOID BruceProcessGuardPolicyChanged(VOID);

// The agent's own process is never stripped (containment suspends and kills through handles
// to the processes it responds to). Called in the context of the agent's thread, and with
// NULL when it disconnects.
VOID BruceProcessGuardSetAgent(_In_opt_ PEPROCESS Agent);

// BRUCE_GUARD_* flags for BRUCE_STATUS.
ULONG BruceProcessGuardFlags(VOID);

// Implemented by BruceFilter.c: sends one report to the agent without waiting.
VOID BruceSendNotification(_In_ const BRUCE_NOTIFICATION* Note);

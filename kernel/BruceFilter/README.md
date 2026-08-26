# BruceFilter minifilter

The inline-prevention layer for BruceEDR. It denies opens of sensitive paths
while blocking is enabled, driven by policy pushed from the user-mode agent over a
filter communication port.

## Build (requires the WDK)
1. Install Visual Studio + the **Windows Driver Kit (WDK)** matching your VS version.
2. Create a "Kernel Mode Driver, Empty (KMDF/WDM)" or "Filter Driver: Filesystem
   Mini-Filter" project and add `BruceFilter.c`, `BruceFilter.h`, `BruceFilter.inf`.
3. Configuration: **x64 / Release**. Build → produces `BruceFilter.sys`.

## Load in a LAB (test-signing)
Production Windows will not load an unsigned kernel driver. In an isolated VM:
```
bcdedit /set testsigning on          &  reboot
inf2cat /driver:. /os:10_X64          (generate the .cat)
```
Sign with a test certificate (makecert/signtool), then install + start:
```
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 128 .\BruceFilter.inf
fltmc load BruceFilter
fltmc                                  (confirm it is running)
```
The agent's `MinifilterClient` connects to `\BruceFilterPort` and pushes policy.

## Production signing (the hard gate)
To load on normal machines the `.sys` must be signed via **attestation signing** or
an **EV code-signing certificate + WHQL/HLK** submission through the Microsoft
Partner Center. A unique **altitude** must also be requested from Microsoft (the
385201 here is a placeholder). This is an external process, not something the code
can satisfy on its own.

## Extending the skeleton
- Push a **trusted-PID allowlist** from user mode and check
  `FltGetRequestorProcessId(Data)` before denying.
- Switch from outright deny to **send-event-and-wait**: `FltSendMessage` the create
  attempt to the agent and complete based on its verdict.
- Add contexts/streams and handle `IRP_MJ_SET_INFORMATION` (renames) and writes.

# BruceFilter minifilter

The inline-prevention layer for BruceEDR. While blocking is on, it refuses the guarded
credential stores (browser profiles, wallets) to every process whose image is not trusted
for that store: opens, renames onto them or of a folder above them, and hard links onto
them. The agent pushes the policy over a SYSTEM-only filter port and logs every refusal
the driver reports back.

**Status.** Built, analysed and unit-tested by `build.ps1` (below), then loaded in two test-signed
VMs, Windows 10 21H2 (19044) and Windows 11 22H2 (22621): the lab's 42 scenarios and its two
unload checks pass (on Windows 10 under Driver Verifier's standard checks), it unloads clean
under Verifier, and the agent service drives it end to end. It is signed with a lab certificate only, so a production install
needs a Microsoft-signed build. `detection.kernelBlocking` stays off by default.

## What it decides

- **Guarded stores** are directory fragments, such as `\google\chrome\user data\`, matched
  as whole names anywhere in a path, without regard to case. The guarded directory itself
  matches too, and a stream (`Exodus::$INDEX_ALLOCATION`) or a trailing separator on the
  last name does not hide it. The list is `KernelGuards` in `Core/Models.cs`; each fragment
  names the store, never the program's own folder.
- **Trusted images** are exact NT image paths (`\Device\HarddiskVolume3\...\chrome.exe`, as
  `SeLocateProcessImageName` reports them), each trusted for one store or for all of them.
- **Names never fail open.** Before an open the filter reads the opened name, and expands
  an 8.3 alias (`USERDA~1`) through the normalized name. An open by file id, or one whose
  name cannot be read beforehand, is decided after the file system opens it, on the
  normalized name, and cancelled with `FltCancelFileOpen` if the store is guarded. A name
  that cannot be resolved even then is refused unless the image is trusted for every store.
- **Renames and hard links.** The destination is resolved with
  `FltGetDestinationFileNameInformation`. Renaming a directory is refused when it is a
  guarded store or a folder above one (`...\Google\Chrome`), since moving it would carry
  the store out from under its fragment. A rename buffer the filter cannot read, or a
  destination it cannot resolve, counts as unresolved: refused unless the image is trusted
  for every store.
- **Every refusal is reported** to the agent without waiting (`FltSendMessage`, zero
  timeout). With no read outstanding at that moment the report is dropped and counted; the
  refusal stands either way. The agent keeps eight reads waiting, so a burst is lost only
  past eight reports in the time it handles one. The agent also feeds each refusal to its
  detection engine as a `KernelRefusal` signal, once per process and store a minute, which the
  engine scores once per process and store (+40; +10 for a name the driver could not resolve).
- **The policy** is staged and swapped in whole under a push lock, so a half-pushed policy is
  never live. It outlives the agent: killing the agent does not switch protection off.
- **The port admits SYSTEM only**, so with the agent gone an administrator cannot quietly
  rewrite the policy or switch blocking off through it.
- **While blocking is on it cannot be unloaded or detached by hand.** The unload callback
  returns `STATUS_FLT_DO_NOT_DETACH` for a non-mandatory unload (`fltmc unload`,
  `FilterUnload`, `FltUnloadFilter`), and the instance-teardown callback returns it for a manual
  detach (`fltmc detach`, `FilterDetach`, `FltDetachVolume`); both fail with
  `ERROR_FLT_DO_NOT_DETACH` (0x801F0010). With blocking off both go through. A mandatory
  unload (a service stop: `sc stop BruceFilter`, `net stop`) cannot be refused by the callback
  and is not. The callback is not called at shutdown, and a volume dismount or an unload does
  not go through the detach callback, so neither is held up. See the Microsoft pages on
  [when the unload callback is called](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/when-the-filterunloadcallback-routine-is-called),
  [`PFLT_FILTER_UNLOAD_CALLBACK`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_filter_unload_callback)
  and [`PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_query_teardown_callback).
- **The agent follows the driver.** If the driver is unloaded, its port closes or a read fails,
  the agent logs a WARN system event saying kernel enforcement is off and why, then reconnects
  (5 s, doubling to 5 min, until the agent stops). A reloaded driver starts empty with blocking
  off, so each reconnect pushes the current policy and blocking state again, and a second WARN
  says so once if the driver itself is not loaded.

The decisions are pure functions in `BruceFilterPolicy.c`, compiled into both the driver and
`test\PolicyTests.c`, so the tests exercise the code the kernel runs.

## Build

`build.ps1` needs Visual Studio 2022 with the C++ x64 tools and the WDK NuGet packages; neither
the WDK installer nor Visual Studio's "Windows Driver Kit" component is required.

```
nuget restore packages.config -PackagesDirectory packages
./build.ps1                       # or: ./build.ps1 -Configuration Debug
```

It runs, failing on the first problem:

1. compile with the WDK's kernel-mode settings, `/W4 /WX`, Spectre mitigation on;
2. code analysis with the WDK's driver plugins and recommended driver rules;
3. link `x64\<Configuration>\BruceFilter.sys`;
4. stamp a copy of the INF, check it with InfVerif (`/w` driver isolation from build 25952,
   and `/h` signing requirements), and build `brucefilter.cat` with Inf2Cat;
5. build and run `test\PolicyTests.c` against the same policy source;
6. build the VM lab harness, `lab\BruceLab.exe`.

CI runs the same script (`.github/workflows/driver.yml`), plus a dry run of the lab harness.

`BruceFilter.vcxproj` builds the same sources from Visual Studio once the "Windows Driver Kit"
component is installed; this repository's verification does not exercise it. The driver
needs Windows 10 2004 or later (`ExAllocatePool2`).

## Load in a lab (test signing)

[`lab/`](lab/README.md) automates all of this: `lab\lab.ps1 prepare` signs and stages a package on
the build machine, and in the VM `lab.ps1 testsigning`, `install` and `test` load the driver and
run 41 scenarios through it (opens, streams, links, 8.3 names, opens by file id, renames,
reparse points, a shadow copy, SMB loopback, trusted and untrusted copies of one program),
checking every refusal and its report, then check that an unload and a detach are refused
while blocking is on. The manual
steps follow.

Windows loads an unsigned driver only with test signing on. In an isolated VM, as administrator:

```
bcdedit /set testsigning on                (reboot afterwards)
```

Sign the build with a test certificate, using `signtool.exe` from the SDK package
(`packages\Microsoft.Windows.SDK.CPP.<version>\c\bin\<kit>\x64`):

```
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=BruceFilter Lab" -CertStoreLocation Cert:\CurrentUser\My
signtool sign /fd sha256 /sha1 $cert.Thumbprint x64\Release\BruceFilter.sys
signtool sign /fd sha256 /sha1 $cert.Thumbprint x64\Release\brucefilter.cat
```

Import that certificate into the VM's `LocalMachine\Root` and `LocalMachine\TrustedPublisher`
stores and copy `BruceFilter.sys`, `BruceFilter.inf` and `brucefilter.cat` into one folder.
Install the package with `DiInstallDriver` (newdev.dll), which is what `lab.ps1 install` calls,
or right-click the INF and choose Install. Then:

```
fltmc load BruceFilter
fltmc filters                              (BruceFilter at 385201)
verifier /standard /driver BruceFilter.sys (recommended; reboot afterwards)
```

On Windows 10 1903 and later the package goes to the driver store as a primitive driver.
`RUNDLL32 SETUPAPI.DLL,InstallHinfSection` should hand it on the same way, but run without an
interactive desktop (through VMware Tools) it did nothing, so the lab does not use it.
Windows 11 24H2 and later install from the store with the instance keys under `Parameters`;
earlier builds use the INF's downlevel sections. To remove it:
`fltmc unload` is refused while blocking is on, so reset the driver first, then
`fltmc unload BruceFilter`, then `DiUninstallDriver` on the same INF (`lab.ps1 uninstall` does
all three).

The agent connects only when it runs as the LocalSystem service. Its log says what it found:
the driver's protocol, the stores it guards, the programs it trusts, and the stores nothing
is trusted for.

## Configure

- `detection.kernelBlocking`: off by default. Monitor mode never blocks, whatever this says.
- Each store's owner is trusted when HKLM App Paths, or for Edge, Chrome and Firefox their
  machine-wide install folder (Edge registers no App Paths key on some builds), places it
  where only administrators can change it: SYSTEM, Administrators or TrustedInstaller own the
  file and every folder above it, and no other account can change the file, add a file beside
  it (a planted DLL), or move a folder above it.
- `detection.kernelTrustedImages`: more programs, such as a backup agent, as
  `{ "image": "C:\\Program Files\\Vendor\\agent.exe", "stores": ["chrome"] }`. Leave out
  `stores` to trust the image for every store. The same permission rule applies.
- `detection.kernelExemptStores`: stores to leave unguarded, by name (`chrome`, `edge`,
  `firefox`, `electrum`, `exodus`, `discord`).

Changes to these reload live: the agent rebuilds the policy and swaps it in whole.

## Limits

- **Trust is by image path.** Code injected into a trusted process inherits its access. The
  guard stops a stealer reading the stores itself; it does not stop one running inside the
  browser.
- **Programs installed per user cannot be trusted.** Discord and Exodus always install per
  user, as Chrome can: anything running as that user could replace them. With blocking on
  they are refused their own stores unless exempted.
- **Electrum is never trusted by default.** Its installer registers no App Paths key and names
  the program `electrum-<version>.exe`, so no owner is found. Exempt the store, or trust the
  program through `detection.kernelTrustedImages` again after each update.
- **Only each owner's main program is trusted.** Helpers are refused while blocking is on:
  Chrome's `setup.exe` during an update or uninstall, Edge's `cookie_exporter.exe` (IE mode),
  Firefox's `pingsender.exe`, Explorer browsing a guarded folder, backup and anti-malware
  scanners. Trust the ones you need through `detection.kernelTrustedImages`. A program
  started through an 8.3 path is not recognised as its trusted self.
- **The policy is built when the agent starts** and when a kernel setting changes. A browser
  installed later is trusted after the next agent restart.
- **Handles and links that predate blocking stay usable.** A handle opened before blocking
  was switched on keeps working, and a hard link made before then, elsewhere on the volume,
  reaches the file under an unguarded name.
- **Administrators are out of scope.** Refusing `fltmc unload` and `fltmc detach` makes the
  obvious one-liner fail; it does not stop an administrator. They can stop the driver's service
  (`sc stop BruceFilter`, a mandatory unload; setting `FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP`
  would refuse that too, at the price of never being able to stop the service), run as SYSTEM
  and switch blocking off through the port, set the service's start type and reboot, load a
  vulnerable signed driver to get kernel access, or read the raw volume (volume opens are not
  filtered). The guard is for code running without administrator rights.
- **A short name given before blocking was on.** Since Windows 10 1903 any program with DELETE
  access may give a folder a short name of its choosing. While blocking is on, setting one on a
  store or a folder above it is refused, like renaming it; one set before then has no `~digit`
  to give it away, so the store opens under a name no fragment matches.
- **The driver outlives the agent with its last policy.** Stopping or killing the agent leaves
  blocking as it was, so `fltmc unload` stays refused afterwards. To replace or remove the
  driver, reset it as SYSTEM with the agent stopped (`BruceLab.exe reset`: blocking off, empty policy; a
  running agent would switch blocking on again), or stop its service, or reboot.
  `lab.ps1 uninstall` stops the agent, resets the driver and then unloads it.
- **Fragments match anywhere in a path.** A copy of a store's folder layout elsewhere, such
  as `Documents\Exodus\exodus.wallet\`, is guarded too.
- **Network volumes are not attached.** A remote host's stores are that host's to guard.
- **An open another filter has already given a handle** cannot be cancelled after the fact;
  such an open stands.
- **A burst of refusals can outrun the reader.** The driver counts what it could not report;
  the agent logs one event per process, operation and path a minute, at most 60 a minute.

## Production

Loading on normal machines needs attestation or WHQL signing through the Microsoft Partner
Center, and a unique altitude from Microsoft: 385201 in the INF is a placeholder. Both are
external processes the code cannot satisfy on its own.

## Files

| File | Contents |
|------|----------|
| `BruceFilter.c` | registration, the create and set-information callbacks, the port |
| `BruceFilterPolicy.c`, `.h` | the decisions, shared with the tests |
| `BruceFilter.h` | the wire protocol, mirrored byte for byte by `Driver/MinifilterClient.cs` |
| `BruceFilter.inf` | Windows 11 24H2 driver-store sections, plus downlevel sections |
| `build.ps1`, `packages.config`, `Directory.Build.props` | the build without the VS component |
| `BruceFilter.vcxproj` | the Visual Studio project |
| `test\PolicyTests.c` | user-mode tests of the decisions |
| `lab\BruceLab.c`, `lab\lab.ps1` | the VM lab: scenario harness and the steps around it |

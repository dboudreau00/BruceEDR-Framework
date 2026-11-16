# Changelog

All notable changes to BruceEDR. This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Allow a program from the Dashboard.** Select a process and press **Allow**: it is no longer
  scored and leaves the list. The button writes a watchlist entry with the new `allow` action,
  by path when only administrators can write to the program's folder, or else by the SHA-256 of
  the file as it is now (allow it again after an update). Undo it on the Watchlist tab. An
  `allow` entry has to name one exact file, a full path with no wildcards or a hash; a name or a
  command line is refused, since any program can take a name. A changed watchlist now reaches
  idle processes too, so an allowed program leaves the list within a couple of seconds, and a
  process that is actually suspended stays listed until it is released.

### Changed

- **Opening another process scores once per target, for three targets at most.** Every event
  scored 25 points, so an antivirus or a network monitor that opens every process with full
  rights reached thousands of points in minutes. Duplicating a handle (how browsers and Electron
  apps run their helpers) no longer counts as injection, except out of LSASS, and a program
  writing into a copy of itself that it started (`chrome.exe` and its renderers) is not scored.
  Writing into a child of another image, the way hollowing starts, still is.
- **Traffic from a flagged process scores once per address, for three addresses at most.** Every
  connection scored 15 points, so a browser that one false positive had flagged climbed with
  every page it loaded.
- **Who signed a program now counts.** A program with a valid signature from any publisher,
  installed where only administrators can write, is not scored for opening other processes, for
  strings in its memory, or for packing and imports in its image. One that is only signed, or
  only installed there, is scored as before. A process Windows runs protected (PPL) is not
  scored at all: only Windows and signed security software can be one, and containment already
  refused it.
- The Dashboard's **SIGNATURE** line (was TRUST) names the signer: "signed by ...", "unsigned"
  or "protected process". It said "unsigned" for every program signed by a publisher outside the
  trusted-publisher list. A process that was running before the agent started now gets its full
  path from the same lookup, so it can be allowed by path.
- The title bar matches the app: its caption, text and border colours on Windows 11, and the
  dark title bar on Windows 10 (20H1 and later).

### Fixed

- Console hosts were flagged for opening their own console's programs. Starts and stops are
  handled ahead of other telemetry, so a `conhost.exe` that served one command had exited before
  its events were scored, and an exited process was never recognised as part of Windows. It is
  now recognised from its own path.
- Words any program that handles text can hold ("exfil", "keylog", "stealer" and a few API
  names) no longer score as memory strings on their own: a stealer-specific string or a YARA rule
  has to be among the hits, or three of the common words together. They were found in git, grep,
  a chat client and an AI coding tool reading this repository.
- An uninitialised data section (`.bss`, which takes no room in the file) was reported as a
  packer's empty section, which put every MinGW build at "packed", git and grep included. Only an
  executable section with no file data counts now.
- `crypto-wallet-file-access` matched any folder named after a wallet, including the wallet
  programs' own install folders. It now matches the folders the wallets keep their data in, and
  never a program file (`.exe`, `.dll`, `.node`, `.pak`, `.asar`).
- The desktop app saved each run even with `telemetry.saveSessions` off, and a run it had just
  saved did not appear in the source picker until **Earlier runs** was pressed.
- The shortcut hint in Settings said `Ctrl+1` to `Ctrl+8`; it is `Ctrl+1` to `Ctrl+0`.

## [3.4.1] - 2026-11-14

The desktop app now shows what a run did, not only what it scored: a process map and a file map
you can read at a glance, Insights charts, and every run saved so it can be opened again. A
program that deletes itself after it ran (a melt) is found and shown.

### Added

- **Process map.** Who started what, as a mind map you can pan, zoom and fold. Anything flagged,
  or that made or removed a file, is lit up. Three layouts: **Outline** (one row per process,
  indented under its parent, readable however deep the chain), **Flow** (left to right) and
  **Radial** (the mind map). A time slider scrubs the tree back to how it looked, with a play
  button; search takes a name, a command line, a path or a pid. Click a process for its command
  line, why it was flagged, what it started and the files it touched.
- **File map.** What was made, run, renamed and deleted, grouped by what happened to it, by program
  or by folder. Melted files drip, files that ran and were then deleted are marked, and a file's
  detail lists who made it, who ran it and who deleted it, with the times. Browser caches and
  other constant churn start hidden.
- **Insights.** Six views of the same run: activity over time, a heatmap by kind of activity,
  process lifetimes, top processes (by files, network or score), what became of the files and
  what kinds there were, and where connections went.
- **Earlier runs.** Each run is saved when monitoring stops (`telemetry.saveSessions`, on by
  default; `telemetry.sessionsPath`; `telemetry.sessionsKept`, default 30). Every screen has a
  source picker for the live run, a saved one, or a file from another machine, and replaying a
  recorded scenario fills the same screens. The files hold command lines and paths, so the folder
  is locked to SYSTEM, Administrators and the account that ran the agent.
- **Delete and rename telemetry.** Two new signal kinds, `FileDelete` and `FileRename`, from the
  kernel file provider (delete, rename, and a file opened delete-on-close) and from the folder
  watcher. The activity model turns them into melts: a program that deleted its own file, a
  file deleted by a program it started, and one that ran and was deleted by anything within ten
  minutes. No shipped rule scores the new kinds yet, so a melt is shown, not blocked; a rule can
  match on them (`kind`, `filePath`). Checked live in a Windows 11 22H2 lab VM: a copy of a
  program run from Temp and deleted by a `cmd.exe` it started was found as a melt, with its
  creator, runner and deleter named, and renames, deletes and a delete-on-close file all
  appeared with their paths. Windows 10 was not run.
- The kernel's file-open events now say when the open is of a directory (`detail` `dir`). The
  activity model ignores those, so folders a program lists are not listed as files. A temp file
  one process makes and removes within two seconds, of a kind nobody runs or reads, starts hidden
  as churn, as does the probe file PowerShell writes at every start.
- **`melted-dropper` replay scenario**: a script on a mounted disk image drops a payload, which
  calls out and drops a second program that persists, reads the browser's logins, stages an
  archive, renames the user's documents and uploads; the payload is then removed by a
  `cmd.exe` it started, a third program deletes itself on close, and an installer is deleted
  after it ran. Synthesised, with documentation-only addresses.
- A grouped sidebar (Investigate, Monitor, Network, Configure) with section headings and a
  count on each entry that has something to look at. `Ctrl+1` to `Ctrl+0` switch screens and
  `Ctrl+,` opens Settings.

### Changed

- The set-up screen has an **Earlier runs** button, so a saved run can be opened without
  starting anything.
- Search boxes showed no text while typing (the text area had no height left in a 30 px box);
  fixed for every search box in the app.
- Chart axes step in whole numbers, and the donut legend has room between its entries.

## [3.4.0] - 2026-11-14

The kernel minifilter, finished: trusted programs, renames and links, a process guard that keeps
other programs out of a trusted one, and refusals the agent can see. Enforce mode no longer
touches the processes Windows needs to keep running. The driver passed its 49 lab scenarios and
two unload checks in Windows 10 21H2 (under Driver Verifier) and Windows 11 22H2 VMs, and the
agent service drove it end to end in both; it is signed with a lab certificate only, so
production still needs a Microsoft-signed build.

### Changed - read before upgrading

- **Containment refuses Windows' own processes.** Automatic and analyst suspend, firewall block
  and kill now refuse pid 0 and 4, the agent itself, any process running protected (PPL, which
  only Windows and signed antivirus engines can do), the Windows processes the watchlist already
  protects, and the programs on the new safe-process lists. A name or list entry counts only for
  the real file (its folder only administrators can write) and for the instance Windows started:
  svchost when the protected services.exe started it, the rest under a service account. A copy a
  user starts, and could hollow out, is contained as before; the user's own shell programs
  (explorer, sihost and the like) are the exception, refused by name and path. The verdict is
  still recorded and triage and the webhook still run; the log says what was refused and why. In
  two lab VMs, enforce mode suspended csrss, svchost and the Defender engine within minutes,
  after which no program could start; with the guard, both ran 25 minutes in enforce mode
  without a hang.
- **The driver and the agent speak protocol 2.** The agent refuses an older `BruceFilter.sys`
  (logged, enforcement unavailable) rather than switch on a driver that denies every process.
  Build and install the driver from this release.
- **The agent connects only as the service.** The driver's port now admits LocalSystem alone;
  the console run as an administrator logs that it was refused.
- **The kernel guards eight named stores** (`chrome`, `edge`, `firefox`, `electrum`, `exodus`,
  `discord`, `discordptb`, `discordcanary`), each by the store's own folder; Discord's PTB and
  Canary builds keep their tokens in folders of their own. `\exodus\` matched Exodus's install
  directory and would have kept the wallet from starting; it is now `\exodus\exodus.wallet\`.
  `\discord\leveldb\` matched nothing Discord writes; it is now `\discord\local storage\leveldb\`.

### Added

- **Safe-process lists** (`safe-processes\*.json`, `response.safeProcessesPath`): programs
  containment leaves alone while detection still reports them, by full image path, never by name.
  A list file a standard user could edit is not loaded, and script hosts such as `powershell.exe`
  and `rundll32.exe` are refused outright. The shipped lists cover WMI, Windows Search, Optimize
  Drives, the UAC prompt, VMware Tools, Hyper-V management and the WSL service.
- **Trusted programs.** Each store's owner is trusted for that store when HKLM App Paths or its
  machine-wide install folder (Edge registers no App Paths key on some builds) places it where
  only SYSTEM, Administrators or TrustedInstaller can change the file or the folders above it.
  `detection.kernelTrustedImages` adds programs, for chosen stores or all of them, under the
  same rule; `detection.kernelExemptStores` leaves stores unguarded. Both reload live,
  and the log names every store left with nothing trusted.
- **Renames and hard links** onto a guarded store are refused, and so is renaming the store's
  folder or a folder above it.
- **The agent notices when the driver goes away.** If BruceFilter is unloaded, detached or its
  port closes, the agent logs a WARN system event that kernel enforcement is off and why, then
  reconnects (5 s, doubling to 5 min) and pushes the policy and blocking state again, instead
  of going quiet.
- **While blocking is on, `fltmc unload` and `fltmc detach` are refused** (`STATUS_FLT_DO_NOT_DETACH`).
  A service stop still unloads it, and an administrator can still switch blocking off as SYSTEM;
  `lab.ps1 uninstall` now resets the driver first.
- **The process guard.** While blocking is on, a program not trusted for a store can no longer
  reach into one that is: a handle to a trusted process, or to one of its threads, loses the
  rights to write its memory, create threads in it, copy its handles, set its information,
  suspend it and set a thread's context. Termination, memory reads and queries stay. System,
  protected processes, the agent and the program that started the trusted one keep every right;
  without that last exemption Explorer and Task Scheduler could not start a trusted program. A
  program that starts the browser itself can still write into it before it runs
  (`kernel/BruceFilter/docs/process-guard.md`, residual 1). Each restriction is an ACTION event;
  it is not scored, since debuggers and task managers ask for the same rights. The driver is now
  linked with `/INTEGRITYCHECK`, which these callbacks require, and `build.ps1` fails a build in
  which a Filter Manager release is compiled as a tail call: Driver Verifier reads that as a
  leak, which stopped a lab VM twice during development.
- **Every refusal is an event**: ACTION, with the process, its image, the store and the path, at
  most once a minute per process, operation and path.
- **A refusal is also detection evidence.** Each store refusal reaches the detection engine as a
  `KernelRefusal` signal (one per process and store a minute), so a stealer the kernel kept out is
  scored (+40 per guarded store, T1555.003 / T1539 for browsers, T1555 / T1005 for wallets, T1539 /
  T1552.001 for Discord), correlated with a staged archive like a credential read, and contained
  by the playbook in enforce mode. It is never excused by process name: the kernel judged the
  image path. A refusal for a name the driver could not resolve scores +10. Monitor mode scores
  and records the incident and contains nothing.
- `kernel/BruceFilter/build.ps1` builds the driver from the WDK NuGet packages, without the WDK
  installer: compile at `/W4 /WX`, driver code analysis, InfVerif, Inf2Cat, and user-mode tests
  of the decision code the driver runs (340 checks). A `driver` CI workflow runs it.
- **A VM lab for the driver** (`kernel/BruceFilter/lab`). `lab.ps1 prepare` signs and stages a
  package with a lab certificate; in a test VM, `testsigning`, `install` and `test` load the
  driver and run 49 scenarios through it as SYSTEM, from a trusted and an untrusted copy of one
  program: opens, streams, junctions, symlinks, 8.3 and custom short names, opens by file id
  (including the recheck after the open), copies, deletes, links and renames, a shadow copy and
  SMB loopback, starting the trusted copy and reaching into a running one, each refusal checked
  against the exact operation the driver reports. Two more checks confirm `fltmc unload` and
  `fltmc detach` are refused. Driver Verifier and an end-to-end run with the agent service are
  one command each.

### Fixed

- **A name the driver cannot read no longer means allow.** Opens are decided on the opened
  name, 8.3 aliases are expanded, and an open by file id is checked again once the file is
  open, and cancelled if it is guarded. A name unresolved even then is refused unless the
  program is trusted for every store.
- The guarded folder itself was open to everyone, so it could be listed, or moved away with
  everything in it. It is guarded too now, whatever stream (`Exodus::$INDEX_ALLOCATION`) or
  trailing separator the open names it with.
- The INF had a made-up class GUID and failed InfVerif. It now follows Microsoft's minifilter
  layout: the driver store on Windows 11 24H2 and later, the old layout before.
- **A stream on a folder inside the path hid the store** (found in review). NTFS opens
  `...\Exodus::$INDEX_ALLOCATION\exodus.wallet\seed.seco` and `...\Exodus:$I30\...`, and only a
  stream on the last component was stripped, so the fragment never matched. Fragments are now
  matched component by component, each name ending at its first colon.
- **A short name hid the store** (found in review). Since Windows 10 1903 any program with DELETE
  access may give a folder a short name of its choosing, and one without `~digit` was never
  expanded: `...\Google\CH\User Data\` no longer carried the Chrome fragment. Setting a short name
  on a store or a folder above it is now refused like renaming it. A short name given before
  blocking was switched on still hides the store; see the driver README's limits.
- **Blocking was off for a moment on every policy change** (found in review). A commit copied the
  whole staged policy, whose blocking flag is off, over the live one and then switched the flag
  back, while every open read that flag without a lock. A commit no longer writes it.
- **Refusal reports were lost in bursts.** The driver drops a report that finds no read waiting,
  and the agent and the lab harness kept one. Both keep eight now: in the lab VMs the harness
  received every report (22 of 22 under Driver Verifier, 28 of 28 on Windows 11) where up to a
  third had been lost.
- **Processes that started before the agent had no name** in events and incidents (csrss and
  svchost showed as ""), so name watchlist entries and the pid-reuse check passed them by. Each
  is named from its pid on its first event.
- **Reading another process scored as injection.** The cross-process rule (+25 per target,
  T1055) counted read-only masks such as `0x410` and `GENERIC_READ`, so WMI, Defrag and VMware
  Tools reached quarantine on a clean lab VM by looking at three processes. It now counts only
  rights that change the target (thread creation, memory writes, handle duplication, DACL or
  owner changes, `MAXIMUM_ALLOWED` and the wide grants). Reading LSASS still scores 60, apart
  from the two readers named in the next entry.
- **Windows' own processes no longer reach quarantine on a clean machine.** In enforce mode the
  guard kept csrss, svchost and the antivirus alive, but the verdicts were still false and the
  processes outside the guard (WmiPrvSE, conhost, Widgets) were suspended. The causes, each fixed
  at its source:
  - **Verified Windows components** (`Security/PlatformImages.cs`). A process counts as one when
    its image is the component's own file in the component's own folder and no account other than
    SYSTEM, Administrators or TrustedInstaller can write it or anything above it, and the
    process is the instance Windows started (a service under a service account, svchost started
    by services.exe), since any user can start such a file and hollow it out; the name alone
    counts for nothing. The cross-process rule does not score such a process (csrss opens every
    new process with full rights, svchost and lsass duplicate handles, conhost asks for
    `MAXIMUM_ALLOWED`, the System process is pid 4), and the genuine WMI provider host and
    Defender engine (MsMpEng, NisSrv) are not scored for reading LSASS with a read mask. Writing
    to LSASS, or any other process, is scored whoever asks. Rule packs reach the same check
    through the new `platform` field. The table holds services of the system only; powershell,
    cmd, rundll32, mshta and the other programs that run whatever they are given are not in it.
  - **Process names lost their extension.** The registry and process-access monitors report
    `svchost`, the kernel and the rule packs say `svchost.exe`, and the last signal to arrive
    decided whether any exclusion by name held. Names are normalised on entry.
  - **Opening a Run key scored as persistence.** `RegCreateKeyEx` opens an existing key, so
    sihost and the driver installer "created" `Run`, `RunOnce` and `RunNotification` (the
    builtin rule matched any key that starts with `Run`). Only a value written into a Run,
    RunOnce, RunOnceEx or RunServices key scores now, in the builtin rule and in both pack rules.
  - **Opening a folder scored as a drop.** The Startup folder itself, and the Tasks folder when
    the Windows Search indexer or the Task Scheduler's svchost reads it, no longer match
    `startup-folder-drop` and `scheduled-task-xml-drop`; a file inside them still does.
  - **WebView2.** The genuine runtime reading its host's cookies and Local State under an
    `EBWebView` folder (Widgets, Search and the Start menu on Windows 11) is not scored.
  - **The memory scan matched the operating system.** `SetWindowsHookEx`, `GetAsyncKeyState` and
    `keybd_event` are exports of user32.dll, so every process with a window held them in
    unmodified image pages, and any process another rule had scored 20 gained +40. The scan now
    skips image pages that have not been written and files mapped read-only. Hits are written to
    the incident text defanged (`s[t]ealer`): the log held the very strings the scanner looks
    for, so every reader of it (VMware Tools copying it out of a guest, the desktop app, a
    shell) was flagged in turn.
  - **The agent no longer scores itself.** Its triage files in `Windows\Temp` and the IOC list in
    its own memory scored the agent as a staging, stealing process.
- **Reload from disk could crash the desktop app.** In Settings and Watchlist it read the config
  file without catching a syntax error, so a bad edit on disk threw on the UI thread. It now says
  "Reload failed" with the reason, and "Reloaded from disk." when it worked.
- **The set-up screen saved thresholds Settings would refuse.** Warn at must be 1 to 99 and
  contain at above it and at most 100; the set-up screen now checks before it saves or asks
  about enforce mode, and shows its errors in the error colour.
- **Settings checks the syslog port and the webhook URL** when those outputs are on: a port from
  1 to 65535, and a full `http://` or `https://` address.
- Settings: a failed firewall-rule cleanup shows in the error colour; Open app log and Open config
  file say when the file does not exist yet instead of doing nothing; removing the assistant key
  says so when the key is still there; the save message names kernel blocking among the settings
  that apply live.
- The desktop app says "Event copied." or that the clipboard is busy, as the other copy commands
  do, and shows refusals ("Could not...", "Actions are off...") in the error style.
- **Deleting an incident or clearing the history** no longer crashes on a storage error, and no
  longer empties the list as if it had worked: it says the delete failed and keeps the list.
- The console's `surface` takes `surface pid:1234` as its help says, and rejects an invalid pid
  instead of listing every endpoint; `vault restore` accepts a quoted destination path.

## [3.3.0] - 2026-11-14

A UX pass over the desktop app, Incident triage, and two fixes in the engine.

### Fixed

- **Analyst Suspend, Resume and End now check the process name before acting.** Automatic
  containment already refused a pid that had been reused; the analyst path (desktop app,
  console and control API) acted on the bare pid. A row that outlived its process could end
  whatever had taken the pid since. Host-level tests cover it against a real child process.
- **Telemetry queued behind a process's stop is scored on that process.** Starts and
  stops are applied ahead of queued telemetry, so under load a stop could overtake the
  process's last events, which then opened a fresh profile under the same pid and split the
  evidence: a burst of the infostealer trace left powershell.exe at 575 without its
  start-time reasons, against 765 in order. Events stamped at or before the stop now reach
  the exited process, even after a new process has taken the pid; newer ones still start
  clean. A verdict on an exited process is recorded but contains nothing, and takes no
  signature discount from the pid's new owner.
- Scores are not capped at 100, so the detail panel no longer shows "765 / 100".
- Row severity follows the configured contain threshold instead of a fixed 70.
- Tooltips, context menus and the watchlist pickers were stock light controls on the dark
  theme; the pickers' selected value was close to unreadable.
- API surface had no column headers; its endpoint count was the display cap, not the total.
- Settings refuses warn and contain thresholds the config would silently clamp, and says why.
  It also lists the correct shortcuts (Ctrl+1 to Ctrl+8).
- Event counts, the status bar and the coverage view reset properly between sessions.
- `publish-release.ps1` fails if the zip has backslash entry names. Under Windows PowerShell 5.1
  the .NET Framework zip API still writes them, so run the script under PowerShell 7 (`pwsh`).

### Added

- **Incident triage**, first in the sidebar. Every detection, live or replayed, is kept in a
  library (the latest 100). Pick one and a log line, and the attack plays back as a scene on a
  mind map: the process in the middle, its ATT&CK stages around it, each step lighting up in
  order while a model explains it in plain English. The reader sets the tone: Teacher, SOC
  analyst, Network security engineer, Executive or Mom. One answer is generated per detection
  and reader and kept; Refresh asks again.
- **Assistant**, folded away at the very end of Settings: an API key for Claude, Gemini, Grok or
  OpenAI, encrypted with Windows DPAPI for the current account. Requests go only to the chosen
  provider's fixed endpoint over HTTPS, through the agent's single HTTP client (same DNS pinning
  and TLS checks, redirects refused). User names, the machine name, secrets and long encoded
  blobs are removed first (on by default), and log text cannot close the evidence block it is
  quoted in.
- **Replay a recorded attack** from the set-up screen: a shipped trace plays through a real host
  in about twenty seconds, with no monitors, monitor mode forced, auto-kill off, no memory or
  image scanning, and analyst actions disabled. A banner and a REPLAY badge say so throughout.
- Dashboard: an activity timeline by severity, sparklines, a score ring with the warn and
  contain thresholds marked, the process lineage as a chain, and named ATT&CK chips that open
  the MITRE page.
- Coverage: a matrix of every catalogued ATT&CK technique by tactic, shaded by rule count, with
  techniques seen on this host in red and gaps left dark. The list view is still there.
- Network map: Miller projection instead of a stretched plate carree, glowing markers, country
  labels, a pulse on threat markers, and arcs from the country of the Windows region setting.
- Sidebar icons with live badges, a status card, toasts for action results and view transitions.
- A save bar pinned to the bottom of Settings.
- A two-column set-up screen.

## [3.2.0] - 2026-10-08

BruceEDR no longer goes live by accident. Double-clicking the agent used to start a live
console session that scored, suspended and firewall-blocked real processes on a workstation
straight away. Now nothing is monitored until someone presses Start, and even then the default
is to watch and report, not to act.

### Changed - read before upgrading

- **Monitor mode is the default.** New `response.mode`: `monitor` detects, scores and logs, and
  for every verdict logs what enforce mode would have run (`monitor mode, nothing done; enforce
  would run ...`). It never suspends, firewall-blocks, quarantines, kills or isolates on its own.
  `enforce` runs the playbook as before. Anything other than an explicit `enforce` is treated as
  monitor, and the setting reloads live. **A config without the key now runs in monitor mode:
  set `"mode": "enforce"` to keep automatic containment.** Actions an analyst takes by hand are
  unaffected.
- **Double-clicking `BruceEDR.exe` opens the desktop app instead of starting the agent.** The
  live console agent is opt-in with `--console`. The Windows service is unaffected.
- **The desktop app opens on a set-up screen** (response mode, trusted publishers, scores) and
  builds nothing until **Start**. **Stop monitoring** in the status bar returns to set-up. A
  config that exists but cannot be parsed is reported and blocks Start, as the console refuses
  to start on it.
- **Release layout:** `BruceEDR.Gui.exe` now sits next to `BruceEDR.exe`. In the old `gui\`
  subfolder the app looked for a `bruce.config.json` that was not there and silently ran on
  built-in defaults with no rule packs.

### Added

- **MSI installer** (`BruceEDR-v3.2.0-win-x64.msi`, WiX 5, `installer/`): installs to
  `C:\Program Files\BruceEDR` with Start Menu and desktop shortcuts to the desktop app. It never
  installs or starts the service. The folder is fixed on purpose (the uninstall clean-up runs
  `BruceEDR.exe` as SYSTEM, so it must live where only administrators can write). Your edited
  config survives upgrades. Any removal, upgrade included, first removes the service and its
  watchdog task if you installed them, so reinstall the service after an upgrade. A full
  uninstall also removes every BruceEDR firewall block, and leaves config, logs and quarantine.
- **`BruceEDR.exe --cleanup`** and **Settings > Remove rules**: remove every Windows Firewall
  rule BruceEDR created, and lift host isolation if BruceEDR applied it. Outbound blocks are
  keyed to an image path and outlive the agent, so an app could stay offline after a
  containment.
- Status-bar badge for the live mode (MONITOR ONLY or ENFORCING); in monitor mode the dashboard
  and threat table say *would contain* rather than *contained*.
- One product version for every assembly (`Directory.Build.props`); the sidebar shows it
  instead of a hard-coded `v1.0`. `publish-release.ps1` reads it when `-Version` is omitted and
  builds the zip and the MSI from one staged folder that has passed the self-test.

### Fixed

- **The packaged desktop app could not start.** Single-file publish leaves WPF's native DLLs
  (`wpfgfx_cor3.dll`, `PresentationNative_cor3.dll`, ...) beside the exe, and the release
  script only ever copied the exe, so the 3.0.0 to 3.1.1 zips shipped a GUI without them. They
  are now staged next to it, and both the release script and the MSI build refuse to package
  without them.
- **Watchlist convictions were missing from the threat table.** The "all flagged" list filtered
  on score, and a watchlist conviction is contained at score 0, so the desktop app's table and
  `list all` never showed the processes an operator had named.
- **A process whose suspend failed was retried on every signal.** Each retry re-ran the firewall
  step (two netsh spawns) and printed a fresh QUARANTINE. Now one attempt per incident per minute.
- **Stopping or closing left suspended processes frozen**, with nothing left to release them.
  Stop and close now offer to resume them (and lift their firewall blocks) first.
- **Switching monitor to enforce never contained processes monitor mode had flagged**: their
  verdict had already set the one-shot gate. Monitor-mode verdicts are recorded as *would
  contain* and re-armed on the switch, so the next thing such a process does is contained.
- The tray no longer says "monitoring" while nothing runs, the dashboard is neutral (not the
  green of "all clear") while stopped, the overlay keeps keyboard and screen readers out of the
  tabs underneath, Start no longer blocks the window, and the status bar fits the minimum width.
- Monitor mode keeps the kernel driver non-blocking even with `kernelBlocking` set, and a reload
  applies the response mode, playbook isolation and kernel blocking before anything that can fail.
- `--uninstall` ends the watchdog task before removing the service, waits for it to stop, and no
  longer fails on a broken config. The clean-up never resets the firewall policy unless a marker
  written by isolation proves BruceEDR changed it: hosts that block outbound by design are left
  alone.
- **A click in the console could freeze the agent.** With QuickEdit on, a selection blocks
  every console write, and the agent writes while holding the lock its detection thread also
  needs. Console mode now turns QuickEdit off and restores it on exit.
- **Console floods.** The console echo is capped at 40 lines a second with a summary of what was
  held back. QUARANTINE and error lines always print, redirected output is never limited, and
  the log sinks still receive every event.
- The MSI build in `publish-release.ps1` always rebuilds and re-validates, so a re-run after a
  failed validation cannot report a stale installer as built.

## [3.1.1] - 2026-10-06

A small follow-up to 3.1.0: one behaviour change you need to know about, a few hardening
fixes from an external review, and CI.

### Changed - read before upgrading

- **Playbook `IsolateHost` is now opt-in.** A playbook that orders `IsolateHost` is skipped,
  with a logged reason, unless `response.allowPlaybookIsolation` is `true` (default
  `false`). Having the action in a JSON file was enough to cut a host off the network, which is
  how a mis-copied playbook locks a fleet out of RDP and WinRM. The shipped default playbook
  never orders it, and the console `isolate` command is unchanged (it still asks you to type
  `yes`). Empty allowlists are still refused by the isolation primitive whatever this flag says.
  If you rely on playbook isolation, fill in `response.isolationAllowlist` first, then set the
  flag. It reloads live, and the reload says so in the log.

### Fixed

- **Control API bearer check** hashes both sides with SHA-256 before the constant-time compare,
  so the compare always sees equal-length inputs and the token length is no longer observable
  through an early return. Wrong-length bearers (short, long, and 10 KB) are pinned to a clean
  401.
- **API Studio `api send` is now paced.** The console built a new client for every send, and the
  rate limit lives on the client, so interactive sends were never throttled. One client is now
  shared for the console session and rebuilt when a reload swaps the safety policy.

### Added

- A startup log line when `allowlist.checkRevocation` is false (the default), and README and
  XML-doc guidance: for production turn revocation on, or pin thumbprints and set
  `allowSubjectMatch` to false.
- `.github/workflows/verify.yml`: runs `tools/verify.ps1` (build, tests, rule validation, scenario
  replay) on `windows-latest` for pushes to main and pull requests.
- Host-level tests that build the real composition and prove the isolation gate and the
  revocation notice, rather than only pinning config defaults. The gate test was
  mutation-checked: with the gate disabled it fails.

## [3.1.0] — 2026-09-09

A hardening release driven by two external reviews of 3.0.0. The headline: **watchlist
containment did not work on a running agent.** The engine issued the verdict; the host
handed it to a playbook that only looks at score and trust, nothing matched at score 0,
and the process the operator had named was never frozen — while its profile sat marked
Contained. The engine-level tests passed; no test crossed the engine/host seam. One does now.

### Fixed — containment

- **Watchlist Quarantine now reaches the containment primitives.** The snapshot carries the
  operator's decision (`ContainmentRequired`), and the host treats it as a floor: Suspend and
  FirewallBlock run regardless of what the playbook selects, and the playbook may still add
  triage, isolation or notification. Covered by host-level tests for both an unsigned and a
  trusted-signed process.
- A containment task dropped by a full response queue no longer leaves the process marked
  Contained; the flag is cleared so fresh evidence re-escalates and containment is retried.
- Suspend and Kill are identity-checked: the pid must still belong to the process named in
  the verdict, so a recycled pid is refused rather than frozen.
- The protected-process guard now covers the shell (`explorer.exe`, `SearchHost.exe`,
  `StartMenuExperienceHost.exe`, `RuntimeBroker.exe`) and the security stack (`MsMpEng.exe`,
  `NisSrv.exe`, `SecurityHealthService.exe`, `MsSense.exe`, `SgrmBroker.exe`).

### Fixed — detection

- **LSASS rules could not see LSASS.** The ProcessAccess monitor emitted only the access mask;
  the target's name was never resolved, so both the builtin and the JSON credential-dump rules
  scored a generic cross-process open. The engine now resolves the target pid (process tree,
  then a live lookup for processes older than the agent) and writes it into `detail` as
  `open-process:lsass.exe:PROCESS_VM_READ|...`, which is what the shipped rules match.
- **`MAXIMUM_ALLOWED` / `GENERIC_*` opens were emitted and then discarded** by the builtin
  rule. They are now scored, and the rule engine expands them to the rights they imply, so
  `desiredAccess in ["PROCESS_VM_READ"]` fires for the documented evasion.
- **Live pid lifecycle.** ETW now subscribes `ProcessStop` (WMI watches deletions too);
  start/stop travel on their own queue drained ahead of file telemetry, so a create flood
  cannot drop the one event that is the PID-reuse barrier. A stop older than the current
  tenant's start is ignored; an exited profile is never built on again.
- **Image paths on the primary source.** Kernel `ProcessStart` carries only a basename; the
  full path is now promoted from the main image's `ImageLoad`, so path and hash watchlist
  entries work on live ETW data instead of only in replay.
- The image-hash cache opens files with `FileShare.ReadWrite | Delete` (it could not hash a
  running image before), never caches a failed read, and keys on length + mtime so a
  replaced binary is re-hashed.
- Off-thread results (memory scan, PE analysis) carry the profile generation they were
  claimed under and are discarded after pid reuse.
- Negative rule scores are now a persistent allowance: the credit past zero is banked and
  absorbs later points, instead of being clamped away by the first positive score.
- An unattributed staged archive charges the likeliest author, not every flagged process.
- `imagePath` / `commandLine` rule fields fall back to the profile for signal kinds that do
  not carry them (same fix `processName` already had).
- A signature check that threw is retried rather than recorded as untrusted forever.
- Rule-evaluation budget exhaustion is alerted (rate-limited), not just counted.
- `IsRoutableRemote` classifies IPv4-mapped IPv6, CGNAT, 0/8 and multicast as internal.

### Fixed — secrets and files

- **The generated control-plane token was written to every telemetry sink** (incidents.jsonl,
  the audit chain, syslog, webhook, the `/events` buffer). It now goes to
  `%ProgramData%\BruceEDR\control.token` with a SYSTEM + Administrators DACL, and to the
  console only when a person is at it.
- The vault key, audit key, triage packages, and plain-moved quarantine samples are created
  with inheritance disabled (SYSTEM + Administrators) instead of the directory's inherited
  permissions. Plain-moved samples also get a `.quarantined` suffix.
- Deleting the audit `.anchor` sidecar no longer heals a truncation: a missing anchor over a
  populated log is an integrity failure, and no replacement anchor is written until an
  operator runs `audit ack`. The audit key is created first-writer-wins like the vault key.
- API Studio file bodies are confined to `api.studio.fileBodyRoot` (empty = disabled): UNC
  and device paths are refused before the path is touched, and reparse points anywhere
  under the root are refused.
- API Studio pins DNS: after the host allowlist passes, the resolved addresses are checked
  and internal, link-local, loopback and metadata space are refused unless the address itself
  is allowlisted.
- `--install` refuses to register a SYSTEM service from a user-writable location and pins
  `--config` on both the service binPath and the watchdog task.
- A malformed `bruce.config.json` refuses to start instead of silently starting on factory
  defaults; a missing file is still a first run. The watchdog keeps its lenient mode.
- The control plane (`api.control.*`) hot-reloads, so disabling HTTP process actions takes
  effect on reload rather than at the next restart. An IPv6 listen address is bracketed.
- Isolation refuses whole-space and inverted address ranges (`0.0.0.0-255.255.255.255`).
- The webhook sink no longer follows redirects. URL redaction masks a bare token in userinfo.
- Vault entry ids are validated before they name a blob path.
- IOC feeds refuse `/0` prefixes. Watchlist breadth checks refuse `*exe`, bare words as
  path fragments, and two-character command-line fragments; switch-style command-line
  entries match on token boundaries. The GUI confirm names each contain-on-sight entry with
  its match kind.
- The minifilter receives directory prefixes only, not bare artifact names; over-long
  fragments are refused rather than truncated. The memory walker only reads pages whose
  protection actually grants read. Secret scanning recognises `github_pat_`, `sk-`/`sk-proj-`
  and `glpat-` tokens. ETW pump death is retried with backoff; watcher overflow says what was lost.
- Incident ids use the `BR-` prefix. Playbook `requiredTechniques` match sub-techniques.

### Removed

- `allowlist.requireValidChain`. It was never honoured — trust has always required a valid
  chain — so it was removed rather than left as a knob that appeared to do something. Old
  configs that still carry it load unchanged.

## [3.0.0] — 2026-08-26

Renamed to **BruceEDR**, plus operator-authored detections, an offline network map,
and a rebuilt desktop UI.

### Breaking

- **The project is renamed.** Namespaces (`ProcessShield.*` → `BruceEDR.*`), assemblies,
  the solution and project files, and the minifilter (`ShieldFilter` → `BruceFilter`).
- **The config file is now `bruce.config.json`** (was `shield.config.json`). Rename your
  existing file; the schema is unchanged apart from the additions below.
- **Prometheus metrics use the `bruceedr_` prefix** (was `processshield_`). Update any
  dashboards or alert rules that match on the old names.
- **Default service and ETW session names follow the product name**, and per-user state
  moves to `%LOCALAPPDATA%\BruceEDR`.

### Added

- **Watchlist** — name a process, path, SHA-256 or command line and contain it on sight,
  warn, or score it. A `quarantine` entry deliberately outranks a valid Authenticode
  signature; entries resolving to protected Windows processes are reported but never
  contained. Hot-reloaded, with a GUI editor.
- **Network map** — every observed destination plotted by country, hover-linked to the
  endpoint list, with plaintext HTTP called out. Geolocation is fully offline (RIR
  delegation data at /16 resolution); nothing is asked of a third party.
- **Desktop UI rebuilt** — new theme, live telemetry status bar, filterable event feed with
  CSV/JSON export, ATT&CK coverage grouped by tactic, incident reports to the clipboard,
  tray monitoring, and persisted window state.
- `BruceHost.StatsSnapshot()` for structured counters.

### Fixed

Twelve defects found by an adversarial review of the new code, several of them fail-open
in the containment path:

- Watchlist hot reload never reached an already-running process: a per-process identity
  fingerprint short-circuited before the new list was consulted, so adding an entry for
  something you could see running did nothing until a restart.
- Removing or disabling an entry left the conviction latched, because the forced verdict
  was never cleared.
- SHA-256 entries were inert whenever `intel.enabled` was false — the hasher was wired
  behind that flag while the log still reported the entry as armed.
- A `warn` entry silently added its default 50 points and could tip a process into
  containment the operator never asked for. Only `score` entries contribute points now.
- The protected-process guard could not see `System`, `Registry`, `Idle` or
  `MemCompression`, so a containment entry naming them would not have been downgraded.
- `watchlist.alertOnEveryHit` was ignored on reload and missing from the restart-required
  report; it now rides on the compiled list and reloads with it.
- The Settings and Watchlist editors each wrote a whole stale config snapshot, silently
  reverting each other's saves.
- Saving the watchlist dropped the ATT&CK techniques of every entry.
- `IsPrivate` missed IPv6 unique-local (`fc00::/7`) and IPv4-mapped private space, which
  would have plotted internal hosts on a world map.
- The endpoint header counted every endpoint while the map and table showed only the
  first 300; the cap is now reported rather than silent.
- Row hover was dead in four list views (an inline `Background` outranks a style trigger).
- The release package shipped the map feature without its data.

## [2.0.0] — 2026-08-11

The framework release. v1 was a behavioural agent with hardcoded detections; v2 turns it
into something you can extend, integrate and regression-test without touching C#.

Source grew from roughly 5,000 to roughly 28,500 lines, alongside 15,000 lines of tests.

### Added

**Detection content is now data, not code**
- JSON detection rule engine, Sigma-inspired: 14 operators, 25 matchable fields, AND/OR/NOT
  clauses, compiled regexes with a 250 ms match timeout, and per-rule ATT&CK technique ids.
- 72 shipped rules across 5 packs covering LOLBin abuse, credential access, persistence,
  command-and-control and exfiltration. Hot-reloadable — edit the JSON, type `reload`.
- Negative scores act as allowlist rules, so tuning suppresses noise without hiding evidence.
- Rule authoring guide at `rules/detection/README.md`.
- MITRE ATT&CK catalogue; every alert now carries technique ids, and coverage is visible from
  the console (`attack`) and a new GUI tab.

**Offline detection testing**
- `--selftest` validates every rule pack and replays every scenario through a real engine on a
  simulated clock. No admin, no malware, runs in under a second.
- JSON-Lines trace format plus three shipped scenarios, one of which is a benign
  developer-workstation trace that exists purely as a false-positive regression guard.
- `tools/verify.ps1` — build, tests, rule validation and replay in one command.

**New telemetry sources**
- Separate user-mode ETW sessions for DNS queries, AMSI script content, registry writes and
  cross-process handle access. Each degrades independently rather than taking the agent down.

**Behavioural analytics**
- C2 beacon detection using median inter-arrival time and median absolute deviation, so
  jittered beacons are still caught.
- DGA and DNS-tunnelling scoring.
- Process lineage tracking, hardened against PID reuse and hostile parent cycles.
- Score decay, so a long-lived process cannot trip a threshold on accumulated noise.

**Response**
- AES-256-GCM encrypted quarantine vault with a manifest, integrity verification and restore.
  A quarantined payload is no longer a runnable file sitting in a folder.
- Config-driven response playbooks.
- Host network isolation with an allowlist, and forensic triage package collection.

**Integration**
- Elastic Common Schema, OCSF 1.1 and CEF output formats, so an existing SIEM ingests
  BruceEDR without a custom parser.
- Prometheus metrics.
- Localhost-only REST control plane with bearer auth — disabled by default, read-only by
  default, and refuses to bind to a non-loopback address.

**Analysis and intel**
- Dependency-free PE reader: sections, entropy, imphash, packer indicators, suspicious imports.
  Bounds-checked at every offset, because it gets pointed at hostile files.
- Indicator feeds: SHA-256/MD5/domain/IPv4/IPv6/CIDR/URL, matched via hash sets.
- Secret scanner with entropy gating.

**API Studio**
- Imports Postman v2.1, OpenAPI 3, Swagger 2, HAR and curl.
- Sends requests, evaluates assertions, and chains captured values between requests.
- Passively grades responses for TLS, security headers, CORS, cookie flags, leaked secrets and
  PII, mapped to the OWASP API Security Top 10.
- Exports to Postman, OpenAPI, `.http`, curl and Markdown; reports to JSON, JUnit, HTML.
- Builds a collection directly from the endpoints the agent *observed* processes contacting.
- Locked down by default: no host is reachable until allowlisted, state-changing verbs and
  plain HTTP are refused, requests are rate-limited and responses size-capped.

### Changed

- Containment now publishes incident updates. Previously every piece of evidence observed
  *after* a process was contained was discarded, so an incident could be recorded as "encoded
  PowerShell" when it was actually credential theft followed by staging and exfiltration.
  New ATT&CK techniques on a contained process now raise a bounded, log-only update.
- `amsi-bypass-attempt` and `lsass-handle-with-vm-read` scored high enough to quarantine
  unaided. Both document false positives including Microsoft Defender, Windows Error Reporting
  and Task Manager — at that score a default install would suspend the user's antivirus. Both
  lowered so they require corroboration; a test pins the only two rules still permitted to
  quarantine on their own.
- Telemetry sinks accept a format, so JSONL, syslog and webhook can emit ECS/OCSF/CEF. The
  audit chain deliberately keeps the native shape, because its HMACs are computed over it.
- Quarantine moves files into the encrypted vault when enabled, falling back to the previous
  plain move otherwise.

### Fixed

- **The published repository contained `audit.log.key`** — the per-install secret that keys the
  tamper-evident audit chain. Anyone with it can re-forge that install's audit log, defeating
  the one guarantee the log exists to provide. Removed and untracked.
- **`tests/Tests.cs` on `main` did not compile.** It constructed `DetectionEngine` with a
  memory scanner as the second argument, but that parameter was removed when scanning moved to
  `BruceHost`. `dotnet test` failed on a clean clone.
- `obj/` build artifacts were committed; now untracked.
- Prometheus `# HELP` text double-escaped backslashes in gauge names.

### Security notes

The encrypted vault carries the same honest caveat as the audit log: the key sits beside the
data, so it defeats accident and opportunism, not an attacker who already holds your privilege
level. Host isolation with an empty allowlist will cut off your own remote session — the
console makes you confirm, a playbook does not.

Unchanged from v1: PPL/ELAM tamper protection and production driver signing remain gated behind
Microsoft vendor programs, and the minifilter is test-signed for lab use only.

### Verified at release

Zero build warnings, 1,969 tests passing, 72 rules loading with no validation errors, and 3 of 3
replay scenarios meeting their expectations. The extended ETW monitors have not been soak-tested
against a live fleet, and neither the GUI nor the live agent was smoke-tested in the build
environment, since both require Administrator rights.

## [1.0.0]

Initial release: ETW/WMI monitoring, exfil-chain scoring, Authenticode trust, suspend-first
containment, hash-chained audit log, Windows Service with watchdog, WPF GUI, kernel minifilter.

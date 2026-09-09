# BruceEDR - Build, Install & Beta-Test Guide

This walks you from source to a running beta, using **Visual Studio 2022**. CLI
equivalents are given where useful. Read section 0 first.

---

## 0. Safety first (read this)

BruceEDR **suspends and can kill processes, adds Windows Firewall rules, and
moves files to quarantine**. Do **not** run it on a machine you care about.

- Use a **disposable Windows 10/11 x64 VM** (Hyper-V, VMware, or VirtualBox).
- Take a **VM snapshot** before you start so you can roll back.
- Keep `autoKill` = `false` (the default) during early testing so contained
  processes are only suspended, not terminated.

---

## 1. Prerequisites

| Need | For |
|------|-----|
| Windows 10/11 x64 (or Server 2019/2022), in a VM | running the agent (ETW + admin) |
| **Visual Studio 2022 17.8+** with the **".NET desktop development"** workload | building the solution |
| .NET 8 SDK | included with that VS workload (or install standalone for CLI) |
| Local **Administrator** rights | ETW kernel session, process access, service control |
| *(optional)* **Windows Driver Kit (WDK)** matching your VS | building the kernel minifilter (section 9) |

Nothing extra is needed for the default build. YARA and the kernel driver are
opt-in (sections 7 and 9).

---

## 2. Get the code onto the VM

1. Copy `BruceEDR.zip` into the VM and unzip it. You'll get a `BruceEDR\`
   folder containing **`BruceEDR.sln`**.
2. Folder map:
   - `BruceEDR.csproj` - the agent (app)
   - `tests\BruceEDR.Tests\` - the xUnit test project
   - `kernel\BruceFilter\` - the C minifilter (built separately with the WDK)
   - `rules\` - sample YARA rules, and `rules\detection\` - the JSON detection packs
   - `Replay\scenarios\` - detection scenarios replayed by `--selftest`
   - `intel\feeds\` - drop your indicator feeds here
   - `tools\simulate-benign-stealer.ps1` - the safe detection demo
   - `tools\verify.ps1` - build + tests + rules + replay in one command
   - `bruce.config.json` - configuration

---

## 3. Build in Visual Studio

1. **Double-click `BruceEDR.sln`** to open it in Visual Studio 2022.
2. Wait for **NuGet restore** (watch the status bar). If it doesn't start
   automatically: right-click the solution in Solution Explorer -> **Restore
   NuGet Packages**. (First restore needs internet: it pulls TraceEvent,
   System.Management, and Microsoft.Extensions.Hosting[.WindowsServices].)
3. In the top toolbar set the two dropdowns to **`Release`** and **`x64`**.
   (Both projects are x64-only; `x64` is the only platform offered.)
4. **Build -> Build Solution** (`Ctrl+Shift+B`). You should get
   **`Build: 2 succeeded, 0 failed`**.

**Output:** `bin\x64\Release\net8.0-windows\BruceEDR.exe` (plus its DLLs).

> CLI equivalent:
> ```
> dotnet build BruceEDR.csproj -c Release
> ```

---

## Desktop GUI (BruceEDR.Gui)

Besides the console, the solution includes a **WPF desktop app** — a dark
instrument-panel dashboard. It shows current posture, a live table of contained and
flagged processes with one-click **Release / Suspend / End process**, a live event
feed, and a Settings editor that writes `bruce.config.json` (threshold and
allowlist changes apply live).

### Watchlist — writing your own detections

The **Watchlist** tab is where you name things you have already decided do not belong on
your estate. Each entry matches on one of four things — process **name**, image **path**,
image **SHA-256**, or a **command-line** fragment (names and paths accept `*`/`?` globs) —
and picks one of three actions:

| Action | What happens |
|---|---|
| `quarantine` | Contained on sight: suspended and network-blocked the moment it appears |
| `warn` | Alert only, no containment |
| `score` | Adds points and lets the normal thresholds decide |

Two things make this more than a blocklist:

- **A `quarantine` entry overrides a trusted signature.** If you name a binary by hand, a
  valid Authenticode chain does not excuse it — that is the whole point of naming it.
- **It cannot be aimed at Windows itself.** Entries resolving to a protected system process
  (`lsass.exe`, `csrss.exe`, `services.exe`, `svchost.exe`, …) are still *reported*, but
  containment is refused, so a typo in a rule cannot bugcheck the host it is defending.

Entries live in `bruce.config.json` under `watchlist` and are **hot-reloaded** — saving in
the GUI arms them within a second or two, no restart. Invalid entries are rejected
individually with the reason, and a pattern that would match everything (`*`, `*.exe`) is
refused outright.

```jsonc
"watchlist": {
  "enabled": true,
  "entries": [
    { "match": "name",    "value": "mimikatz",  "action": "quarantine", "note": "red-team tooling" },
    { "match": "hash",    "value": "<sha256>",  "action": "quarantine", "note": "IOC from IR-2451" },
    { "match": "cmdline", "value": "-enc",      "action": "score", "score": 25 },
    { "match": "path",    "value": "\\appdata\\local\\temp\\", "action": "warn" }
  ]
}
```

### Network map

The **Network map** plots every observed outbound destination on a world map, grouped by
country and sized by connection volume. Hovering a marker highlights its endpoints in the
side list and vice versa; markers are coloured by severity, and a **dashed ring marks a
destination reached over plaintext HTTP**. Traffic that cannot be placed (local network,
IPv6, unallocated space) is counted in a tray rather than silently dropped.

Geolocation is **fully offline** — BruceEDR makes no network call to build this view,
because asking a third party where an address is would tell them exactly which
infrastructure you are investigating. It resolves the country an address block is
*registered* to, at `/16` resolution, so CDNs and anycast land in the wrong place. Read
`intel/geo/README.md` before drawing any conclusion from a marker.

### Analyst conveniences

- **Incident detail** — the selected process shows its ATT&CK technique chips,
  command line, ancestry chain, peak score and reason timeline; **Copy report**
  puts a plain-text hand-off on the clipboard, **Open location** reveals the image
  in Explorer (both also on the row's right-click menu).
- **Live events** — search box, severity filter chips with live counts,
  **Pause/Resume** (buffered while paused), **Export** to CSV/JSON, per-row copy.
- **API surface** — search, an *only beaconing* switch, CSV export.
- **Coverage** — techniques grouped by tactic with per-tactic coverage bars and
  links to each MITRE page.
- **Status bar** — monitor health, signals/sec, processed count, p95 detection
  latency, rules/IOCs loaded, uptime, and a dropped-signal warning when the
  pipeline sheds telemetry.
- **Tray icon** — minimizing keeps monitoring from the notification area and
  containments raise a balloon alert (toggle in Settings → Interface).
- **Quality of life** — window size/position and last tab persist, `F5`
  refreshes, `Ctrl+1…5` switch views.

Build the solution (section 3), then run it either way:
- **Visual Studio:** right-click **BruceEDR.Gui** in Solution Explorer ->
  **Set as Startup Project**, then **Debug -> Start** (F5). It requests administrator
  rights through its manifest, so a UAC prompt appears automatically.
- **Or** run `BruceEDR.Gui.exe` from
  `gui\BruceEDR.Gui\bin\x64\Release\net8.0-windows\`.

It drives the same engine as the console — use whichever you prefer. The
detection walkthrough below works with either front-end.

---

## 4. Run the unit tests

- In VS: **Test -> Run All Tests** (opens Test Explorer). All 2,180 tests should pass.
  They cover the exfil-chain scoring, the JSON rule engine, ATT&CK mapping, beacon and
  DGA analytics, the process tree (including PID reuse and hostile parent cycles), PE
  parsing against malformed files, indicator feeds, the encrypted quarantine vault,
  ECS/OCSF/CEF serialisation, the whole API Studio stack, the audit hash-chain (incl.
  tamper detection), config clamping, the firewall-name sanitizer, the routable-IP check,
  and the pattern matcher.

> CLI equivalent — or just run everything at once:
> ```
> dotnet test tests\BruceEDR.Tests\BruceEDR.Tests.csproj -c Release
> .\tools\verify.ps1        # build + tests + rule validation + scenario replay
> ```

### 4b. The offline self-test (no admin needed)

This is the fastest way to know the detection content is healthy, and it is the loop to
use when writing rules:

```
BruceEDR.exe --selftest
```

It validates every JSON rule pack (reporting rule count and ATT&CK coverage) and replays
every scenario in `Replay\scenarios\` through a real detection engine on a simulated
clock. It starts no monitors and needs no elevation, so it is safe to run anywhere.

---

## 5. Run the agent interactively (the main beta loop)

The agent **requires elevation**. Double-clicking the `.exe` now pops a **UAC
prompt** and relaunches itself elevated (accept it, and an elevated console opens
at the `bruce>` prompt). If anything fails at startup the window stays open with
the error and a "Press Enter to close" pause, so it won't just vanish anymore.

For the cleanest experience, run it from an elevated terminal. Pick one:

**Option A - elevated terminal (recommended, simplest):**
1. Open **Windows Terminal** or **cmd** via right-click -> **Run as administrator**.
2. `cd` into the build output folder, e.g.:
   ```
   cd C:\path\to\BruceEDR\bin\x64\Release\net8.0-windows
   ```
3. Run:
   ```
   BruceEDR.exe
   ```

**Option B - from Visual Studio:** right-click Visual Studio -> **Run as
administrator**, reopen the solution, make `BruceEDR` the startup project,
then **Debug -> Start Without Debugging** (`Ctrl+F5`). If VS is *not* elevated the
app prints `Run as Administrator` and exits by design - use Option A.

You should see it start the ETW monitor and print the prompt:
```
[*] BruceEDR active (console mode). Monitors: ETW(process,image,file,network), FileStaging.
bruce>
```

**Console commands:** `list` / `list all`, `info N`, `tree N`, `resume N`, `suspend N`,
`kill N`, `stats`, `metrics`, `reload` (re-read config, rules and intel), `audit` (verify
the tamper-evident log), `attack`, `rules [id]`, `intel`, `surface [pid]`, `api ...`,
`vault ...`, `isolate on|off`, `triage N`, `replay <file>`, `quit`. Type `help` for the
full list.

---

## 6. Trigger a detection safely

With the agent running (section 5), open a **second** elevated PowerShell and run
the included harmless simulator:

```
powershell -ExecutionPolicy Bypass -File .\tools\simulate-benign-stealer.ps1
```

It reproduces the **collect -> archive -> exfil** shape without stealing anything:
it writes a dummy file on a path containing `\Google\Chrome\User Data\...\Login
Data` under `%TEMP%`, zips it into `%TEMP%`, and opens/closes a TCP connection to
`1.1.1.1:443`. That crosses the quarantine threshold, so BruceEDR will
**suspend that PowerShell process**.

Now switch to the BruceEDR console:
```
bruce> list
  #   PID     SCORE  STATE                NAME
  1   7364    90     contained            powershell.exe
bruce> info 1        # see the full [+points] reason breakdown
bruce> resume 1      # release it  (or:  kill 1)
```

The simulator sleeps ~90s so you can observe and resume it, then cleans up its
dummy files.

> If ETW couldn't start (you'll see it fall back to WMI), file/network events are
> not captured and only process-start heuristics fire - make sure you launched
> elevated.

---

## 7. Optional: build with the YARA engine

YARA is **off by default** so the standard build has no third-party native/API
dependency. To enable it:

```
dotnet build BruceEDR.csproj -c Release -p:EnableYara=true
```
(In Visual Studio, open **Tools -> Command Line -> Developer PowerShell** and run
the same command, or add `<EnableYara>true</EnableYara>` to a
`Directory.Build.props` at the repo root.)

Then set `"memoryScanEngine": "yara"` in `bruce.config.json`. If the installed
dnYara build doesn't match, the agent logs a warning and falls back to the builtin
scanner automatically - it won't crash.

---

## 8. Optional: install as a Windows Service (longer soak testing)

The service host needs a **self-contained** executable so its binPath is the app
itself (not `dotnet.exe`).

1. Publish self-contained:
   ```
   dotnet publish BruceEDR.csproj -c Release -r win-x64 --self-contained true -o publish
   ```
   (VS: right-click the project -> **Publish** -> Folder -> target `win-x64`,
   deployment mode **Self-contained**.)
2. From an **elevated** prompt in the `publish` folder:
   ```
   BruceEDR.exe --install
   ```
   This registers and starts the `BruceEDR` service (with auto-restart
   recovery) plus a SYSTEM **watchdog** scheduled task.
3. Verify:
   ```
   sc query BruceEDR
   ```
   Events stream to the configured `incidents.jsonl` and `audit.log`.
4. Remove it when done:
   ```
   BruceEDR.exe --uninstall
   ```

> Tamper note: the watchdog + service recovery restart the agent if it crashes or
> is stopped, but an administrator can still kill both. True kill-resistance needs
> PPL/ELAM, which requires Microsoft's anti-malware vendor program (out of scope).

---

## 9. Optional: the kernel minifilter (advanced, lab only)

Real inline prevention. Built **separately** with the WDK.

1. Install the **WDK** matching your VS 2022.
2. In VS: **New Project -> "Filter Driver: Filesystem Mini-Filter"**. Add
   `kernel\BruceFilter\BruceFilter.c`, `.h`, and `.inf` to it. Build **x64 /
   Release** to produce `BruceFilter.sys`.
3. In the VM, enable test signing and reboot:
   ```
   bcdedit /set testsigning on
   ```
   Then install + load (see full steps in `kernel\BruceFilter\README.md`):
   ```
   RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 128 .\BruceFilter.inf
   fltmc load BruceFilter
   ```
4. The agent's `MinifilterClient` auto-connects to `\BruceFilterPort` and pushes
   policy on startup.

> Keep `"kernelBlocking": false` unless you've extended the driver with a
> trusted-PID allowlist (per the driver README) - with it `true`, the skeleton
> denies **every** process access to sensitive paths, including legitimate apps.
> Production loading (no test signing) requires attestation/EV signing + a
> Microsoft-assigned altitude.

---

## 10. Configuration (`bruce.config.json`)

Key settings:
- `detection.warnThreshold` / `quarantineThreshold` - scoring cutoffs.
- `detection.autoKill` - `false` = suspend only (recommended for beta).
- `detection.memoryScanEngine` - `"builtin"` or `"yara"`.
- `detection.rulesPath` - where the JSON detection packs live (default `rules/detection`).
- `detection.enableScoreDecay` - lets a quiet process cool off so it cannot trip on
  weeks of accumulated low-value hits. Contained processes never decay.
- `detection.enableExtendedMonitors` - the DNS / AMSI / registry / process-access ETW
  sessions. Turn off if one of them misbehaves on your build; the agent keeps running.
- `allowlist.publishers` / `thumbprints` - signed apps to de-prioritise (e.g. your
  legitimate RMM tools); pin exact SHA-1 thumbprints for strongest trust.
- `intel.feedPath` - drop hash/domain/IP/CIDR indicator files in here (see
  `intel/feeds/README.md`).
- `response.useEncryptedVault` - quarantine files into an AES-256-GCM vault instead of
  moving them somewhere they are still runnable.
- `response.isolationAllowlist` - **set this before ever using `isolate`**, or you will
  cut off your own remote session.
- `telemetry.format` - `native`, `ecs`, `ocsf` or `cef`. Pick the one your SIEM parses.
- `telemetry.syslog` / `webhook` - set `enabled` + endpoint to forward to a SIEM.
- `api.control.enabled` - the localhost REST control plane. Off by default, and
  read-only unless you also set `allowActions`.
- `api.studio.allowedHosts` - API Studio sends nothing until a host is listed here.

Editing the file **hot-reloads** the detection posture, allowlist, **detection rules and
indicator feeds** live (the console prints `config applied: ...` / `rules reloaded: N`).
Scan-engine, telemetry-format and control-API changes take effect on restart.

### 10b. Writing your own detections

Rules are JSON and need no rebuild. Copy one out of `rules\detection\`, edit it, and type
`reload` at the `bruce>` prompt. The schema, every field and operator, and the
contribution guide are in `rules\detection\README.md`. Test with a replay scenario rather
than with live malware — see `Replay\scenarios\README.md`.

### 10c. API Studio

```
bruce> surface              # what this machine has actually been connecting to
bruce> api surface          # turn that into an inspectable collection
bruce> api send 1           # send it and grade the response
bruce> api help             # everything else
```

It refuses to send anywhere until you allowlist a host in `api.studio.allowedHosts`, and
refuses POST/PUT/PATCH/DELETE until you set `allowMutatingMethods`. That is deliberate.

---

## 11. Telemetry & audit

- `incidents.jsonl` - one JSON line per WARN/QUARANTINE/ACTION event.
- `audit.log` - the same events in a **keyed (HMAC-SHA256) hash chain** with a sibling
  head-anchor (`audit.log.anchor`) and key (`audit.log.key`). Run `audit` in the console
  (or `AuditLogSink.Verify`) to detect alteration, reordering, interior deletion, tail
  truncation, and emptying.
  - **Honest scope:** the key lives on disk next to the log. This defeats an attacker who
    has only a copy of the log, or who cannot read the key — so **protect the audit
    directory with an admin-only ACL**. It does *not* defeat a same-privilege attacker who
    can read the key (BruceEDR runs elevated, so a same-integrity RAT can re-forge the
    chain). For proof against an equal-privilege adversary, forward every event off-box to
    an append-only SIEM (enable the `syslog`/`webhook` sinks) and reconcile against that
    remote head — the local chain is evidence, not a guarantee, once the host is owned.

---

## 12. Troubleshooting

| Symptom | Fix |
|---------|-----|
| App prints `Run as Administrator` and exits | Launch from an elevated terminal (section 5, Option A). |
| Window flashed open and closed on double-click (older build) | The app now self-elevates via UAC; accept the prompt, or run from an elevated terminal. |
| Falls back to `WMI(process)` only | You're not elevated, or ETW is blocked; file/network correlation is limited until ETW works. |
| Build error about platform / `AnyCPU` | Set the VS platform dropdown to **x64**. |
| NuGet restore fails | Check the VM's internet/proxy; retry **Restore NuGet Packages**. |
| `--install` says it needs a self-contained exe | You ran it from a framework-dependent build; publish self-contained first (section 8). |
| YARA build errors | Only happens with `-p:EnableYara=true`; the default build doesn't reference dnYara. |
| Nothing detects during the sim | Confirm the agent started ETW (not WMI) and that you ran the sim **after** the agent. |
| GUI shows a red banner, a warning dialog, or won't start | It logs to `%LOCALAPPDATA%\BruceEDR\gui.log` — open that for the exact error. The banner usually means "not running as Administrator." |
| `rules: '...' not found; running with builtin detections only` | The `rules/detection` folder didn't reach the output directory. Rebuild, or point `detection.rulesPath` at an absolute path. |
| The **API surface** tab is empty | It needs the DNS/network ETW monitors, which need elevation, plus some actual traffic. Check `stats` shows `DNS` among the active monitors. |
| `api send` says *blocked by API safety policy* | By design. Add the host to `api.studio.allowedHosts`, and set `allowMutatingMethods` if you need a non-GET. |
| A monitor is missing from `stats` | Each extended ETW monitor degrades independently — the startup log says which one failed and why. The agent is still detecting on everything else. |
| `--selftest` fails after editing a rule | It prints the exact validation error and which scenario expectation went unmet. That is the intended feedback loop. |

---

## 13. Honest status

This is a **hardened prototype plus real integration layers**, audited by review
but not yet run through a full security review or tested against live malware.
Two capabilities are intentionally not shippable here because they're gated behind
Microsoft programs: **PPL/ELAM tamper protection** and **production driver
signing**. See `README.md` -> "Security model & honest limitations".

What *is* verified on every build: the solution compiles with zero warnings, 2,180 unit
tests pass, all 72 detection rules validate, and all three replay scenarios meet their
expectations — including the benign one that must produce no verdicts at all.

What is **not** verified: the four extended ETW monitors (registry, DNS, AMSI,
process-access) have not been soak-tested against a live fleet; host isolation and triage
collection have been unit-tested at the command-construction level but not exercised
end-to-end on a production box; and nothing here has been run against real malware.
Treat the detection content as a starting point to tune, not as a finished ruleset.

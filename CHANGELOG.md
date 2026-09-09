# Changelog

All notable changes to BruceEDR. This project follows [Semantic Versioning](https://semver.org/).

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

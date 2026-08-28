# Changelog

All notable changes to BruceEDR. This project follows [Semantic Versioning](https://semver.org/).

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

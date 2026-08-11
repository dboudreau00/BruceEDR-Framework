# Replay scenarios

A scenario is a recorded or synthesised sequence of `Signal`s, stored as JSON Lines and
replayed through the detection engine on a `ManualClock`. A six-minute attack chain runs
in a few milliseconds, always the same way, with no processes started, no network touched
and no administrator rights required.

This is how detection changes get reviewed. A pull request that adds or retunes a rule
should also add a scenario that fails before the change and passes after it — and must
keep `benign-developer-day.jsonl` clean.

| File | What it is |
| --- | --- |
| `infostealer-chain.jsonl` | Maldoc → hidden encoded PowerShell → browser credential stores → zip staged in `%TEMP%` → dynamic-DNS C2 → upload. Expects a quarantine on the PowerShell child and none on Word. |
| `rat-beacon.jsonl` | Dropped `%APPDATA%` executable loads a RAT core module, opens a control pipe, persists, then beacons twelve times to one host at a ~30 s cadence with jitter. Expects at least a warn. |
| `benign-developer-day.jsonl` | One developer, one morning: git, npm, msbuild, two release archives. Expects **no quarantine for any pid**. This is the false-positive regression guard and it is as load-bearing as the two attack traces. |

## What replay does and does not prove

It proves that detection logic reaches the stated verdicts for a given signal sequence,
deterministically. It does **not** prove that the monitors would ever emit those signals
on a live host: a technique that ETW, WMI and the minifilter never surface will pass here
and miss in production. Synthesised scenarios test rules; only recorded ones say anything
about telemetry coverage.

Both attack scenarios use RFC 5737 documentation addresses (`203.0.113.0/24`,
`198.51.100.0/24`). They are routable as far as the engine's private-range check is
concerned, and can never resolve to a real host. Nothing in this directory is a live IOC.

## File format

One JSON object per line. Blank lines are ignored, as are lines starting with `#` or `//`.
There are three object shapes.

**Comment.** Any object with a `"#"` property is ignored entirely:

```json
{"#":"why this scenario exists, or what an editor needs to know"}
```

**Meta.** Optional, at most one per file (a second is ignored with a warning), and it may
appear anywhere — timestamps are resolved after the whole file is read, so a meta line at
the bottom still anchors the events above it.

```json
{"meta":{"name":"infostealer-chain","description":"…","start":"2026-03-04T14:02:11Z","expect":["quarantine:pid=4816"]}}
```

* `name` — scenario id. Falls back to the file name.
* `description` — one paragraph: what an analyst is looking at.
* `start` — ISO 8601, assumed UTC if no offset is given. Defaults to `2026-01-01T00:00:00Z`.
* `expect` — array of expectation strings (grammar below).

**Event.** Everything else is one signal.

```json
{"at":1500,"kind":"ProcessStart","pid":4816,"parentPid":3120,"processName":"powershell.exe","commandLine":"…"}
```

`at` is milliseconds from `start`. When it is absent the previous step's offset is
reused, which is how several signals are placed at the same instant. Every other field
maps to a property of `Core/Models.cs :: Signal`, in camelCase:

| Field | Type | Used by |
| --- | --- | --- |
| `kind` | one of `ProcessStart`, `ProcessStop`, `ImageLoad`, `FileCreate`, `NetworkConnect`, `MemoryMatch`, `RegistryWrite`, `DnsQuery`, `ProcessAccess`, `ScriptContent`, `NamedPipe` | required |
| `pid`, `parentPid` | int | all |
| `processName`, `imagePath`, `commandLine` | string | all |
| `filePath` | string | `FileCreate`, `ImageLoad` |
| `remoteAddress`, `remotePort` | string, int | `NetworkConnect` |
| `targetPid`, `desiredAccess` | int, uint (number or `"0x1410"`) | `ProcessAccess` |
| `registryKey`, `registryValue` | string | `RegistryWrite` |
| `domain` | string | `DnsQuery` |
| `scriptText` | string | `ScriptContent` |
| `pipeName` | string | `NamedPipe` |
| `user`, `detail` | string | all |
| `timestampUtc` | ISO 8601 | overrides the `start + at` value; only needed to reproduce a clock skew deliberately |

Field names are matched case-insensitively; the writer always emits camelCase.

### Parser behaviour you can rely on

* `TraceFormat.Parse` **never throws.** Problems come back as warnings tagged with the
  line number. One bad line in a 200-line trace must not hide the other 199 from whoever
  is reviewing the pull request.
* An **unknown field** is a warning and is ignored, so a trace recorded by a newer build
  still replays on an older one.
* A line with a **missing or unknown `kind`** is skipped, not guessed at — guessing would
  quietly change what a detection test asserts. A numeric `kind` such as `"5"` is
  rejected for the same reason: the ordinal it maps to changes whenever the enum grows.
* A **missing `pid`** is warned about and treated as `0` (the engine's "unattributed"
  path, used for archive correlation).
* Offsets are forced non-decreasing. A negative `at`, or one earlier than the previous
  step, is clamped with a warning; the replay clock must never rewind or every
  correlation window in the engine silently misbehaves. Offsets beyond 30 days are
  clamped too — that is almost always seconds written where milliseconds were meant.

## Expectation grammar

Expectations are evaluated after the whole trace has been fed. `ReplayResult.Success` is
true only when every one of them holds; each failure is reported as
`"<expectation> -- <reason>"`.

| Expectation | Holds when |
| --- | --- |
| `quarantine:pid=4242` | a Quarantine verdict was raised for that pid |
| `warn:pid=4242` | a verdict of Warn **or higher** was raised for that pid |
| `no-quarantine:pid=900` | no Quarantine verdict was raised for that pid |
| `score>=70:pid=4242` | final score comparison; operators are `>=`, `>`, `<=`, `<`, `==` (`=` is accepted as an alias for `==`) |
| `technique:T1059.001` | some verdict cited that ATT&CK technique (case-insensitive) |
| `verdicts<=3` | bound on the total number of verdicts, all pids; same five operators |

Three deliberate choices:

* **`warn:` is satisfied by a Quarantine.** An expectation meaning "warn and nothing
  stronger" would break every time a rule was legitimately sharpened. When escalation
  really is the thing being forbidden, add `no-quarantine:` alongside it.
* **A `score` expectation on a pid the engine never scored fails**, rather than treating
  the absent pid as zero. Otherwise `score<40:pid=<typo>` would be vacuously true
  forever. This does mean the engine adapter must report every pid it built state for,
  including ones sitting at zero.
* **An unparsable expectation fails**, with an explanation. Silently ignoring a misspelt
  assertion is the worst thing a test harness can do.

`Expectation.IsWellFormed` checks the grammar without needing a replay, which is what the
test suite uses to make sure every shipped scenario asserts something checkable.

### A note on technique expectations

`technique:` only holds if the engine cites ATT&CK ids on its verdicts. The built-in
heuristics in `DetectionEngine` score without citing techniques (`ReasonEntry.Techniques`
is populated by rule-driven detections). Scenarios here assert the techniques the chain
genuinely demonstrates, which means those particular expectations need the rule pack
loaded. That is intentional: the file describes the attack, not the current engine's
coverage of it.

## Running a scenario

```csharp
var scenario = TraceFormat.Load(@"Replay\scenarios\infostealer-chain.jsonl");
var replay   = new TraceReplay(clock => new MyEngineAdapter(clock));   // IReplayEngine
var result   = replay.Run(scenario);

Console.Write(result.Summary);
if (!result.Success) Environment.ExitCode = 1;
```

`TraceReplay` builds a `ManualClock` at `scenario.StartUtc`, hands it to the factory,
then advances it to each step's offset before feeding the signal. A fresh engine per run
is required, not optional: reusing one across scenarios lets a previous trace's process
profiles change the next one's verdicts.

An exception thrown by the engine is not caught. A crash inside detection is the most
serious thing a replay can find and it should surface with its stack trace intact.

## Recording a real trace

`TraceFormat.FromSignals(signals, name)` converts a captured `IEnumerable<Signal>` into a
scenario, anchoring offset 0 at the first signal's timestamp, and `TraceFormat.Save`
writes it out. To capture the signals, tee them where they enter the engine — an
`IEventSink`-style collector or a wrapper around the ingest call — run the behaviour you
care about in a disposable VM, then serialise.

Delivery order is preserved and **not** re-sorted by timestamp: several monitors feed one
engine and their clocks disagree by a few milliseconds, and the engine reacted to the
order it was actually given. A timestamp that would move an offset backwards is clamped
to the previous offset instead.

Before committing a recording:

1. Scrub it. Real traces carry usernames, machine names, internal hostnames, share paths
   and sometimes tokens on a command line. Rewrite them.
2. Replace real C2 addresses with RFC 5737 documentation ranges, and real domains with a
   plausible shape of name. A scenario file must never become a copy-pasteable IOC list.
3. Trim it. Keep the signals that carry the narrative and the ones that make the trace
   honest (the boring `ImageLoad`s that a real capture contains); drop the other 40 000.
4. Write the `expect` list by hand. Do not paste in whatever the current engine happens
   to conclude — that turns the scenario into a snapshot of today's behaviour instead of
   an assertion about correct behaviour.

## Adding a scenario in a pull request

1. Drop `your-scenario.jsonl` in this directory. Name it after the behaviour, not the
   malware family — families get renamed, behaviours do not.
2. Open with one or more `{"#": "…"}` comment lines saying whether it is recorded or
   synthesised, and what it is modelled on.
3. Give it a `meta` line with a real description and an `expect` list.
4. Confirm it parses with **zero** warnings (`TraceFormat.Load(path, out var warnings)`).
   Warnings mean the file says something you did not intend.
5. Run the whole suite, including `benign-developer-day.jsonl`. A new detection that
   quarantines a build is not a detection.
6. If your rule is prone to a specific false positive, add the benign counter-example to
   `benign-developer-day.jsonl` in the same pull request rather than a separate one.

### Known rough edge

`benign-developer-day.jsonl` avoids `powershell.exe -NoProfile`, which is what the
developer would really have typed: `-NoProfile` contains `-nop`, one of the substrings in
`IocDatabase.CommandLineIocs`, so it scores +15 on an entirely ordinary shell. That is a
real false-positive source in the current rule set. It is called out here rather than
hidden, because a benign trace that quietly dodges a known weakness is worse than no
benign trace at all.

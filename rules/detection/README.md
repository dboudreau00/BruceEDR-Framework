# Writing ProcessShield detection rules

Detection rules are plain JSON. You do not need to build the project, write C#, or
understand the engine internals to add one — write the file, drop it in this directory,
type `reload` in the analyst console, and it is live.

This is deliberate. The hardcoded C# rules in `Detection/DetectionEngine.cs` cover the
classic infostealer and RAT chains, but the interesting detections are the ones *you* need
for the threats *you* see. Those should not require a pull request against the engine.

```bash
# validate every rule pack and replay the detection scenarios — no admin needed
ProcessShield.exe --selftest
```

---

## The shape of a rule pack

A pack is one JSON file: a name, a description, and an array of rules. Files load in
filename order, which is why the shipped ones are numbered.

```json
{
  "name": "My detections",
  "description": "Rules for the tooling my org actually runs.",
  "rules": [
    {
      "id": "curl-to-paste-site",
      "title": "curl.exe uploading to a paste service",
      "description": "curl.exe was launched with a paste-site URL. Legitimate use exists but is rare on a workstation; treat as exfiltration until shown otherwise.",
      "author": "you@example.com",
      "severity": "high",
      "score": 40,
      "techniques": ["T1567", "T1105"],
      "references": ["https://attack.mitre.org/techniques/T1567/"],
      "enabled": true,
      "oncePerProcess": true,
      "kinds": ["ProcessStart"],
      "detection": [
        {
          "all": [
            { "field": "processName", "op": "equals", "value": "curl.exe" },
            { "field": "commandLine", "op": "regex", "value": "(pastebin|hastebin|termbin|transfer\\.sh)" }
          ],
          "none": [
            { "field": "commandLine", "op": "contains", "value": "--our-approved-uploader" }
          ]
        }
      ],
      "falsePositives": [
        "Developers pasting build logs by hand.",
        "CI agents that publish artifacts through a paste-like service."
      ]
    }
  ]
}
```

A single rule object, or a bare array of rule objects, is accepted too — the wrapper is
only for tidiness.

### Fields on a rule

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Unique, kebab-case. Appears in every alert and in `rules <id>`. |
| `title` | yes | One line an analyst reads at 3 a.m. |
| `description` | recommended | What it means and what to pivot on next. |
| `author` | no | Who to ask about it. |
| `severity` | no | `informational` \| `low` \| `medium` \| `high` \| `critical`. Presentation only — `score` drives the verdict. |
| `score` | yes | Points added when the rule fires. **May be negative** — that is how you write an allowlist rule. |
| `techniques` | recommended | MITRE ATT&CK ids. They flow into the alert, the ECS/OCSF output and the `attack` coverage view. |
| `references` | no | URLs. |
| `enabled` | no | Defaults to `true`. |
| `oncePerProcess` | no | Defaults to `true`. Keep it true unless you genuinely want repeat scoring. |
| `kinds` | no | Signal kinds this rule applies to. Empty means all. Restricting it is a large performance win. |
| `detection` | yes | Array of clauses. The rule fires if **any** clause matches (OR of ANDs). |
| `falsePositives` | yes in review | Be honest and specific. A rule with no known false positives has usually not been tested. |

### Clauses

Each clause has `all` (every condition must be true) and optionally `none` (no condition
may be true).

```json
{ "all": [ ... ], "none": [ ... ] }
```

### Fields you can match on

| Field | Available on |
| --- | --- |
| `kind` | every signal (`ProcessStart`, `FileCreate`, `NetworkConnect`, `DnsQuery`, `RegistryWrite`, `ProcessAccess`, `ScriptContent`, `NamedPipe`, `ImageLoad`, `ProcessStop`) |
| `pid`, `parentPid`, `targetPid` | every signal |
| `processName`, `imagePath`, `commandLine` | process-attributed signals |
| `filePath`, `fileName`, `fileExtension` | `FileCreate`, `ImageLoad` |
| `remoteAddress`, `remotePort` | `NetworkConnect` |
| `domain` | `DnsQuery` |
| `registryKey`, `registryValue` | `RegistryWrite` |
| `pipeName` | `NamedPipe` |
| `scriptText` | `ScriptContent` (AMSI) |
| `desiredAccess` | `ProcessAccess` |
| `user`, `detail`, `primaryTarget` | every signal |
| `parentName` | resolved from the process tree |
| `ancestry` | every ancestor process name, nearest first |
| `score` | the process's current score, for staged rules |
| `trusted` | `true` when the image is Authenticode-signed by an allowlisted publisher |

`primaryTarget` is whichever path-like field the signal actually carries, so one rule can
cover files, registry keys, pipes and domains at once.

### Operators

| `op` | Notes |
| --- | --- |
| `equals`, `notEquals` | Case-insensitive by default. |
| `contains`, `notContains` | Substring. |
| `startsWith`, `endsWith` | |
| `regex` | .NET syntax, compiled once, 250 ms match timeout. A timeout skips the rule for that signal; it never throws. |
| `in`, `notIn` | Use `values` (an array) instead of `value`. |
| `greaterThan`, `lessThan` | Numeric. Use for `remotePort`, `score`, `desiredAccess`. |
| `exists`, `notExists` | Field is present and non-empty. |
| `cidrIn` | `remoteAddress` inside a CIDR range. IPv4 and IPv6. |

Set `"caseSensitive": true` on a condition when case actually matters.

Short aliases are accepted so a rule reads naturally whichever dialect you came from:
`eq`/`is`, `ne`/`neq`/`isNot`, `has`, `matches`/`re`, `anyOf`, `noneOf`, `gt`, `lt`,
`missing`, `cidr`.

---

## Rules that lower the score

A negative `score` suppresses noise without disabling detection elsewhere. This is almost
always better than deleting a rule, because the evidence still shows up in the alert
reasoning:

```json
{
  "id": "allow-our-backup-agent",
  "title": "Approved backup agent archiving to the staging share",
  "score": -60,
  "kinds": ["FileCreate"],
  "detection": [{
    "all": [
      { "field": "processName", "op": "equals", "value": "backup-agent.exe" },
      { "field": "imagePath",  "op": "startsWith", "value": "C:\\Program Files\\Contoso\\" }
    ]
  }],
  "falsePositives": ["None known — but this rule is a suppression, so audit it periodically."]
}
```

Pin the publisher thumbprint in `shield.config.json` too. A rule keyed on a filename alone
is trivially spoofed by dropping a binary with that name.

---

## Validation

`--selftest` and startup both validate every rule. These are **blocking** errors — the rule
is dropped and the rest of the pack still loads:

- missing or duplicate `id`
- unknown `field` or `op`
- a `regex` that does not compile
- `in`/`notIn` with an empty `values` array
- an unknown signal kind in `kinds`

An ATT&CK id that this build's catalogue does not recognise is reported as a **note**, not
an error — new technique ids appear faster than the bundled table, and a rule should not be
disabled for being current.

---

## Testing a rule before you ship it

Do not test detections by running malware. Write a scenario instead:
`Replay/scenarios/*.jsonl` is a JSON-Lines trace of signals with a simulated clock, replayed
through a real detection engine in milliseconds. See
[`Replay/scenarios/README.md`](../../Replay/scenarios/README.md) for the format.

```bash
ProcessShield.exe --selftest                       # validates rules + replays every scenario
```

From inside the running agent:

```
shield> rules curl-to-paste-site      # confirm it loaded and read it back
shield> replay Replay/scenarios/my-new-case.jsonl
shield> reload                        # after editing the JSON
```

**Every rule contribution should come with a scenario**, and ideally with an addition to
`benign-developer-day.jsonl` proving the rule does not fire on ordinary work. That benign
trace is the project's false-positive regression guard and it matters as much as the
malicious ones.

---

## Style guide for contributed rules

1. **Score conservatively.** The default quarantine threshold is 70 and quarantine suspends
   a live process. A single rule scoring 70+ is asserting "this alone justifies freezing a
   process on someone's machine". Very few things do. Prefer several 20–45 point rules that
   have to combine.
2. **Restrict `kinds`.** A rule with no `kinds` is evaluated against every signal on a busy
   host — that is a lot of wasted regex.
3. **Prefer `in` over many `regex` alternations.** It is a hash lookup rather than a scan.
4. **Anchor on behaviour, not on names.** `processName == "mimikatz.exe"` catches nobody who
   matters. The handle-access pattern behind it catches the technique.
5. **Write the false positives down.** If you cannot think of one, you have not run the rule
   on a real fleet yet — say that in the field.
6. **Say what to do next** in `description`. An alert nobody can action is noise with extra
   steps.

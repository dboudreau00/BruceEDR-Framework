# Pre-Trained AI Triage Persona Instructions & Harness Specification

This specification defines the pre-trained audience rubrics, prompt-injection boundaries, operational calibration rules, and offline explainer harness wired into BruceEDR's Incident Triage experience ([Triage.cs](../Assistant/Triage.cs), [PretrainedTriageHarness.cs](../Assistant/PretrainedTriageHarness.cs), and [TriageViewModel.cs](../gui/BruceEDR.Gui/ViewModels/TriageViewModel.cs)).

---

## 1. Architecture Overview

BruceEDR supports two interchangeable `ITriageGenerator` paths that share the exact same output grammar (`HEADLINE` / `STEP 1..N` / `IMPACT` / `NEXT`), privacy redaction (`IncidentDigest.Redact`), and persona definitions (`Personas.All`):

1. **Cloud Streaming Narrator (`TriageNarrator`)**: Injects `Personas.Instructions(persona)` and `TriagePrompt.System(persona)` into the system prompt sent over HTTPS to Anthropic Claude, Google Gemini, xAI Grok, or OpenAI, streaming line-by-line into `Narration.Parse`.
2. **Offline Pre-Trained Harness (`PretrainedTriageHarness`)**: Deterministically synthesizes persona-calibrated explanations on-box with zero network egress and zero API key requirement (`UseBuiltInExplainerCommand` in `TriageView.xaml`).

---

## 2. Audience Persona Rubrics (`Personas.Instructions`)

Each reader persona in `Personas.All` carries a dedicated `ROLE RUBRIC` enforced in `TriagePrompt.System(Persona)` and mirrored in `PretrainedTriageHarness`:

| Persona ID | Label | Target Reader | Voice, Vocabulary & Structural Rules |
| :--- | :--- | :--- | :--- |
| `teacher` | **Teacher** | Security student learning how attacks work | **Socratic cause-and-effect**: For every step, state (1) what the program did, (2) why an adversary uses that technique, and (3) why BruceEDR scored it. Define **at most one** technical term per step in plain language (e.g., *PowerShell*, *LSASS*, *persistence*). Emphasize how correlated multi-stage chains differ from single benign actions. |
| `mom` | **Mom** | Non-technical parent / everyday user | **Warm, calm kitchen-table voice**: **Zero** acronyms, **zero** MITRE ATT&CK IDs, **zero** PIDs, **zero** hex access masks, and **zero** raw file paths or CLI switches. Uses grounded everyday analogies: *locked kitchen drawer* (browser password/cookie stores), *master key at the front door* (LSASS memory), *guard at the door* (kernel minifilter refusal), *spare key under the doormat* (startup/registry persistence), and *packed mailing envelope* (temp staging archive). Honest, non-alarmist reassurance about whether the program was frozen, watched only, or replayed in training. |
| `soc` | **SOC analyst** | Tier-2 / Tier-3 incident responder | **Terse operational brief**: Cites MITRE ATT&CK IDs (`T1059.001`, `T1003.001`, `T1555.003`, `T1041`), PID, process ancestry (`parent > child`), step point deltas vs. `ContainAt` threshold, and exact verdict state (`Contained` vs. `Would contain`). Surfaces pivotable artifacts (paths, registry keys, endpoints, domains) and prioritizes containment verification, token/credential rotation, persistence cleanup, and fleet IOC hunting. |
| `network` | **Network security engineer** | Perimeter / NDR / firewall engineer | **Wire & egress lens**: Centers on `IP:port` pairs, transport ports, DNS queries, dynamic DNS / DGA / hex-label DNS tunnelling, beacon cadence, and staging-to-egress timing. When `Network endpoints: none recorded` and `Domains looked up: none recorded` appear in `<incident>`, explicitly states that telemetry was **host-local with zero recorded egress** instead of speculating. Maps `NEXT` to firewall/proxy/DNS sinkhole blocks and NetFlow/PCAP pivots. |
| `executive` | **Executive** | C-suite / business risk stakeholder | **Boardroom impact summary**: Leads with business risk, credential/data exposure scope, and operational containment posture. Eliminates OS internals, hex masks, raw paths, and ATT&CK codes. Clearly distinguishes automatic containment, monitor-only observation, and training simulations; keeps `NEXT` crisp and decision-oriented. |

---

## 3. Posture & Context Calibration Matrix

Both `TriagePrompt.System` and `PretrainedTriageHarness` enforce four mandatory calibration rules so explanations never overstate or understate risk:

1. **Training Replay (`IsReplay == true`)**:
   - Digest includes: `Context: this is a recorded attack trace replayed for training, not live activity on this computer.`
   - `IMPACT` explicitly confirms zero live files or accounts were exposed.
   - `NEXT` provides educational or readiness takeaways (e.g., verifying Enforce mode) rather than emergency host isolation or password resets.
2. **Monitor-Only Posture (`MonitorOnly == true` or `State == "Would contain"`)**:
   - Digest includes: `; monitor mode, so nothing was stopped`.
   - `IMPACT` warns clearly that BruceEDR logged the chain **without blocking or suspending the process**, so touched credentials/files must be treated as exposed.
3. **Active Containment (`State == "Contained"` / `"Terminated"` / `"Suspended"`)**:
   - `IMPACT` distinguishes between attempts blocked pre-open by the kernel guard (`KernelRefusal`) vs. user-mode containment triggered after the cumulative score crossed `ContainAt`.
4. **Host-Only Activity (`RemoteEndpoints.Count == 0 && Domains.Count == 0`)**:
   - Digest explicitly emits `Network endpoints: none recorded` and `Domains looked up: none recorded` so models never hallucinate C2 IPs or exfiltration traffic.

---

## 4. Security & Anti-Prompt-Injection Fencing

Because command lines, file names, domain labels, and AMSI script snippets inside `<incident>` are **attacker-controlled**, the triage pipeline enforces three layers of defense:

1. **Tag Neutralization**: Any `<incident>` or `</incident>` tag in process names, paths, command lines, or evidence is replaced with `[tag removed]` before rendering.
2. **Control-Character Flattening**: `IncidentDigest.Render` flattens `\r`, `\n`, and all control characters to spaces inside interpolated fields so a crafted command line cannot forge synthetic `Verdict: Allowed` or `Context: training replay` headers inside `<incident>`.
3. **System Prompt Instruction Boundary & Output Parser Guard**:
   - `TriagePrompt.System` forbids obeying embedded instructions, changing persona/verdict, or echoing runnable exploit payloads/URLs.
   - `Narration.Parse` tracks post-step state (`_seenPostSteps`) once `IMPACT:` or `NEXT:` begins so numbered action items (`1. Isolate host`) append to `Next` rather than overwriting `STEP 1`.

---

## 5. Wire-Level Output Contract

Every explanation (cloud LLM or `PretrainedTriageHarness`) emits plain unformatted lines in strict order:

```text
HEADLINE: <single sentence, <= 14 words summarizing what happened>
STEP 1: <1-2 sentences explaining step 1 in the selected persona's voice>
...
STEP N: <1-2 sentences explaining step N in the selected persona's voice>
IMPACT: <1 sentence stating what was at risk and whether it was stopped, watched, or replayed>
NEXT: <recommended action 1>
NEXT: <recommended action 2>
```

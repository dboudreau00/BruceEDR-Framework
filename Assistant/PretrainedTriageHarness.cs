using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using BruceEDR.Detection;
using BruceEDR.Intel;

namespace BruceEDR.Assistant;

/// <summary>
/// Deterministic, pre-trained offline explainer implementing <see cref="ITriageGenerator"/>.
/// Applies the exact persona rubrics (<see cref="Personas.Instructions(Persona)"/>) locally so
/// offline lab VMs, smoke tests, and air-gapped analysts get persona-authentic explanations
/// ("Teacher", "Mom", "SOC analyst", "Network security engineer", "Executive") with zero API key.
/// </summary>
public sealed class PretrainedTriageHarness : ITriageGenerator
{
    private static readonly Regex PointsPrefix = new(@"^[+-]?\d+\s+", RegexOptions.CultureInvariant);

    public Task<TriageResult> GenerateAsync(TriageRequest request, Action<string> onText, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(onText);

        if (ct.IsCancellationRequested)
            return Task.FromCanceled<TriageResult>(ct);

        string text = Render(request.Incident, request.Persona, request.Redact);
        foreach (string line in text.Split('\n'))
        {
            ct.ThrowIfCancellationRequested();
            onText(line + "\n");
        }

        string trimmed = text.TrimEnd('\n');
        return Task.FromResult(new TriageResult(trimmed, Refused: false, StopReason: "pretrained", Error: ""));
    }

    public static string Render(IncidentCase c, Persona persona, bool redact = true)
    {
        string id = persona.Id;
        var sb = new StringBuilder(1024);

        sb.Append("HEADLINE: ").AppendLine(BuildHeadline(c, id));
        foreach (var step in c.Steps)
        {
            sb.Append(CultureInfo.InvariantCulture, $"STEP {step.Number}: ")
              .AppendLine(BuildStep(c, step, id, redact));
        }
        sb.Append("IMPACT: ").AppendLine(BuildImpact(c, id));
        foreach (string next in BuildNext(c, id, redact))
        {
            sb.Append("NEXT: ").AppendLine(next);
        }
        return sb.ToString().TrimEnd();
    }

    private enum StepKind
    {
        Execution,
        Script,
        Lsass,
        CredentialStore,
        KernelRefusal,
        CrossProcess,
        ArchiveStage,
        Persistence,
        NetworkExfil,
        Dns,
        StaticOrMemory,
        TrustDiscount,
        Other
    }

    private static StepKind Classify(IncidentStep step)
    {
        if (step.Points < 0) return StepKind.TrustDiscount;
        string joined = (step.Title + " " + string.Join(" ", step.Evidence)).ToLowerInvariant();
        var techs = step.Techniques;

        if (joined.Contains("kernel refused")) return StepKind.KernelRefusal;
        if (joined.Contains("lsass") || techs.Any(t => t.StartsWith("T1003", StringComparison.OrdinalIgnoreCase)))
            return StepKind.Lsass;
        if (joined.Contains("credential") || joined.Contains("login data") || joined.Contains("cookies") ||
            joined.Contains("local state") || joined.Contains("wallet") || joined.Contains("leveldb") ||
            techs.Any(t => t.StartsWith("T1555", StringComparison.OrdinalIgnoreCase) || t.StartsWith("T1539", StringComparison.OrdinalIgnoreCase)))
            return StepKind.CredentialStore;
        if (joined.Contains("archive") || joined.Contains("staging") || joined.Contains("compress") ||
            techs.Any(t => t.StartsWith("T1560", StringComparison.OrdinalIgnoreCase) || t.StartsWith("T1074", StringComparison.OrdinalIgnoreCase)))
            return StepKind.ArchiveStage;
        if (joined.Contains("outbound") || joined.Contains("beacon") || joined.Contains("upload") ||
            joined.Contains("exfil") || joined.Contains("ftp") || joined.Contains("smtp") ||
            techs.Any(t => t.StartsWith("T1041", StringComparison.OrdinalIgnoreCase) || t.StartsWith("T1567", StringComparison.OrdinalIgnoreCase) || t.StartsWith("T1048", StringComparison.OrdinalIgnoreCase)))
            return StepKind.NetworkExfil;
        if (joined.Contains("dns") || joined.Contains("domain") || joined.Contains("dga") ||
            techs.Any(t => t.StartsWith("T1568", StringComparison.OrdinalIgnoreCase) || t.Equals("T1071.004", StringComparison.OrdinalIgnoreCase)))
            return StepKind.Dns;
        if (joined.Contains("autostart") || joined.Contains("run key") || joined.Contains("startup") ||
            joined.Contains("scheduled task") || joined.Contains("tasks") || joined.Contains("service") ||
            joined.Contains("ifeo") || joined.Contains("clsid") || joined.Contains("winlogon") ||
            string.Equals(step.Stage, "Persistence", StringComparison.OrdinalIgnoreCase))
            return StepKind.Persistence;
        if (joined.Contains("amsi") || joined.Contains("script") || joined.Contains("obfuscated"))
            return StepKind.Script;
        if (joined.Contains("injection-capable") || joined.Contains("opened pid") ||
            techs.Any(t => t.StartsWith("T1055", StringComparison.OrdinalIgnoreCase)))
            return StepKind.CrossProcess;
        if (joined.Contains("memory ioc") || joined.Contains("pe ") || joined.Contains("packer") || joined.Contains("hash"))
            return StepKind.StaticOrMemory;
        if (string.Equals(step.Stage, "Execution", StringComparison.OrdinalIgnoreCase) ||
            joined.Contains("spawned") || joined.Contains("command") || joined.Contains("lolbin") || joined.Contains("powershell"))
            return StepKind.Execution;

        return StepKind.Other;
    }

    private static string FriendlyAppName(string processName)
    {
        string lower = (processName ?? "").Trim().ToLowerInvariant();
        return lower switch
        {
            "powershell.exe" or "pwsh.exe" or "cmd.exe" => "a built-in Windows command tool",
            "wscript.exe" or "cscript.exe" or "mshta.exe" => "a Windows script helper",
            "rundll32.exe" or "regsvr32.exe" => "a Windows system helper",
            "notepad.exe" => "the Notepad text app",
            "winword.exe" => "a Word document",
            "excel.exe" => "an Excel spreadsheet",
            _ => "an unfamiliar program"
        };
    }

    private static string BuildHeadline(IncidentCase c, string personaId)
    {
        bool hasCreds = c.Steps.Any(s => Classify(s) is StepKind.CredentialStore or StepKind.Lsass or StepKind.KernelRefusal);
        bool hasExfil = c.RemoteEndpoints.Count > 0 || c.Steps.Any(s => Classify(s) == StepKind.NetworkExfil);
        bool hasStage = c.StagedArchives.Count > 0 || c.Steps.Any(s => Classify(s) == StepKind.ArchiveStage);
        bool hasPersist = c.Steps.Any(s => Classify(s) == StepKind.Persistence);
        string proc = string.IsNullOrWhiteSpace(c.ProcessName) ? "Suspicious process" : c.ProcessName;

        return personaId switch
        {
            "mom" => hasCreds && hasExfil
                ? "A sneaky program reached for saved passwords and tried sending them out"
                : hasCreds
                    ? "A suspicious program tried peeking into saved sign-in details"
                    : hasPersist
                        ? "A program tried hiding a startup shortcut so it could return later"
                        : "BruceEDR spotted a program acting in an unsafe, unusual way",

            "executive" => hasCreds && (hasExfil || hasStage)
                ? "Automated credential theft and data staging detected on endpoint"
                : hasCreds
                    ? "Unauthorized credential access attempt detected on endpoint"
                    : hasPersist
                        ? "Unauthorized system persistence attempt detected on endpoint"
                        : $"Suspicious endpoint activity flagged on {proc}",

            "network" => hasExfil
                ? $"{proc} triggered outbound egress alerts after host-side staging"
                : c.Domains.Count > 0
                    ? $"{proc} generated suspicious DNS resolution activity during alert"
                    : $"{proc} triggered host-local threat detections with no recorded egress",

            "soc" => hasCreds && hasExfil
                ? $"{proc} executed credential access and outbound exfiltration chain ({c.State})"
                : hasCreds
                    ? $"{proc} attempted credential harvesting reaching score {c.Score} ({c.State})"
                    : $"{proc} escalated to {c.State} at score {c.Score} across {c.Steps.Count} step(s)",

            _ => hasCreds && (hasStage || hasExfil)
                ? $"{proc} chained suspicious execution, credential access, and data staging"
                : $"{proc} triggered {c.Steps.Count} correlated security signal(s) on Windows"
        };
    }

    private static string BuildStep(IncidentCase c, IncidentStep step, string personaId, bool redact)
    {
        var kind = Classify(step);
        string rawSummary = CleanEvidence(step, redact);
        string techList = step.Techniques.Count > 0
            ? string.Join(", ", step.Techniques.Take(4))
            : "behavioral heuristic";
        string firstTechName = step.Techniques.Count > 0
            ? AttackCatalog.Lookup(step.Techniques[0]).Name
            : step.Stage;

        return personaId switch
        {
            "mom" => BuildMomStep(c, kind),
            "executive" => BuildExecutiveStep(kind, step),
            "network" => BuildNetworkStep(c, step, kind, rawSummary),
            "soc" => BuildSocStep(c, step, techList, rawSummary),
            _ => BuildTeacherStep(c, step, kind, firstTechName, rawSummary),
        };
    }

    private static string BuildMomStep(IncidentCase c, StepKind kind)
    {
        string app = FriendlyAppName(c.ProcessName);
        return kind switch
        {
            StepKind.Execution =>
                $"First, {app} started running hidden instructions in the background without asking you.",
            StepKind.Script =>
                "It used scrambled wording to hide what it was doing, much like writing a note in secret code.",
            StepKind.Lsass =>
                "Next, it tried reaching into Windows's own sign-in memory, like trying to copy the master key while the front door is unlocked.",
            StepKind.CredentialStore =>
                "It opened the private drawer where web browsers or chat apps keep saved passwords and sign-in cookies.",
            StepKind.KernelRefusal =>
                "It tried opening your saved password drawer, but BruceEDR's guard at the door blocked its hand before anything could be read.",
            StepKind.CrossProcess =>
                "It tried reaching inside another running program to hide behind a familiar name.",
            StepKind.ArchiveStage =>
                "Then it packed files into a temporary bundle, like stuffing copies of paperwork into a mailing envelope by the door.",
            StepKind.Persistence =>
                "It tried leaving a hidden spare key in Windows startup settings so it could wake back up after a restart.",
            StepKind.NetworkExfil =>
                "After that, it tried connecting over the internet to hand that bundle off to an outside server.",
            StepKind.Dns =>
                "It looked up an unusual internet address to find out where its outside controller was waiting.",
            StepKind.StaticOrMemory =>
                "BruceEDR inspected the program closely and noticed hidden tools commonly used by password-stealing software.",
            StepKind.TrustDiscount =>
                "BruceEDR noted that the program itself carried a real publisher signature, so it weighed all the actions carefully before deciding.",
            _ =>
                $"The program took another unusual step that raised BruceEDR's concern level further."
        };
    }

    private static string BuildTeacherStep(IncidentCase c, IncidentStep step, StepKind kind, string firstTechName, string rawSummary)
    {
        string delta = step.Points >= 0 ? $"+{step.Points}" : step.Points.ToString(CultureInfo.InvariantCulture);
        return kind switch
        {
            StepKind.Execution =>
                $"The process launched with suspicious execution traits ({rawSummary}), adding {delta} points (total {step.ScoreAfter}). Attackers use built-in shells like PowerShell (Windows's automation command tool) so they do not have to drop a brand-new program first.",
            StepKind.Script =>
                $"Windows's script scanner surfaced concealed or downloader script code ({rawSummary}), adding {delta} points (total {step.ScoreAfter}). Obfuscation scrambles text to slip past simple keyword checks, which is why BruceEDR inspects the decoded script behavior.",
            StepKind.Lsass =>
                $"The process opened LSASS (the Windows security service that holds active sign-in secrets in memory), adding {delta} points (total {step.ScoreAfter}). Attackers read LSASS to steal active account credentials without knowing the user's password.",
            StepKind.CredentialStore =>
                $"The process accessed a saved credential or token file ({rawSummary}), adding {delta} points (total {step.ScoreAfter}). Only the browser or app that owns that store should read it; another program opening it is a classic infostealer clue.",
            StepKind.KernelRefusal =>
                $"BruceEDR's kernel driver intercepted and refused access to a guarded credential store ({rawSummary}), adding {delta} points (total {step.ScoreAfter}). Even though the read failed, the attempt proves the process tried to harvest saved secrets.",
            StepKind.ArchiveStage =>
                $"The process created a compressed archive in a writable staging folder ({rawSummary}), adding {delta} points (total {step.ScoreAfter}). Attackers bundle stolen files into one zip in Temp so they can upload everything in a single quick connection.",
            StepKind.Persistence =>
                $"The process modified a startup or service registration ({rawSummary}), adding {delta} points (total {step.ScoreAfter}). Persistence (planting a hook that runs automatically at boot or sign-in) lets malware survive a reboot.",
            StepKind.NetworkExfil =>
                $"The process opened an outbound network connection ({rawSummary}), adding {delta} points (total {step.ScoreAfter}). Notice how BruceEDR connects earlier local clues with outbound traffic to spot data exfiltration ({firstTechName}).",
            StepKind.Dns =>
                $"The process queried a suspicious domain pattern ({rawSummary}), adding {delta} points (total {step.ScoreAfter}). Malware often uses dynamically generated domain names to locate command-and-control servers.",
            StepKind.TrustDiscount =>
                $"BruceEDR applied a trust offset ({delta} points, score now {step.ScoreAfter}) because the executable is signed by an allowlisted publisher. A valid signature lowers noise on benign tools without excusing high-scoring attack chains.",
            _ =>
                $"BruceEDR recorded {firstTechName} evidence ({rawSummary}), changing the risk score by {delta} to {step.ScoreAfter}. Correlating each step in sequence helps separate real multi-stage attacks from isolated admin activity."
        };
    }

    private static string BuildSocStep(IncidentCase c, IncidentStep step, string techList, string rawSummary)
    {
        string lineage = c.Lineage.Count > 1 ? string.Join(" > ", c.Lineage) : $"{c.ProcessName} (pid {c.Pid})";
        string delta = step.Points >= 0 ? $"+{step.Points}" : step.Points.ToString(CultureInfo.InvariantCulture);
        return $"[{step.Stage} | {techList}] {c.ProcessName} (pid {c.Pid}, chain: {lineage}) scored {delta} -> {step.ScoreAfter}/{c.ContainAt}: {rawSummary}.";
    }

    private static string BuildNetworkStep(IncidentCase c, IncidentStep step, StepKind kind, string rawSummary)
    {
        return kind switch
        {
            StepKind.NetworkExfil =>
                $"Outbound transport activity recorded ({rawSummary}), pushing score to {step.ScoreAfter}; correlate destination IP:port against firewall/proxy session logs and byte-volume spikes.",
            StepKind.Dns =>
                $"DNS resolution anomaly observed ({rawSummary}), score {step.ScoreAfter}; inspect recursive resolver logs for NXDOMAIN bursts, TXT/hex labels, or low-TTL answers.",
            StepKind.ArchiveStage =>
                $"Host-local archive staging ({rawSummary}) raised score to {step.ScoreAfter}; no wire traffic in this step itself, but it typically precedes outbound HTTP POST, TLS, or cloud-storage egress.",
            _ => c.RemoteEndpoints.Count == 0 && c.Domains.Count == 0
                ? $"Host-local telemetry ({step.Stage}: {rawSummary}) moved score to {step.ScoreAfter}; zero network endpoints or DNS queries were recorded on this incident."
                : $"Host-side precursor ({step.Stage}: {rawSummary}) moved score to {step.ScoreAfter} alongside recorded endpoint/DNS activity ({ SummarizeNet(c) })."
        };
    }

    private static string BuildExecutiveStep(StepKind kind, IncidentStep step)
    {
        return kind switch
        {
            StepKind.Execution or StepKind.Script =>
                "An automated command tool ran concealed instructions that normal office workflows do not use.",
            StepKind.Lsass or StepKind.CredentialStore =>
                "The program attempted to access stored employee sign-ins or browser session tokens.",
            StepKind.KernelRefusal =>
                "BruceEDR's kernel guard blocked an unauthorized attempt to read protected credential files.",
            StepKind.ArchiveStage =>
                "The program packaged local data into a temporary archive to prepare it for transfer.",
            StepKind.Persistence =>
                "The program attempted to register itself to restart automatically on the workstation.",
            StepKind.NetworkExfil or StepKind.Dns =>
                "The program initiated external network communication consistent with sending data off-host.",
            StepKind.TrustDiscount =>
                "BruceEDR verified vendor code-signing credentials while continuing to evaluate behavioral risk.",
            _ =>
                $"Endpoint monitoring logged an elevated risk indicator during {step.Stage.ToLowerInvariant()} activity."
        };
    }

    private static string BuildImpact(IncidentCase c, string personaId)
    {
        bool hasCreds = c.Steps.Any(s => Classify(s) is StepKind.CredentialStore or StepKind.Lsass);
        bool kernelBlockedOnly = !hasCreds && c.Steps.Any(s => Classify(s) == StepKind.KernelRefusal);
        bool hasExfil = c.RemoteEndpoints.Count > 0 || c.Steps.Any(s => Classify(s) == StepKind.NetworkExfil);

        if (c.IsReplay)
        {
            return personaId switch
            {
                "mom" => "Nothing on your real computer was touched. This was a safe practice recording showing how BruceEDR spots password thieves.",
                "executive" => "No live company assets were exposed because this alert came from a controlled training replay rather than live workstation activity.",
                "network" => "Training replay only (no live packet egress occurred on this host); in a live incident the simulated chain risks credential and archive exfiltration.",
                "soc" => $"Replay simulation ({c.Source}): zero live host exposure; simulated chain reached score {c.Score} ({c.State}) demonstrating credential/exfil detection.",
                _ => "Because this is a training replay, no real files or accounts were harmed, though in real life this pattern puts saved sign-ins and staged data at risk."
            };
        }

        if (c.MonitorOnly || string.Equals(c.State, "Would contain", StringComparison.OrdinalIgnoreCase))
        {
            return personaId switch
            {
                "mom" => "BruceEDR was in watch-only mode so it did not freeze the program, meaning saved passwords or personal files could be at risk until checked.",
                "executive" => "Because the sensor is running in monitor-only mode, the activity was logged but not automatically blocked, leaving workstation credentials potentially exposed.",
                "network" => hasExfil
                    ? $"Monitor-only mode left {c.ProcessName} unblocked while contacting {c.RemoteEndpoints.Count} external endpoint(s), creating active data-egress risk."
                    : "Monitor-only mode logged host-local threat activity without blocking the process, though no external network egress was recorded.",
                "soc" => $"Monitor mode ('{c.State}', score {c.Score}/{c.ContainAt}): containment was skipped, so {c.ProcessName} (pid {c.Pid}) ran unrestrained and any touched credentials must be treated as exposed.",
                _ => "Because BruceEDR was in monitor-only mode, it alerted without stopping the process, so any saved credentials or staged files touched in these steps may have been exposed."
            };
        }

        bool contained = string.Equals(c.State, "Contained", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(c.State, "Terminated", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(c.State, "Suspended", StringComparison.OrdinalIgnoreCase);

        return personaId switch
        {
            "mom" => contained
                ? (kernelBlockedOnly
                    ? "BruceEDR blocked the password drawer and froze the program right away, keeping your saved accounts safe."
                    : "BruceEDR froze and cut off the program as soon as the danger score crossed its safety line, limiting what could leave your computer.")
                : "BruceEDR flagged early warning signs on this program before it crossed the full freeze threshold, so keeping an eye on saved accounts is wise.",
            "executive" => contained
                ? $"BruceEDR automatically contained {c.ProcessName} at score {c.Score}, halting further workstation activity and limiting potential credential or data exposure."
                : $"BruceEDR raised an early warning on {c.ProcessName} (score {c.Score}/{c.ContainAt}); no automatic containment has fired yet.",
            "network" => hasExfil
                ? $"Process reached {c.State} after contacting {SummarizeNet(c)}; outbound firewall block applies upon containment, but prior packets before threshold crossing warrant proxy review."
                : $"Process reached {c.State} at score {c.Score} with zero recorded external IP connections or DNS lookups.",
            "soc" => $"Posture '{c.State}' (score {c.Score}, peak {c.PeakScore}, threshold {c.ContainAt}): {(hasCreds ? "credential stores were touched prior to containment" : "suspicious execution/persistence observed")} on pid {c.Pid}.",
            _ => contained
                ? $"Saved credentials or staged files were targeted, and BruceEDR contained {c.ProcessName} once its cumulative score ({c.Score}) crossed the {c.ContainAt}-point threshold."
                : $"The activity raised {c.ProcessName} to a warning score of {c.Score}/{c.ContainAt}, signaling suspicious behavior that merits verification before exposure grows."
        };
    }

    private static IReadOnlyList<string> BuildNext(IncidentCase c, string personaId, bool redact)
    {
        if (c.IsReplay)
        {
            return personaId switch
            {
                "mom" => new[]
                {
                    "No password resets are needed because this was only a practice recording.",
                    "Keep Enforce mode and credential protection switched on so BruceEDR can block real threats automatically."
                },
                "executive" => new[]
                {
                    "Confirm production endpoints run in Enforce mode rather than monitor-only mode so live attacks are stopped automatically.",
                    "Use this replay scenario in tabletop reviews to validate SOC escalation and password-reset readiness."
                },
                "network" => new[]
                {
                    "Verify egress firewall and DNS logging visibility for the ports and domains demonstrated in this training trace.",
                    "Ensure Enforce mode outbound host-firewall containment is enabled on production endpoints."
                },
                "soc" => new[]
                {
                    "Compare step scores against your estate's contain threshold and rule-pack exclusions before switching new hosts to Enforce.",
                    "Validate SIEM/webhook forwarding and kernel credential-guard exemptions on test workloads."
                },
                _ => new[]
                {
                    "Compare each numbered step with the score bar to see how correlated behaviors cross the containment threshold.",
                    "Try switching between Teacher, SOC analyst, and Mom above to compare technical and plain-language summaries."
                }
            };
        }

        bool hasCreds = c.Steps.Any(s => Classify(s) is StepKind.CredentialStore or StepKind.Lsass);
        bool hasNet = c.RemoteEndpoints.Count > 0 || c.Domains.Count > 0;
        string endpoints = c.RemoteEndpoints.Count > 0 ? IncidentDigest.Redact(string.Join(", ", c.RemoteEndpoints.Take(3)), redact) : "";
        string domains = c.Domains.Count > 0 ? IncidentDigest.Redact(string.Join(", ", c.Domains.Take(3)), redact) : "";

        return personaId switch
        {
            "mom" => new[]
            {
                hasCreds
                    ? "Change your important browser or account passwords from a clean device and turn on two-step sign-in codes."
                    : "Ask someone you trust in IT or support to look over this program before letting it run again.",
                c.MonitorOnly
                    ? "Turn BruceEDR protection from watch-only mode to active blocking so it can freeze bad programs for you."
                    : "Leave the frozen program quarantined until support confirms whether it should be removed."
            },
            "executive" => new[]
            {
                hasCreds
                    ? "Direct IT security to rotate affected user sessions and enforce MFA re-authentication for the workstation owner."
                    : "Have IT security validate whether the flagged application belongs to an approved business workflow.",
                c.MonitorOnly
                    ? "Transition endpoint policy from monitor-only to active enforcement so future high-risk chains are stopped automatically."
                    : "Confirm any staged temporary files or startup entries left before containment have been removed."
            },
            "network" => new[]
            {
                hasNet
                    ? $"Pivot in firewall, proxy, and DNS logs on {(endpoints.Length > 0 ? endpoints : domains)} to check whether any other hosts communicated with the same infrastructure."
                    : "Confirm in perimeter NetFlow and DNS logs that no unmonitored child process established outbound traffic around the incident window.",
                hasNet
                    ? "Block confirmed malicious destination IPs or domains at the egress proxy/DNS sinkhole and inspect bytes sent prior to containment."
                    : "Keep host egress monitoring active in case a secondary loader attempts delayed C2 callback."
            },
            "soc" => new[]
            {
                $"Verify process tree and binary provenance for {c.ProcessName} (pid {c.Pid}){(c.MonitorOnly ? " and isolate/terminate immediately since monitor mode skipped containment" : " before terminating or releasing from quarantine")}.",
                hasCreds
                    ? "Revoke browser session cookies/OAuth tokens, rotate exposed credentials, and remove any staged archives in Temp."
                    : "Inspect persistence locations (Run keys, Startup folders, Scheduled Tasks, Services) and hunt process/command-line IOCs across the fleet.",
                hasNet
                    ? $"Hunt across SIEM/proxy telemetry for connections or DNS lookups matching {(endpoints.Length > 0 ? endpoints : domains)}."
                    : "Review full command line and parent process ancestry to rule out sanctioned admin automation."
            },
            _ => new[]
            {
                $"Inspect the parent chain ({(c.Lineage.Count > 1 ? IncidentDigest.Redact(string.Join(" > ", c.Lineage), redact) : c.ProcessName)}) to verify whether you or an approved installer started this program.",
                hasCreds
                    ? "Reset passwords and active browser sessions if this activity was unexpected, since credential files were accessed."
                    : "Check any temporary archives or startup entries mentioned in the steps and remove them if unauthorized."
            }
        };
    }

    private static string CleanEvidence(IncidentStep step, bool redact)
    {
        string raw = step.Evidence.Count > 0
            ? string.Join("; ", step.Evidence.Take(2).Select(e => PointsPrefix.Replace(e, "")))
            : step.Title;
        raw = IncidentDigest.Redact(raw, redact);
        var buf = new char[raw.Length];
        for (int i = 0; i < raw.Length; i++)
            buf[i] = char.IsControl(raw[i]) ? ' ' : raw[i];
        string clean = new string(buf).Trim();
        return clean.Length <= 180 ? clean : clean[..177] + "...";
    }

    private static string SummarizeNet(IncidentCase c)
    {
        if (c.RemoteEndpoints.Count > 0 && c.Domains.Count > 0)
            return $"{c.RemoteEndpoints[0]} / {c.Domains[0]}";
        if (c.RemoteEndpoints.Count > 0)
            return c.RemoteEndpoints[0];
        if (c.Domains.Count > 0)
            return c.Domains[0];
        return "none recorded";
    }
}

# Safe processes

Programs BruceEDR never suspends, firewall-blocks or kills, even in enforce mode. Detection
still scores them and every verdict is still recorded; only the response is withheld, and the
log says so:

```
pid 3700: playbook 'high-score-untrusted' refused because WmiPrvSE (C:\Windows\System32\wbem\WmiPrvSE.exe) is on the safe-process list; nothing was suspended, blocked or killed (verdict recorded)
```

The agent reads every `*.json` file in this folder (`response.safeProcessesPath`) when it
starts. Restart the service after editing a list.

## What is already safe without a list

The containment guard (`Response/ContainmentGuard.cs`) always refuses:

- System and Idle, and the agent itself;
- any process Windows runs protected (PPL): csrss, services, a PPL lsass, Defender and other
  antivirus engines that run protected;
- the Windows processes the watchlist protects (svchost, lsass, winlogon, explorer and the
  rest of `Watchlist.ProtectedProcesses`), when the instance is the real one, as described below.

The lists here are for everything else a machine needs: WMI, Search, VM guest tools, your
backup or management agent.

## Format

```json
{
  "description": "What these programs are.",
  "processes": [
    { "image": "%ProgramFiles%\\Vendor\\Agent\\agent.exe", "why": "the backup agent" }
  ]
}
```

- `image` is the full path of the program. Environment variables such as `%SystemRoot%`,
  `%ProgramFiles%` and `%ProgramFiles(x86)%` expand. A bare name is ignored: anyone can name
  a program `WmiPrvSE.exe`.
- `why` and `description` are for people; the agent ignores them.

## When an entry counts

An entry is honoured only for the real program, started by Windows:

- **The file**: no account other than SYSTEM, Administrators or TrustedInstaller can change it,
  add a file beside it, or move a folder above it. A copy in a user's folder is contained as
  usual.
- **The instance**: the process runs under a service account (SYSTEM, LOCAL SERVICE, NETWORK
  SERVICE, a service SID). Any user can start `C:\Windows\System32\wbem\WmiPrvSE.exe` and hollow
  it out; that copy runs as the user and is contained.
- **The list file**: a `.json` file a standard user could edit is not loaded, and the log says
  why.

Script hosts are refused whatever the file says (`powershell.exe`, `cmd.exe`, `wscript.exe`,
`mshta.exe`, `rundll32.exe`, `regsvr32.exe` and the like): everything one of them ran would be
beyond containment.

## Shipped lists

| File | Programs |
|------|----------|
| `windows.json` | WMI provider host, Windows Search, Optimize Drives, the UAC prompt |
| `virtualization.json` | VMware Tools, Hyper-V management, the WSL service |

Lab VMs in enforce mode contained WMI, Search and Defrag within minutes, and suspending VMware
Tools cut every guest operation off. Delete a file, or set `response.safeProcessesPath` to an
empty string, to drop the lists.

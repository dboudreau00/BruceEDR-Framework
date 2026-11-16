# BruceFilter lab

The kit for testing BruceFilter in a virtual machine:

- `BruceLab.exe` drives the driver through its scenarios and checks every result. It is
  plain C with the C runtime linked in, so it runs in a bare VM. `build.ps1` builds it.
- `lab.ps1` prepares a signed package on the build machine, then installs, tests and removes
  the driver inside the VM.

Only `prepare` runs on the build machine; it builds and signs files and touches nothing else.
Every other step changes the VM's boot options, certificate stores and kernel, so use a VM you
can throw away, and take a snapshot before you start.

## The VM

- Windows 10 2004 or later, or Windows 11, x64.
- **Secure Boot off.** Test signing cannot be switched on under it. Hyper-V (generation 2):
  Settings, Security, clear "Enable Secure Boot". VMware: Settings, Options, Advanced, clear
  "Enable secure boot".
- Windows PowerShell 5.1, which Windows ships with, is enough.

## On the build machine

```
cd kernel\BruceFilter
nuget restore packages.config -PackagesDirectory packages      # once
.\lab\lab.ps1 prepare                                           # add -WithAgent for the agent step
```

That runs `build.ps1`, signs copies of `BruceFilter.sys` and its catalog with a lab certificate,
and stages `x64\lab-package`:

| File | |
|------|---|
| `BruceFilter.sys`, `.inf`, `brucefilter.cat` | the driver package, signed with the lab certificate |
| `BruceFilter.pdb` | symbols, for reading a crash dump in the VM |
| `BruceLab.exe` | the harness |
| `BruceLab.cer` | the lab certificate the VM is told to trust |
| `lab.ps1`, `README.md` | this kit |
| `agent\` | a self-contained BruceEDR agent (`-WithAgent` only) |

The lab certificate is self-signed for code signing, made once in `x64\lab-cert` and reused, so
a VM that trusts it keeps trusting rebuilds. Its private key is `x64\lab-cert\BruceLab.pfx`
(not password-protected): `x64\` is ignored by git, and the `.cer` belongs in lab VMs only.

## In the VM

Copy `lab-package` into the VM, open Windows PowerShell **as administrator** in that folder:

```
Set-ExecutionPolicy -Scope Process Bypass
.\lab.ps1 testsigning          # then Restart-Computer
.\lab.ps1 install              # trusts BruceLab.cer, DiInstallDriver on the INF, fltmc load BruceFilter
.\lab.ps1 test                 # a few minutes; ends with LAB PASSED or LAB FAILED
```

`test` copies `BruceLab.exe` twice: `C:\Program Files\BruceLab\BruceLab.exe` is the copy the lab
policy trusts, and `C:\BruceLab\BruceLab.exe` an identical but untrusted one. It runs the
harness as SYSTEM through a one-off scheduled task (the driver's port admits SYSTEM only), and
prints `C:\BruceLab\report.txt`. The harness replaces the driver's live policy with one lab store,
`\brucelab\secret store\`, trusted to the first copy alone; when it finishes it empties the
policy and switches blocking off. If the BruceEDR service is running, `test` stops it for the
run (the port admits one client), and starts it again afterwards. The run makes a Volume Shadow
Copy of the lab volume for two scenarios and deletes it again; besides the two folders (and the agent it pauses) it is
the one thing `test` changes, and the dry run never does it.

Then, as needed:

```
.\lab.ps1 verifier on          # Driver Verifier's standard checks on BruceFilter.sys; Restart-Computer, then test again
.\lab.ps1 verifier off         # then Restart-Computer
.\lab.ps1 agent                # the BruceEDR service end to end (a package built -WithAgent)
.\lab.ps1 status               # the driver's protocol, policy size and counters
.\lab.ps1 reset                # empty policy, blocking off (after an interrupted run)
.\lab.ps1 uninstall -RemoveCertificate -RemoveAgent   # resets the driver first: while blocking is on it refuses fltmc unload
```

`agent` installs the agent under `C:\Program Files\BruceEDR`, or replaces one an older package
installed (its config and logs stay; the service and the watchdog task are stopped first, since
both hold its files), with `kernelBlocking` on and `response.mode` set to
enforce (monitor mode never blocks). The playbook it sets only logs: the probe reads a browser
store on purpose, and the default playbook would suspend it and leave the run waiting. It
trusts the first BruceLab copy for Chrome's store and creates a fake Chrome store under
`C:\BruceLab\agentdata`, then checks that the kernel refuses the untrusted copy, lets the
trusted one in, and that the agent logged the refusal in its `incidents.jsonl`. The agent
stays installed until `uninstall -RemoveAgent`.

## Results so far

Both VMs ran with BIOS firmware (no Secure Boot) and test signing on. The first runs used the
first 24 scenarios; the current build ran all 51 rows.

| Windows | 24 rows | 24 rows, Driver Verifier | 51 rows (current build) | Agent end to end |
|---------|---------|--------------------------|-------------------------|------------------|
| 10 Enterprise LTSC 21H2 (19044) | passed | passed, clean unload | passed under Driver Verifier: 46 pass, 3 observed, 2 skipped; clean unload after it | passed |
| 11 Pro 22H2 (22621) | passed | passed | passed: 44 pass, 3 observed, 4 skipped | passed |

The skipped rows are 40 and 41 (SYSTEM in a workgroup VM cannot use `\\localhost\C$`), and on
Windows 11 also 38 and 39 (the shadow copy was not made that run). Row 29 reached the recheck
after the open and its cancel in both VMs (`reopen`, rechecked +1), row 38 showed the filter
attaches to a shadow copy's volume, row 42 refused a short name on the folder above the store,
rows 45 to 47 showed the process guard refusing a program that reaches into a trusted copy it
did not start (rows 43, 44, 48 and 49 allowed, as designed), and rows 50 and 51 showed
`fltmc unload` and `fltmc detach` refused while blocking is on. The unload after the run, with
the process guard's reports sent, was clean under Driver Verifier.

With one read waiting, the harness lost up to a third of the reports in a scenario's burst
(they count as dropped, and the refusal still stands); with eight it received every one: 22 of
22 on Windows 10 under Driver Verifier, 28 of 28 on Windows 11.

The post-create recheck ran 0 to 4 times in those runs, and none of it was the lab's doing: row 12
(open by file id) was reported as `open`, so the filter manager had resolved the name for it
before the open and the pre-create callback refused it; the run with `rechecked 0` passed row 12
the same way. The rechecks counted were opens by file id that other programs in the VM made
(the recheck is requested for every open by id whose name does not match). Row 29 is the one
that reaches the recheck on purpose.

With the agent in enforce mode and its default playbook, both VMs ran 25 minutes without a
hang: the containment guard refused lsass, csrss, MsMpEng, NisSrv, svchost, sihost, System and
the agent itself. WmiPrvSE (it reads LSASS to answer process queries) and SearchIndexer were
still contained, which is why the `agent` step sets a playbook that only logs.

## The scenarios

The guarded store is `C:\BruceLab\work\data\BruceLab\Secret Store\`. Unless the row says
otherwise, the untrusted copy acts and blocking is on.

A row passes only if the refusal arrives as a report on the port **and the report carries
exactly the operation in the Report column** (`open` is the pre-create callback, `rename` and
`link` the set-information callback, `reopen` the post-create recheck). The older rows used to
accept any report, so a row could pass because a different callback refused it first; the Report
column now says which one, and the harness fails the row if another one (or an extra one) shows up.

The IRP paths, in the order the I/O manager issues them:

- A Win32 open (`CreateFile`, with backup semantics for a folder) is one `IRP_MJ_CREATE`. A guarded
  name is refused in pre-create (`BruceOpOpen`).
- Rename and hard link: before the `IRP_MJ_SET_INFORMATION` the I/O manager opens the parent folder
  of the target name ([Set File Information Processing](https://learn.microsoft.com/windows-hardware/drivers/ifs/set-file-information-processing)),
  an `IRP_MJ_CREATE` with `SL_OPEN_TARGET_DIRECTORY`, and for that open `FltGetFileNameInformation`
  returns the name of the containing folder ([FltGetFileNameInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetfilenameinformation)).
  A target inside the store is therefore refused as an `open` of the store, and the set-information
  hook only decides what that open let through: a destination whose parent is not guarded.
- A junction or symlink answers the first open with `STATUS_REPARSE`; the post-create callback
  ignores it and the I/O manager reissues the open under the target's name, which pre-create refuses.
- A name with `~1` is expanded through the normalized name in pre-create; the recheck is only for
  a name that query cannot give.

| # | Scenario | Expected | Report | What refuses it |
|---|----------|----------|--------|-----------------|
| 1 | reads the guarded file | refused | open | pre-create: the opened name matches |
| 2 | the trusted copy reads it | allowed | | pre-create matches, the image is trusted |
| 3 | opens the store folder itself | refused | open | pre-create: the folder's own name, without the trailing separator |
| 4 | lists the store folder | refused | open | pre-create of the folder open that `FindFirstFile` makes |
| 5 | the folder as `::$INDEX_ALLOCATION` | refused | open | pre-create: the stream suffix is stripped before matching |
| 6 | a stream on the store folder | refused | open | pre-create, the same |
| 7 | a stream of the guarded file | refused | open | pre-create: a name inside the store |
| 8 | the path in upper case | refused | open | pre-create, case-insensitive match |
| 9 | through a junction | refused | open | pre-create of the reissued open, after `STATUS_REPARSE` |
| 10 | through a file symlink | refused | open | the same, for a symlink |
| 11 | through 8.3 short names | refused | open | pre-create: `~1` triggers the normalized name query, which expands it |
| 12 | open by file id | refused | open | pre-create: the filter manager resolves the name of an open by id itself; the recheck is not involved (see row 29) |
| 13 | copies the file out | refused | open | pre-create of the source open; the destination is never created |
| 14 | deletes the file | refused | open | pre-create of the `DELETE` open (a delete does not reach the set-information hook) |
| 15 | hard links the file out | refused | open | pre-create of the source open; the link hook is not reached |
| 16 | renames a file into the store | refused | open | the I/O manager's open of the target folder (named for the store); the rename hook is not reached |
| 17 | hard links a file into the store | refused | open | the same, for a link |
| 18 | renames the store folder | refused | open | pre-create of the open of the folder being moved (it is the store); the rename hook is not reached |
| 19 | renames a folder above the store | refused | rename | the set-information hook's ancestor check: the open of `BruceLab` and of the target folder are not guarded |
| 20 | the trusted copy renames inside the store | allowed | | trust covers the target folder open and the hook |
| 21 | reads an unguarded file | allowed | | no false refusal |
| 22 | reads `Secret Store2\near.txt` | allowed | | whole names only |
| 23 | reads a hard link made before blocking | allowed: a known limit | | the name is the other link's; the documented residual |
| 24 | reads the file with blocking off | allowed | | the switch |
| 25 | renames a file onto the store folder's name | refused | rename | the target folder open is `...\BruceLab` and passes; the set-information hook sees the destination, the store itself |
| 26 | hard links a file onto the store folder's name | refused | link | the same, in the link hook |
| 27 | renames a file onto the store by its 8.3 name | observed | rename | in both VMs the normalized destination kept its final component as written, so the hook let it pass and NTFS refused the existing name (error 183); no way in, as an 8.3 name exists only for an existing item (needs 8.3 names) |
| 28 | renames the store folder by its 8.3 name | refused | open | pre-create of the source open: `~1` expanded to the store (needs 8.3 names) |
| 29 | open by id without the traverse right | refused | reopen | the post-create recheck and `FltCancelFileOpen` (see below) |
| 30 | the same, by the program the store trusts | observed | reopen | refused if the name is still unknown after the open (a program trusted for this store only), allowed if the post-create query returns it |
| 31 | by id, a near-miss file, no traverse right | observed | reopen | an unguarded file under the same folder: refused if the name stays unknown (the filter fails closed) |
| 32 | lists the store through the junction | refused | open | pre-create of the reissued folder open |
| 33 | through a directory symlink to the store | refused | open | the same, for a directory symlink (needs the symlink privilege) |
| 34 | opens the junction itself (`FILE_FLAG_OPEN_REPARSE_POINT`) | allowed | | the open is named `...\outside\jstore`, which is not guarded; with that flag the file system returns the reparse point, not the store, so only its reparse data (the target path) can be read, never the files |
| 35 | a file called `Secret Store` in another folder | allowed | | the fragment is `\brucelab\secret store\`: the last component alone matches nothing |
| 36 | a file called `BruceLab\Secret Store` elsewhere | refused: by design | open | the fragment matches anywhere in a path, whatever the item's type or its parents; over-matching is the cost of path fragments |
| 37 | the trusted copy started through a junction to its folder | allowed | | the image name is taken from the open the I/O manager reissues after the junction, so it is the trusted copy's own path |
| 38 | reads the file in a Volume Shadow Copy | refused | open | pre-create, if the filter has an instance on the snapshot volume (see below) |
| 39 | the trusted copy reads it there | allowed | | the same, trusted |
| 40 | reads the file over SMB loopback | refused | open | pre-create of the SMB server's open of the local file (see below) |
| 41 | the trusted copy reads it over SMB loopback | refused: by design | open | the server's open is made by the System process, so no program is trusted through SMB |
| 42 | gives a folder above the store a short name | refused | rename | the set-information callback decides `FileShortNameInformation` like a rename of that folder: since Windows 10 1903 any caller with DELETE access may set a short name of its choosing |

Rows 43 to 49 test the [process guard](../docs/process-guard.md). Rows 45 to 49 reach into a
trusted copy the harness starts and keeps running (`probe hold`); the harness is its creator, so
the probes are not. Their reports are `process` (a process handle) and `thread` (a thread handle).

| # | Scenario | Expected | Report | What it exercises |
|---|----------|----------|--------|-------------------|
| 43 | starts the trusted copy | allowed | | `CreateProcess`, as Explorer or Task Scheduler would: the creator keeps `THREAD_SUSPEND_RESUME`, or it could not resume the new process's first thread |
| 44 | starts the trusted copy suspended, writes into it, resumes it | observed (expected: refused, no report) | | the creator loses the write and code rights on what it starts (residual 1 of the process guard); refused only if Windows makes the creator's process handle after the notify routine, which a VM must show before this row is judged |
| 45 | writes into the running trusted copy | refused | process | `PROCESS_VM_OPERATION` and `PROCESS_VM_WRITE` taken from the handle |
| 46 | copies a handle out of it | refused | process | `PROCESS_DUP_HANDLE` taken from the handle |
| 47 | suspends one of its threads | refused | thread | `THREAD_SUSPEND_RESUME` and `THREAD_SET_CONTEXT` taken from the handle |
| 48 | the trusted copy writes into it | allowed | | an image trusted for the same stores keeps every right |
| 49 | writes into it with blocking off | allowed | | the guard acts only while blocking is on |

Two more rows follow the scenarios, run as SYSTEM while blocking is on:

| # | Check | Expected | What it exercises |
|---|-------|----------|-------------------|
| 50 | `FilterUnload` (what `fltmc unload` calls) | refused, 0x801F0010 | the unload callback refuses a non-mandatory unload |
| 51 | `FilterDetach` on the system volume (what `fltmc detach` calls) | refused, 0x801F0010 | the instance-teardown callback refuses a manual detach |

Neither is ever allowed to succeed in a run: that would remove the filter mid-run, and the row
fails. A mandatory unload (`sc stop BruceFilter`) cannot be refused and is not tried.

Scenarios whose set-up could not be made show SKIP: no 8.3 names on the volume (11, 27, 28), no symlink privilege (10, 33), no junction (9, 32, 34, 37), a traverse
deny that does not stop a token without the privilege (29 to 31), no SMB loopback (40, 41), no shadow
copy (38, 39), no trusted copy held (45 to 49). The `observed` rows are recorded in the report, not judged; their output says what
the OS did.

### Row 29: the post-create recheck

`BrucePreCreate` asks for the recheck when the name of an open cannot be resolved, and for every
open by file id whose name does not match. The lab cannot make the name query fail by itself:
the filter manager resolves the name for an open by id, so row 12 is refused in pre-create. What
does fail it, and is documented to, is an open by id by a caller without traverse privilege:
`FltGetFileNameInformation` returns `STATUS_ACCESS_DENIED` for it (the return codes of the
[FltGetFileNameInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetfilenameinformation)
page), because the file system must not give such a caller the path
([Checking for Other Special Cases on IRP_MJ_CREATE](https://learn.microsoft.com/windows-hardware/drivers/ifs/checking-for-other-special-cases--on-irp-mj-create)).
The open itself is allowed: the file's own ACL is all it needs. The row sets exactly that up:

- the folder above the store (`...\BruceLab`) gets an ACE denying `FILE_TRAVERSE` to Everyone (only
  a token without `SeChangeNotifyPrivilege`, "bypass traverse checking", is ever checked for it;
  every ordinary token has the privilege, so every other row is unaffected);
- the probe runs with a copy of the harness's own token from which that one privilege was removed
  (`CreateRestrictedToken`, `CreateProcessAsUser`);
- before the driver is armed, the harness opens the secret by path with that token and requires
  access denied from the file system, or the three rows are skipped;
- the probe opens the secret by its file id (`OpenFileById`).

Pre-create then gets `STATUS_ACCESS_DENIED` from the name query, `byId` makes it request the
recheck, the file system opens the file, and the post-create callback either gets the name (the
guarded store: refused) or gets no name (still refused). Both end in `FltCancelFileOpen` and a
`reopen` report; the row also prints how much the driver's `Rechecked` counter moved. If the report
says `open` instead, the filter manager resolved the name in pre-create after all and this row is
no recheck test. A dry run on Windows 11 shows the two facts the row relies on, without a driver:
the open by id succeeds for that token, and the open by path does not.

### Shadow copy (rows 38 and 39)

The harness makes a Volume Shadow Copy of the lab volume as SYSTEM through the CIM class
`Win32_ShadowCopy` (a small PowerShell script it writes to `work\vss.ps1`, run once to create and
once to delete), reads the secret through the copy's device object
(`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\BruceLab\work\...`, the root of the copy is the
device object: [Requester Access to Shadow Copied Data](https://learn.microsoft.com/windows/win32/vss/requestor-access-to-shadow-copied-data)),
and deletes the copy at the end. `InstanceSetup` only declines network file systems, so the
expectation is an instance on the snapshot volume, an opened name that contains the fragment,
and a refusal. Whether FltMgr attaches to the snapshot volume is the OS's: UNVERIFIED until a VM
run, and the row fails if the read is allowed, which is the finding. A shadow copy the harness
could not delete is named in `work\vss.txt`; `lab.ps1 reset` and the next `test` delete it. A dry
run never makes one.

### SMB loopback (rows 40 and 41)

`\\localhost\C$\...` goes through the SMB client, a network file system the filter does not attach
to (`InstanceSetup` returns `STATUS_FLT_DO_NOT_ATTACH`), so that leg is never seen. The local SMB
server then opens the file on the local volume, where the filter is attached, in the System
process: the open is refused as an untrusted open and reported under the System process, not the
probe's pid, which is why these rows take a report from any process. The trusted copy is refused
too: the server, not the trusted program, makes the open. The harness opens the share itself,
with blocking off, before it starts, and skips the rows if it cannot (SYSTEM in a workgroup VM may
not be able to use `C$`). The server-side attribution is UNVERIFIED until a VM run.

## When something fails

- **`install`: the installed driver is not this package's.** Windows Setup keeps a newer
  `BruceFilter.sys` it finds in place, so a package built before the driver on disk leaves that
  other driver installed, and the lab would test a binary it did not ship. Run `uninstall`, delete
  `C:\Windows\System32\drivers\BruceFilter.sys` (it belongs to TrustedInstaller: `takeown /f` it
  first), then `install` again.
- **`install`: fltmc load fails.** Event Viewer, Applications and Services Logs, Microsoft,
  Windows, CodeIntegrity, Operational usually names the reason: test signing off, or the lab
  certificate not trusted.
- **The VM crashes (bugcheck).** It reboots with a dump in `C:\Windows\MEMORY.DMP` or
  `C:\Windows\Minidump`. Open it in WinDbg with `BruceFilter.pdb` from the package beside it
  and run `!analyze -v`. Driver Verifier makes such failures surface at the faulty call.
- **A FAIL row.** The row shows what was expected, what happened and which report arrived
  (`open+reopen` means both arrived), with a note when the access denied did not come from
  the driver (no report) or the operation was allowed. The counters at the end show what the
  driver counted, rechecks included. `.\lab.ps1 reset` clears an interrupted run and deletes
  a shadow copy it left behind.
- **No report file.** BruceLab could not start as SYSTEM, or could not connect: run
  `.\lab.ps1 status`.
- **The guest stops starting programs with the agent running.** Before the containment guard,
  the default playbook suspended csrss, svchost and the Defender engine within minutes, and
  every new program then waited on a scan that never came. Boot the VM from its install ISO,
  open a command prompt in Windows Setup (Shift+F10), load the installed system's
  `Windows\System32\config\SYSTEM` hive with `reg load`, and set `Services\BruceEDR` `Start` to 4
  in each control set; the agent's own log is in `Program Files\BruceEDR\incidents.jsonl`.

`BruceLab.exe run <work> <trusted> <untrusted> --dry-run` runs the same scenarios without the
driver, expecting every operation to succeed (a rename or link onto an existing name may answer
"already exists" instead): a check of the lab itself on any machine, and it also shows what the
file system does under the rows that depend on it (an open by id without the traverse privilege).
A shell without the symlink privilege skips rows 10 and 33, and a dry run never makes the shadow
copy (rows 38 and 39 skip).

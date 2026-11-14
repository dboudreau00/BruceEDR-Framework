<#
.SYNOPSIS
  BruceFilter lab: stage a signed package on the build machine, then install, test and remove
  the driver inside a disposable test VM.
.DESCRIPTION
  On the build machine (the repository copy of this script):
    ./lab.ps1 prepare [-WithAgent] [-WdkPackages <dir>]
        Builds with ..\build.ps1, signs copies of the driver and its catalog with a lab
        certificate made for the purpose (a .pfx kept beside the build output, never added to a
        certificate store on this machine), and stages ..\x64\lab-package. -WithAgent adds a
        self-contained BruceEDR agent for the end-to-end step.

  Inside the test VM, from an elevated Windows PowerShell in a copy of lab-package:
    ./lab.ps1 testsigning          turn test signing on (Secure Boot must be off), then reboot
    ./lab.ps1 install              trust the lab certificate, install and load the driver
    ./lab.ps1 test                 BruceLab's scenarios as SYSTEM (one scenario makes and deletes a
                                   Volume Shadow Copy of C:); prints the report
    ./lab.ps1 verifier on          Driver Verifier (standard checks) on BruceFilter.sys; reboot
    ./lab.ps1 verifier off|status
    ./lab.ps1 agent                the BruceEDR service end to end (package built -WithAgent)
    ./lab.ps1 status               the driver's protocol, policy size and counters
    ./lab.ps1 reset                empty policy, blocking off
    ./lab.ps1 uninstall [-RemoveCertificate] [-RemoveAgent]
                                   resets the driver (blocking off) first: while blocking is on it
                                   refuses fltmc unload and fltmc detach

  The VM steps change that machine's boot options, certificate stores and kernel. Run them only
  in a VM you can throw away.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("prepare", "testsigning", "install", "test", "verifier", "agent", "status", "reset", "uninstall")]
    [string]$Step,
    [Parameter(Position = 1)]
    [ValidateSet("on", "off", "status")]
    [string]$Mode = "status",
    [switch]$WithAgent,
    [switch]$RemoveCertificate,
    [switch]$RemoveAgent,
    [string]$WdkPackages
)

$ErrorActionPreference = "Stop"
$TrustedDir = Join-Path $env:ProgramFiles "BruceLab"     # admin-only: the copy the lab policy trusts
$LabRoot = "C:\BruceLab"                                 # the untrusted copy, the lab tree, reports
$AgentDir = Join-Path $env:ProgramFiles "BruceEDR"
$DriverFiles = "BruceFilter.sys", "BruceFilter.inf", "brucefilter.cat"

function Fail([string]$message) {
    Write-Host "FAILED: $message" -ForegroundColor Red
    exit 1
}

function Note([string]$message) { Write-Host $message -ForegroundColor Cyan }

# Sets a property on a parsed JSON object, adding it when a hand-edited config lacks it.
function Set-ConfigValue($object, [string]$name, $value) {
    if ($object.PSObject.Properties.Name -contains $name) { $object.$name = $value }
    else { $object | Add-Member -NotePropertyName $name -NotePropertyValue $value }
}

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail "run this step from an elevated PowerShell"
    }
}

function Assert-Package {
    foreach ($file in $DriverFiles + "BruceLab.exe", "BruceLab.cer") {
        if (-not (Test-Path (Join-Path $PSScriptRoot $file))) {
            Fail "$file is missing: run this step from a copy of lab-package (lab.ps1 prepare makes it)"
        }
    }
}

function Test-FilterLoaded {
    return [bool]((& fltmc filters) | Select-String -Pattern "^BruceFilter\s")
}

# DiInstallDriver and DiUninstallDriver install and remove a primitive driver package (Windows 10
# 1903 and later) with no user interface. rundll32's InstallHinfSection needs an interactive
# desktop: from a script, a scheduled task or a remote session it silently does nothing.
function Get-DriverApi {
    if (-not ("BruceLab.NewDev" -as [type])) {
        Add-Type -Namespace BruceLab -Name NewDev -MemberDefinition @'
[DllImport("newdev.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool DiInstallDriverW(IntPtr hwndParent, string infPath, uint flags, out bool needReboot);
[DllImport("newdev.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool DiUninstallDriverW(IntPtr hwndParent, string infPath, uint flags, out bool needReboot);
'@
    }
    return [BruceLab.NewDev]
}

# ---------------------------------------------------------------- build machine

function Get-LabCertificate([string]$dir) {
    $pfx = Join-Path $dir "BruceLab.pfx"
    $cer = Join-Path $dir "BruceLab.cer"
    if (-not (Test-Path $pfx)) {
        New-Item -ItemType Directory -Force $dir | Out-Null
        $rsa = [System.Security.Cryptography.RSA]::Create(3072)
        $request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=BruceFilter Lab (test signing only)", $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $codeSigning = New-Object System.Security.Cryptography.OidCollection
        [void]$codeSigning.Add((New-Object System.Security.Cryptography.Oid "1.3.6.1.5.5.7.3.3"))
        $request.CertificateExtensions.Add(
            (New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($codeSigning, $false)))
        $request.CertificateExtensions.Add(
            (New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true)))
        $request.CertificateExtensions.Add(
            (New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($false, $false, 0, $true)))
        $cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(2))
        [IO.File]::WriteAllBytes($pfx, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx))
        [IO.File]::WriteAllBytes($cer, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        Note "lab certificate created: $cer (its private key: $pfx; keep both out of the repository)"
    }
    return @{ Pfx = $pfx; Cer = $cer }
}

function Invoke-Prepare {
    $driverDir = Split-Path -Parent $PSScriptRoot
    $build = Join-Path $driverDir "build.ps1"
    if (-not (Test-Path $build)) { Fail "prepare runs from the repository copy of lab.ps1 (kernel\BruceFilter\lab)" }
    if (-not $WdkPackages) { $WdkPackages = Join-Path $driverDir "packages" }

    & $build -Configuration Release -WdkPackages $WdkPackages
    if ($LASTEXITCODE -ne 0) { Fail "build.ps1 failed" }

    [xml]$packagesXml = Get-Content (Join-Path $driverDir "packages.config")
    $kitVersion = ($packagesXml.packages.package | Where-Object { $_.id -eq "Microsoft.Windows.WDK.x64" }).version
    $kitFolder = (($kitVersion -split '\.')[0..2] -join '.') + ".0"
    $signtool = Join-Path $WdkPackages "Microsoft.Windows.SDK.CPP.$kitVersion\c\bin\$kitFolder\x64\signtool.exe"
    $inf2cat = Join-Path $WdkPackages "Microsoft.Windows.WDK.x64.$kitVersion\c\bin\$kitFolder\x86\Inf2Cat.exe"
    foreach ($tool in $signtool, $inf2cat) { if (-not (Test-Path $tool)) { Fail "missing $tool" } }

    $out = Join-Path $driverDir "x64\Release"
    $package = Join-Path $driverDir "x64\lab-package"
    if (Test-Path $package) { Remove-Item -Recurse -Force $package }
    New-Item -ItemType Directory -Force $package | Out-Null
    Copy-Item (Join-Path $out "BruceFilter.sys"), (Join-Path $out "BruceFilter.inf"), (Join-Path $out "BruceFilter.pdb"),
        (Join-Path $out "lab\BruceLab.exe") $package
    Copy-Item (Join-Path $PSScriptRoot "lab.ps1"), (Join-Path $PSScriptRoot "README.md") $package

    $cert = Get-LabCertificate (Join-Path $driverDir "x64\lab-cert")
    Copy-Item $cert.Cer $package

    # Sign the driver, catalog the signed package, then sign the catalog. Loading a .pfx leaves a
    # persisted copy of its private key in the user's key folders each time; those copies are
    # removed afterwards, so the key lives only in the .pfx.
    Note "-- signing with the lab certificate"
    $keyFolders = @("$env:APPDATA\Microsoft\Crypto\Keys", "$env:APPDATA\Microsoft\Crypto\RSA") | Where-Object { Test-Path $_ }
    $keysBefore = @($keyFolders | ForEach-Object { Get-ChildItem $_ -Recurse -File -Force -ErrorAction SilentlyContinue } | ForEach-Object FullName)
    $signStart = (Get-Date).AddSeconds(-1)
    try {
        & $signtool sign /q /fd sha256 /f $cert.Pfx (Join-Path $package "BruceFilter.sys")
        if ($LASTEXITCODE -ne 0) { Fail "signtool could not sign BruceFilter.sys" }
        & $inf2cat "/driver:$package" "/os:10_VB_X64" | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "Inf2Cat failed on the package" }
        & $signtool sign /q /fd sha256 /f $cert.Pfx (Join-Path $package "brucefilter.cat")
        if ($LASTEXITCODE -ne 0) { Fail "signtool could not sign brucefilter.cat" }
    }
    finally {
        $keyFolders | ForEach-Object { Get-ChildItem $_ -Recurse -File -Force -ErrorAction SilentlyContinue } |
            Where-Object { $keysBefore -notcontains $_.FullName -and $_.CreationTime -ge $signStart } |
            ForEach-Object { Remove-Item -Force $_.FullName -ErrorAction SilentlyContinue }
    }

    if ($WithAgent) {
        $repo = Split-Path -Parent (Split-Path -Parent $driverDir)
        Note "-- publishing the agent (self-contained, win-x64)"
        & dotnet publish (Join-Path $repo "BruceEDR.csproj") -c Release -r win-x64 --self-contained true -o (Join-Path $package "agent") --nologo
        if ($LASTEXITCODE -ne 0) { Fail "dotnet publish failed" }
    }

    Note "lab package ready: $package"
    Get-ChildItem $package -File | ForEach-Object {
        "{0,-18} {1,10:N0} bytes  sha256 {2}" -f $_.Name, $_.Length, (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Note "Copy the folder into the VM, then from an elevated Windows PowerShell there: ./lab.ps1 testsigning (reboot), ./lab.ps1 install, ./lab.ps1 test"
}

# ---------------------------------------------------------------- inside the VM

function Invoke-TestSigning {
    Assert-Admin
    $secureBoot = $false
    try { $secureBoot = Confirm-SecureBootUEFI } catch { $secureBoot = $false }   # BIOS VMs throw
    if ($secureBoot) { Fail "Secure Boot is on: turn it off in the VM's settings first; test signing cannot be enabled under it" }
    & bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) { Fail "bcdedit refused the change" }
    Note "test signing takes effect after a reboot (Restart-Computer); then: ./lab.ps1 install"
}

function Get-InstalledDriverPath {
    $path = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\BruceFilter" -ErrorAction SilentlyContinue).ImagePath
    if (-not $path) { return $null }
    if ($path -like "\SystemRoot\*") { return Join-Path $env:SystemRoot $path.Substring(12) }
    if ($path -like "\??\*") { return $path.Substring(4) }
    if (-not [IO.Path]::IsPathRooted($path)) { return Join-Path $env:SystemRoot $path }
    return $path
}

function Invoke-Install {
    Assert-Admin
    Assert-Package
    if (((& bcdedit /enum "{current}") -join "`n") -notmatch "testsigning\s+Yes") {
        Fail "test signing is off: ./lab.ps1 testsigning, reboot, then install"
    }

    $cer = Join-Path $PSScriptRoot "BruceLab.cer"
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    Note "lab certificate trusted (LocalMachine Root and TrustedPublisher)"

    # A fixed copy of the package, so uninstall finds the same INF later.
    $driver = Join-Path $LabRoot "driver"
    New-Item -ItemType Directory -Force $driver | Out-Null
    foreach ($file in $DriverFiles) { Copy-Item (Join-Path $PSScriptRoot $file) $driver -Force }
    $inf = Join-Path $driver "BruceFilter.inf"
    $api = Get-DriverApi
    $reboot = $false
    if (-not $api::DiInstallDriverW([IntPtr]::Zero, $inf, 0, [ref]$reboot)) {
        Fail ("DiInstallDriver failed (error {0}): see C:\Windows\INF\setupapi.dev.log" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    if (-not (Get-Service BruceFilter -ErrorAction SilentlyContinue)) {
        Fail "the package installed but no BruceFilter service exists: see C:\Windows\INF\setupapi.dev.log"
    }
    if ($reboot) { Note "Windows asks for a restart to finish the driver install" }

    # Setup keeps a newer file it finds in place, so a package built before the driver already on
    # disk leaves that other driver installed; a lab run must never test a binary it did not ship.
    $image = Get-InstalledDriverPath
    if (-not $image -or -not (Test-Path $image) -or
        (Get-FileHash $image).Hash -ne (Get-FileHash (Join-Path $driver "BruceFilter.sys")).Hash) {
        Fail "the installed driver ($image) is not this package's BruceFilter.sys, as when Windows Setup keeps a newer file: ./lab.ps1 uninstall, delete that file, then install again"
    }

    if (-not (Test-FilterLoaded)) {
        & fltmc load BruceFilter
        if ($LASTEXITCODE -ne 0) { Fail "fltmc load BruceFilter failed ($LASTEXITCODE); the System event log says why" }
    }
    & fltmc filters
    & fltmc instances -f BruceFilter
    Note "BruceFilter is loaded. Next: ./lab.ps1 test"
}

function Install-LabCopies {
    New-Item -ItemType Directory -Force $TrustedDir, $LabRoot | Out-Null
    $trusted = Join-Path $TrustedDir "BruceLab.exe"
    $untrusted = Join-Path $LabRoot "BruceLab.exe"
    Copy-Item (Join-Path $PSScriptRoot "BruceLab.exe") $trusted -Force
    Copy-Item (Join-Path $PSScriptRoot "BruceLab.exe") $untrusted -Force
    return $trusted, $untrusted
}

# A shadow copy BruceLab made and could not delete is named in work\vss.txt (second line).
function Remove-StaleShadow {
    $file = Join-Path $LabRoot "work\vss.txt"
    if (-not (Test-Path $file)) { return }
    $id = @(Get-Content $file -ErrorAction SilentlyContinue)[1]
    if ($id -match '^\{[0-9A-Fa-f-]{36}\}$') {
        Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $id } | Remove-CimInstance
        Note "removed the shadow copy $id that an interrupted run left behind"
    }
    Remove-Item $file, (Join-Path $LabRoot "work\vss.ps1") -ErrorAction SilentlyContinue
}

function Format-ExitCode([int64]$code) {
    if ($code -gt 255) { return ("0x{0:X8}" -f $code) }
    return [string]$code
}

# Runs a program as SYSTEM through a one-off scheduled task; returns its exit code (-1: timed out).
# The task is removed again on every path out.
function Invoke-AsSystem([string]$exe, [string]$arguments, [int]$timeoutSeconds) {
    $name = "BruceLab-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $action = New-ScheduledTaskAction -Execute $exe -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    # Done when the new task's result is neither "has not run" (0x41303) nor "running" (0x41301).
    # LastTaskResult is a UInt32 and a task that cannot start leaves an HRESULT above 2^31, so it
    # is compared as Int64: a cast to Int32 would throw on those. LastRunTime is not compared
    # with this clock: Task Scheduler's stamp can lag it by seconds.
    $notRun = 267011
    $running = 267009
    try {
        Start-ScheduledTask -TaskName $name
        $watch = [Diagnostics.Stopwatch]::StartNew()
        do {
            Start-Sleep -Milliseconds 500
            $state = (Get-ScheduledTask -TaskName $name).State
            $result = [int64](Get-ScheduledTaskInfo -TaskName $name).LastTaskResult
            $done = $state -ne "Running" -and $result -ne $notRun -and $result -ne $running
        } while (-not $done -and $watch.Elapsed.TotalSeconds -lt $timeoutSeconds)
        if (-not $done) {
            Stop-ScheduledTask -TaskName $name
            return -1
        }
        return $result
    }
    finally {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# The port admits one client: BruceLab cannot connect while the agent holds it. A step that
# fails half way puts back what it already changed.
function Suspend-Agent {
    $state = @{ Service = $false; Watchdog = $false }
    try {
        $task = Get-ScheduledTask -TaskName "BruceEDRWatchdog" -ErrorAction SilentlyContinue
        if ($task -and $task.State -ne "Disabled") {
            Disable-ScheduledTask -TaskName "BruceEDRWatchdog" | Out-Null
            $state.Watchdog = $true
        }
        $service = Get-Service BruceEDR -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Stopped") {
            Note "stopping the BruceEDR service for the lab run (it holds the driver's only port connection)"
            Stop-Service BruceEDR -Force
            $state.Service = $true
        }
    }
    catch {
        Resume-Agent $state
        throw
    }
    return $state
}

function Resume-Agent($state) {
    try {
        if ($state.Service) {
            Start-Service BruceEDR
            Note "BruceEDR restarted: it pushes its own policy again as it connects"
        }
    }
    catch { Write-Warning "BruceEDR did not restart: $($_.Exception.Message)" }
    try { if ($state.Watchdog) { Enable-ScheduledTask -TaskName "BruceEDRWatchdog" | Out-Null } }
    catch { Write-Warning "the BruceEDRWatchdog task was not enabled again: $($_.Exception.Message)" }
}

function Invoke-Test {
    Assert-Admin
    Assert-Package
    if (-not (Test-FilterLoaded)) { Fail "BruceFilter is not loaded: ./lab.ps1 install" }
    $trusted, $untrusted = Install-LabCopies
    $report = Join-Path $LabRoot "report.txt"
    Remove-Item $report -ErrorAction SilentlyContinue
    Remove-StaleShadow

    $agent = Suspend-Agent
    try {
        Note "-- BruceLab run as SYSTEM (a few minutes: it makes and deletes a shadow copy of C:)"
        $code = Invoke-AsSystem $trusted "run `"$LabRoot\work`" `"$trusted`" `"$untrusted`" --report `"$report`"" 900
    }
    finally {
        Resume-Agent $agent
    }

    if (Test-Path $report) { Get-Content $report -Encoding UTF8 | ForEach-Object { Write-Host $_ } }
    else { Write-Host "no report was written ($report)" }
    Remove-StaleShadow
    if ($code -eq -1) { Fail "BruceLab did not finish within 15 minutes; ./lab.ps1 reset clears the driver's policy" }
    if ($code -ne 0) { Fail ("BruceLab exited {0} (1: a scenario failed; 2: setup or connection; 0x8...: the task could not start it)" -f (Format-ExitCode $code)) }
    Note "LAB PASSED. The report is $report"
}

function Invoke-StatusOrReset {
    Assert-Admin
    Assert-Package
    $trusted, $untrusted = Install-LabCopies
    $report = Join-Path $LabRoot "$Step.txt"
    Remove-Item $report -ErrorAction SilentlyContinue
    if ($Step -eq "reset") { Remove-StaleShadow }
    $agent = Suspend-Agent
    try { $code = Invoke-AsSystem $trusted "$Step --report `"$report`"" 120 }
    finally { Resume-Agent $agent }
    if (Test-Path $report) { Get-Content $report -Encoding UTF8 | ForEach-Object { Write-Host $_ } }
    if ($code -eq -1) { Fail "BruceLab $Step did not finish within 2 minutes" }
    if ($code -ne 0) { Fail ("BruceLab $Step exited {0}" -f (Format-ExitCode $code)) }
}

function Invoke-Verifier {
    Assert-Admin
    switch ($Mode) {
        "on" {
            & verifier /standard /driver BruceFilter.sys
            Note "Driver Verifier starts checking BruceFilter.sys after a reboot; then run ./lab.ps1 test again"
        }
        "off" {
            & verifier /reset
            Note "Driver Verifier stops after a reboot"
        }
        default { & verifier /querysettings }
    }
}

# The BruceEDR service end to end: it pushes its own policy, the kernel refuses an untrusted
# read of a (fake) Chrome store, and the agent logs the refusal as an ACTION event.
function Invoke-Agent {
    Assert-Admin
    Assert-Package
    $source = Join-Path $PSScriptRoot "agent"
    if (-not (Test-Path (Join-Path $source "BruceEDR.exe"))) { Fail "this package has no agent: on the build machine, ./lab.ps1 prepare -WithAgent" }
    if (-not (Test-FilterLoaded)) { Fail "BruceFilter is not loaded: ./lab.ps1 install" }
    $trusted, $untrusted = Install-LabCopies

    # An agent from an earlier run keeps blocking on, and this script is not trusted for the fake
    # store it writes: stop it and switch blocking off first. The service starts again below.
    Stop-ScheduledTask -TaskName "BruceEDRWatchdog" -ErrorAction SilentlyContinue
    $running = Get-Service BruceEDR -ErrorAction SilentlyContinue
    if ($running -and $running.Status -ne "Stopped") { Stop-Service BruceEDR -Force }
    Reset-DriverForUnload

    # The fake store exists before the agent switches blocking on.
    $profileDir = Join-Path $LabRoot "agentdata\Google\Chrome\User Data\Default"
    New-Item -ItemType Directory -Force $profileDir | Out-Null
    $loginData = Join-Path $profileDir "Login Data"
    Set-Content -Path $loginData -Value "lab: not a real Login Data" -Encoding ASCII

    $exe = Join-Path $AgentDir "BruceEDR.exe"
    $service = Get-Service BruceEDR -ErrorAction SilentlyContinue
    if (-not (Test-Path $exe)) {
        Copy-Item $source $AgentDir -Recurse
    }
    elseif (-not (Test-Path (Join-Path $AgentDir "BruceEDR.dll")) -or
            (Get-FileHash (Join-Path $AgentDir "BruceEDR.dll")).Hash -ne (Get-FileHash (Join-Path $source "BruceEDR.dll")).Hash) {
        # An agent from an older package is replaced in place; its config and logs stay. The
        # code is in BruceEDR.dll: BruceEDR.exe is the same apphost stub in every build.
        Note "replacing the installed agent with the one in this package"
        if ($service -and $service.Status -ne "Stopped") { Stop-Service BruceEDR -Force }
        # The watchdog task runs BruceEDR.exe from the same folder, which holds its files open.
        Stop-ScheduledTask -TaskName "BruceEDRWatchdog" -ErrorAction SilentlyContinue
        Get-Process BruceEDR -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$AgentDir\*" } |
            Stop-Process -Force
        Start-Sleep -Seconds 1
        Get-ChildItem $source | Where-Object { $_.Name -ne "bruce.config.json" } |
            Copy-Item -Destination $AgentDir -Recurse -Force
    }
    $configPath = Join-Path $AgentDir "bruce.config.json"
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    Set-ConfigValue $config.detection "kernelBlocking" $true
    Set-ConfigValue $config.response "mode" "enforce"   # monitor mode never blocks
    # The probe reads a browser store on purpose, and the default playbook suspends a program
    # that does: the run then waits forever on its own harness. This playbook only logs.
    $playbook = Join-Path $AgentDir "lab-playbook.json"
    Set-Content -Path $playbook -Encoding ASCII -Value '{ "rules": [ { "name": "lab-log-only", "minScore": 1, "actions": ["Log"] } ] }'
    Set-ConfigValue $config.response "playbookPath" $playbook
    $entry = New-Object PSObject -Property @{ image = $trusted; stores = @("chrome") }
    Set-ConfigValue $config.detection "kernelTrustedImages" @($entry)
    # Windows PowerShell 5.1 writes a byte order mark for -Encoding UTF8: written without one here.
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 32), (New-Object Text.UTF8Encoding($false)))
    Note "agent config: kernelBlocking on, response.mode enforce with a log-only playbook, $trusted trusted for chrome"

    $jsonl = Join-Path $AgentDir "incidents.jsonl"
    $before = 0
    if (Test-Path $jsonl) { $before = @(Get-Content $jsonl).Count }
    if ($service) {
        # The VM rescue boot disables a service that hung the guest; this run starts it again.
        if ($service.StartType -eq "Disabled") { Set-Service BruceEDR -StartupType Automatic }
        Restart-Service BruceEDR -Force
    }
    else {
        & $exe --install
        if ($LASTEXITCODE -ne 0) { Fail "BruceEDR.exe --install exited $LASTEXITCODE" }
    }

    Note "-- waiting for the agent to push its policy"
    $deadline = (Get-Date).AddSeconds(90)
    $enabled = $false
    while (-not $enabled -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        if (Test-Path $jsonl) {
            $new = @(Get-Content $jsonl | Select-Object -Skip $before)
            $new | Where-Object { $_ -match "kernel policy:|minifilter" } | ForEach-Object { Write-Host ("  " + ($_ | ConvertFrom-Json).Message) }
            $before += $new.Count
            $enabled = [bool]($new | Where-Object { $_ -match "kernel enforcement ENABLED" })
        }
    }
    if (-not $enabled) { Fail "the agent did not report kernel enforcement ENABLED within 90 s; see $jsonl" }

    $refused = Start-Process -FilePath $untrusted -ArgumentList "probe read `"$loginData`"" -Wait -PassThru -WindowStyle Hidden
    $allowed = Start-Process -FilePath $trusted -ArgumentList "probe read `"$loginData`"" -Wait -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    $logged = @(Get-Content $jsonl | Select-Object -Skip $before | Where-Object { $_ -match "Kernel refused" -and $_ -match ('"Pid":' + $refused.Id + '[,}]') })

    "untrusted read of the fake Login Data: exit {0} (expected 5, access denied)" -f $refused.ExitCode
    "trusted read: exit {0} (expected 0)" -f $allowed.ExitCode
    "agent event for the refusal: {0}" -f $(if ($logged.Count -gt 0) { ($logged[0] | ConvertFrom-Json).Message } else { "NONE" })
    if ($refused.ExitCode -ne 5 -or $allowed.ExitCode -ne 0 -or $logged.Count -eq 0) { Fail "agent end-to-end check failed" }
    Note "AGENT END TO END PASSED. The agent stays installed in enforce mode with kernel blocking on and the log-only lab playbook; ./lab.ps1 uninstall -RemoveAgent removes it."
}

# While blocking is on the driver refuses a non-mandatory unload (STATUS_FLT_DO_NOT_DETACH), so
# the driver is reset first: blocking off, empty policy. The agent holds the port's only
# connection and would switch blocking on again, so it is stopped for the unload.
function Reset-DriverForUnload {
    $lab = @((Join-Path $PSScriptRoot "BruceLab.exe"), (Join-Path $TrustedDir "BruceLab.exe")) |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lab) {
        Note "no BruceLab.exe to reset the driver with; the unload below may be refused while blocking is on"
        return
    }
    New-Item -ItemType Directory -Force $LabRoot | Out-Null
    $report = Join-Path $LabRoot "uninstall-reset.txt"
    $code = Invoke-AsSystem $lab "reset --report `"$report`"" 120
    if (Test-Path $report) { Get-Content $report -Encoding UTF8 | ForEach-Object { Write-Host $_ } }
    if ($code -ne 0) { Note "BruceLab reset exited $code; the unload below may be refused while blocking is on" }
}

function Invoke-Uninstall {
    Assert-Admin
    if ($RemoveAgent -and (Test-Path (Join-Path $AgentDir "BruceEDR.exe"))) {
        & (Join-Path $AgentDir "BruceEDR.exe") --uninstall
        Remove-Item -Recurse -Force $AgentDir -ErrorAction SilentlyContinue
    }
    $agent = Suspend-Agent
    try {
        if (Test-FilterLoaded) {
            Reset-DriverForUnload
            & fltmc unload BruceFilter
            if ($LASTEXITCODE -ne 0 -and (Test-FilterLoaded)) {
                # A service stop is a mandatory unload, which the driver cannot refuse.
                Note "fltmc unload failed ($LASTEXITCODE): the driver refuses it while blocking is on; forcing it with a service stop"
                & sc.exe stop BruceFilter
                Start-Sleep -Seconds 2
            }
            if (Test-FilterLoaded) { Fail "BruceFilter is still loaded; reboot the VM, then run uninstall again" }
        }
    }
    finally {
        # Left stopped when it is being removed (Suspend-Agent found no service then).
        Resume-Agent $agent
    }
    $inf = Join-Path $LabRoot "driver\BruceFilter.inf"
    if (Test-Path $inf) {
        $api = Get-DriverApi
        $reboot = $false
        if (-not $api::DiUninstallDriverW([IntPtr]::Zero, $inf, 0, [ref]$reboot)) {
            Write-Host ("DiUninstallDriver failed (error {0}); pnputil /enum-drivers lists the package to remove by hand" -f
                [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        if ($reboot) { Note "Windows asks for a restart to finish removing the driver" }
    }
    Remove-StaleShadow
    Remove-Item -Recurse -Force $TrustedDir, $LabRoot -ErrorAction SilentlyContinue
    if ($RemoveCertificate) {
        $cer = Join-Path $PSScriptRoot "BruceLab.cer"
        if (Test-Path $cer) {
            $thumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cer)).Thumbprint
            foreach ($store in "Root", "TrustedPublisher") {
                Remove-Item "Cert:\LocalMachine\$store\$thumbprint" -ErrorAction SilentlyContinue
            }
            Note "lab certificate removed from LocalMachine Root and TrustedPublisher"
        }
        else { Write-Warning "BruceLab.cer is not beside lab.ps1: the lab certificate was not removed" }
    }
    Note "BruceFilter unloaded and uninstalled. Test signing stays on: bcdedit /set testsigning off, then reboot."
}

switch ($Step) {
    "prepare"     { Invoke-Prepare }
    "testsigning" { Invoke-TestSigning }
    "install"     { Invoke-Install }
    "test"        { Invoke-Test }
    "verifier"    { Invoke-Verifier }
    "agent"       { Invoke-Agent }
    "status"      { Invoke-StatusOrReset }
    "reset"       { Invoke-StatusOrReset }
    "uninstall"   { Invoke-Uninstall }
}

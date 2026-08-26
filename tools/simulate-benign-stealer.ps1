#requires -Version 5.1
<#
    simulate-benign-stealer.ps1

    A HARMLESS test harness that reproduces the *shape* of an infostealer's
    collect -> archive -> exfil sequence so you can watch BruceEDR detect and
    contain it. It steals nothing and exfiltrates nothing:

      1. Creates a DUMMY file on a path that merely CONTAINS the fragment
         "\Google\Chrome\User Data\...\Login Data" under %TEMP% (NOT a real browser
         profile), with fake contents.
      2. Compresses that folder into %TEMP%\ps_loot.zip (an "archive in staging").
      3. Opens (and immediately closes) a TCP connection to 1.1.1.1:443, a public
         DNS resolver, to look like an outbound "exfil" connection.
      4. Sleeps so BruceEDR has time to suspend THIS PowerShell process, which
         is the whole point of the demo.

    RUN THIS ONLY IN A DISPOSABLE VM, and start BruceEDR first.
    When BruceEDR suspends this process, switch to its console and run:
        list        (see this powershell.exe, contained)
        info 1      (see the reason breakdown)
        resume 1    (release it)  -- or --  kill 1
#>

$ErrorActionPreference = 'Continue'
$root = Join-Path $env:TEMP 'PS_StealerSim'
$profile = Join-Path $root 'Google\Chrome\User Data\Default'
$zip = Join-Path $env:TEMP 'ps_loot.zip'

Write-Host '[sim] STEP 1: create a fake credential store (harmless dummy file)...' -ForegroundColor Cyan
New-Item -ItemType Directory -Path $profile -Force | Out-Null
# Deliberately fake, non-secret content:
Set-Content -Path (Join-Path $profile 'Login Data') -Value 'THIS-IS-A-HARMLESS-TEST-FILE-NO-REAL-SECRETS' -Encoding ASCII
Set-Content -Path (Join-Path $profile 'Local State') -Value 'test-local-state' -Encoding ASCII

Write-Host '[sim] STEP 2: stage an archive in %TEMP% ...' -ForegroundColor Cyan
if (Test-Path $zip) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
Compress-Archive -Path $root -DestinationPath $zip -Force

Write-Host '[sim] STEP 3: open a benign outbound connection (1.1.1.1:443) ...' -ForegroundColor Cyan
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('1.1.1.1', 443)   # public Cloudflare resolver; nothing is sent
    Start-Sleep -Milliseconds 300
    $client.Close()
    Write-Host '[sim]        connection opened and closed.' -ForegroundColor DarkGray
} catch {
    Write-Host "[sim]        outbound connect failed (fine for the demo): $($_.Exception.Message)" -ForegroundColor DarkGray
}

Write-Host ''
Write-Host '[sim] Sequence complete. This process should now be flagged/contained by BruceEDR.' -ForegroundColor Yellow
Write-Host '[sim] Sleeping 90s so you can observe/resume it. Ctrl+C to stop early.' -ForegroundColor Yellow
Start-Sleep -Seconds 90

Write-Host '[sim] Cleaning up dummy files...' -ForegroundColor Cyan
Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Write-Host '[sim] Done.' -ForegroundColor Green

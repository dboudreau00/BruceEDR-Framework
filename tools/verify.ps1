<#
.SYNOPSIS
  One command that proves the tree is healthy: clean build, full test suite, rule-pack
  validation, and an offline replay of every detection scenario.

.DESCRIPTION
  Run this before opening a pull request and before believing any claim that
  ProcessShield "works". It exercises the parts that can be checked without
  Administrator rights or a live ETW session:

    1. dotnet build   -- the whole solution, warnings as information
    2. dotnet test    -- the xUnit suite
    3. rules          -- every shipped JSON detection pack parses and validates
    4. replay         -- every scenario under Replay/scenarios meets its expectations

  Steps 3 and 4 run through the built console (`ProcessShield.exe --selftest`), which
  needs no elevation because it never starts a monitor.

.PARAMETER SkipTests
  Skip step 2. Useful only when iterating on the build itself.

.PARAMETER Configuration
  Debug or Release. Defaults to Release, which is what CI and the release script use.

.EXAMPLE
  ./tools/verify.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$failures = New-Object System.Collections.Generic.List[string]

function Step($name, $block) {
    Write-Host ""
    Write-Host "== $name " -NoNewline -ForegroundColor Cyan
    Write-Host ("=" * [Math]::Max(0, 60 - $name.Length)) -ForegroundColor DarkCyan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $block
        $sw.Stop()
        Write-Host ("   OK  ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Green
    } catch {
        $sw.Stop()
        Write-Host ("   FAILED  ({0:N1}s): {1}" -f $sw.Elapsed.TotalSeconds, $_.Exception.Message) -ForegroundColor Red
        $failures.Add($name)
    }
}

Write-Host "ProcessShield verify -- $Configuration" -ForegroundColor White

Step "build" {
    dotnet build "$root/ProcessShield.sln" -c $Configuration --nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet build exited $LASTEXITCODE" }
}

if (-not $SkipTests) {
    Step "tests" {
        # Deliberately NOT --no-build. The solution build above targets Release|x64 and
        # writes bin/x64/...; `dotnet test` on the project resolves the default platform and
        # reads bin/Release/... With --no-build those are different binaries, so this step
        # would silently run a stale DLL and report green for code that is not on disk.
        # That trap has already produced one false pass in this repo.
        dotnet test "$root/tests/ProcessShield.Tests/ProcessShield.Tests.csproj" `
            -c $Configuration --nologo
        if ($LASTEXITCODE -ne 0) { throw "dotnet test exited $LASTEXITCODE" }
    }
}

$exe = Join-Path $root "bin/x64/$Configuration/net8.0-windows/ProcessShield.exe"
if (-not (Test-Path $exe)) {
    $exe = Join-Path $root "bin/$Configuration/net8.0-windows/ProcessShield.exe"
}

if (Test-Path $exe) {
    Step "rules + replay (self-test)" {
        & $exe --selftest
        if ($LASTEXITCODE -ne 0) { throw "self-test exited $LASTEXITCODE" }
    }
} else {
    Write-Host ""
    Write-Host "   SKIPPED rules + replay: $exe not found" -ForegroundColor Yellow
}

Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "All checks passed." -ForegroundColor Green
    exit 0
}
Write-Host ("FAILED: " + ($failures -join ", ")) -ForegroundColor Red
exit 1

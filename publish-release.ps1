<#
.SYNOPSIS
  Build, test, and package a self-contained BruceEDR release for Windows x64.

.DESCRIPTION
  Produces artifacts/BruceEDR-<version>-win-x64.zip containing single-file,
  self-contained BruceEDR.exe (console) and BruceEDR.Gui.exe (desktop),
  plus the sample config, YARA rules, and docs. No .NET runtime required on the target.

.EXAMPLE
  ./publish-release.ps1 -Version 1.0
#>
[CmdletBinding()]
param(
    [string]$Version = "1.0",
    [string]$Rid     = "win-x64"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$name = "BruceEDR-v$Version-$Rid"
$artifacts = Join-Path $root "artifacts"
$stage = Join-Path $artifacts $name

Write-Host "== BruceEDR release $Version ($Rid) ==" -ForegroundColor Cyan

# Clean prior artifacts
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# 1) Gate on a clean build + green tests
Write-Host "-- build + test" -ForegroundColor Cyan
dotnet build "$root/BruceEDR.sln" -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw "build failed" }
dotnet test "$root/tests/BruceEDR.Tests/BruceEDR.Tests.csproj" -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

$common = @(
    "-c", "Release", "-r", $Rid,
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-p:EnableCompressionInSingleFile=true",
    "-p:DebugType=none"
)

# 2) Publish the console agent (single self-contained exe)
Write-Host "-- publish console" -ForegroundColor Cyan
$conOut = Join-Path $artifacts "_console"
if (Test-Path $conOut) { Remove-Item $conOut -Recurse -Force }
dotnet publish "$root/BruceEDR.csproj" @common -o $conOut
if ($LASTEXITCODE -ne 0) { throw "console publish failed" }

# 3) Publish the WPF GUI into a gui/ subfolder
Write-Host "-- publish gui" -ForegroundColor Cyan
$guiOut = Join-Path $artifacts "_gui"
if (Test-Path $guiOut) { Remove-Item $guiOut -Recurse -Force }
dotnet publish "$root/gui/BruceEDR.Gui/BruceEDR.Gui.csproj" @common -o $guiOut
if ($LASTEXITCODE -ne 0) { throw "gui publish failed" }

# 4) Stage: console exe at the root, gui exe under gui/, plus config/rules/docs
Write-Host "-- stage" -ForegroundColor Cyan
Copy-Item (Join-Path $conOut "BruceEDR.exe") $stage -Force
New-Item -ItemType Directory -Force -Path (Join-Path $stage "gui") | Out-Null
Copy-Item (Join-Path $guiOut "BruceEDR.Gui.exe") (Join-Path $stage "gui") -Force

Copy-Item (Join-Path $root "bruce.config.json") $stage -Force
# rules/ carries both the YARA samples and the JSON detection packs the agent loads at
# startup; Replay/scenarios and intel/feeds are what make --selftest and the intel feature
# work out of the box in the shipped layout.
Copy-Item (Join-Path $root "rules") (Join-Path $stage "rules") -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $stage "Replay") | Out-Null
Copy-Item (Join-Path $root "Replay/scenarios") (Join-Path $stage "Replay/scenarios") -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $stage "intel") | Out-Null
Copy-Item (Join-Path $root "intel/feeds") (Join-Path $stage "intel/feeds") -Recurse -Force

foreach ($doc in "README.md","LICENSE","GETTING_STARTED.md") {
    Copy-Item (Join-Path $root $doc) $stage -Force
}
Copy-Item (Join-Path $root "docs") (Join-Path $stage "docs") -Recurse -Force

# 4b) Gate the release on the packaged content actually working. This runs the shipped
#     exe against the shipped rules and scenarios, so a rule pack that got left out of the
#     zip fails the build rather than the user's first run.
Write-Host "-- self-test the staged build" -ForegroundColor Cyan
& (Join-Path $stage "BruceEDR.exe") --selftest
if ($LASTEXITCODE -ne 0) { throw "self-test failed against the staged release" }

# 5) Zip
Write-Host "-- zip" -ForegroundColor Cyan
$zip = Join-Path $artifacts "$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal

# cleanup intermediate publish dirs
Remove-Item $conOut,$guiOut -Recurse -Force -ErrorAction SilentlyContinue

$size = "{0:N1} MB" -f ((Get-Item $zip).Length / 1MB)
Write-Host "== done: $zip ($size) ==" -ForegroundColor Green

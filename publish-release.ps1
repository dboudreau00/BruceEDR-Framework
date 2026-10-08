<#
.SYNOPSIS
  Build, test, and package a self-contained BruceEDR release for Windows x64.

.DESCRIPTION
  Produces, in artifacts/:
    BruceEDR-v<version>-win-x64.zip  single-file, self-contained BruceEDR.Gui.exe (the
                                     desktop app) and BruceEDR.exe (the agent), side by side
                                     with the config, rules and docs
    BruceEDR-v<version>-win-x64.msi  the same files as an installer (installer/Package.wxs)
  No .NET runtime is required on the target. Both are built from one staged folder that
  has passed the self-test, so the zip and the MSI ship exactly what was tested.

.PARAMETER Version
  Release version (x.y.z). Defaults to the <Version> in Directory.Build.props.

.EXAMPLE
  ./publish-release.ps1 -Version 3.2.0
#>
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$Rid     = "win-x64"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if (-not $Version) {
    $Version = ([xml](Get-Content (Join-Path $root "Directory.Build.props"))).Project.PropertyGroup.Version
}
# MSI product versions are numeric; fail now, not after the build, tests and publish.
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version '$Version' must be x.y.z" }
$name = "BruceEDR-v$Version-$Rid"
$artifacts = Join-Path $root "artifacts"
$stage = Join-Path $artifacts $name

Write-Host "== BruceEDR release $Version ($Rid) ==" -ForegroundColor Cyan

# Clean prior artifacts
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# 1) Gate on a clean build + green tests
Write-Host "-- build + test" -ForegroundColor Cyan
dotnet build "$root/BruceEDR.sln" -c Release --nologo "-p:Version=$Version"
if ($LASTEXITCODE -ne 0) { throw "build failed" }
dotnet test "$root/tests/BruceEDR.Tests/BruceEDR.Tests.csproj" -c Release --nologo "-p:Version=$Version"
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

$common = @(
    "-c", "Release", "-r", $Rid,
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-p:EnableCompressionInSingleFile=true",
    "-p:DebugType=none",
    "-p:Version=$Version"
)

# 2) Publish the console agent (single self-contained exe)
Write-Host "-- publish console" -ForegroundColor Cyan
$conOut = Join-Path $artifacts "_console"
if (Test-Path $conOut) { Remove-Item $conOut -Recurse -Force }
dotnet publish "$root/BruceEDR.csproj" @common -o $conOut
if ($LASTEXITCODE -ne 0) { throw "console publish failed" }

# 3) Publish the WPF desktop app
Write-Host "-- publish gui" -ForegroundColor Cyan
$guiOut = Join-Path $artifacts "_gui"
if (Test-Path $guiOut) { Remove-Item $guiOut -Recurse -Force }
dotnet publish "$root/gui/BruceEDR.Gui/BruceEDR.Gui.csproj" @common -o $guiOut
if ($LASTEXITCODE -ne 0) { throw "gui publish failed" }

# 4) Stage: both exes side by side, plus config/rules/docs. They must share one folder:
#    each reads bruce.config.json and rules/ from its own directory, and a GUI in a gui/
#    subfolder silently ran on built-in defaults with no rule packs.
Write-Host "-- stage" -ForegroundColor Cyan
Copy-Item (Join-Path $conOut "BruceEDR.exe") $stage -Force
Copy-Item (Join-Path $guiOut "BruceEDR.Gui.exe") $stage -Force
# Single-file publish does not bundle native libraries, and WPF needs its own beside the
# exe (wpfgfx_cor3, PresentationNative_cor3, ...). Copying only the exe shipped a desktop
# app that could not start. Not IncludeNativeLibrariesForSelfExtract: that unpacks DLLs
# into a user-writable temp folder, which an elevated app must not load from.
Get-ChildItem $guiOut -Filter *.dll | Copy-Item -Destination $stage -Force
foreach ($native in "wpfgfx_cor3.dll", "PresentationNative_cor3.dll") {
    if (-not (Test-Path (Join-Path $stage $native))) { throw "staged desktop app is missing $native" }
}

Copy-Item (Join-Path $root "bruce.config.json") $stage -Force
# rules/ carries both the YARA samples and the JSON detection packs the agent loads at
# startup; Replay/scenarios and intel/feeds are what make --selftest and the intel feature
# work out of the box in the shipped layout.
Copy-Item (Join-Path $root "rules") (Join-Path $stage "rules") -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $stage "Replay") | Out-Null
Copy-Item (Join-Path $root "Replay/scenarios") (Join-Path $stage "Replay/scenarios") -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $stage "intel") | Out-Null
Copy-Item (Join-Path $root "intel/feeds") (Join-Path $stage "intel/feeds") -Recurse -Force
# intel/geo is what the GUI's Network map resolves addresses against. Without it the tab
# degrades to "map data missing" -- shipping the feature but not its data.
Copy-Item (Join-Path $root "intel/geo") (Join-Path $stage "intel/geo") -Recurse -Force

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
#    Not Compress-Archive: it writes entry names with backslash separators, which Windows
#    and .NET happen to accept but Info-ZIP unzip on Linux/macOS (and many archive
#    libraries) treat as literal filename characters -- extracting the release as a flat
#    pile of files with names like "rules\detection\x.json". ZipFile.CreateFromDirectory writes the
#    forward slashes the zip spec calls for, so the layout survives on every platform.
Write-Host "-- zip" -ForegroundColor Cyan
$zip = Join-Path $artifacts "$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
if (-not ('System.IO.Compression.ZipFile' -as [type])) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
}
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $stage, $zip, [System.IO.Compression.CompressionLevel]::Optimal, $false)

# 6) MSI from the same staged folder.
Write-Host "-- msi" -ForegroundColor Cyan
$msiOut = Join-Path $artifacts "_msi"
if (Test-Path $msiOut) { Remove-Item $msiOut -Recurse -Force }
$msi = Join-Path $artifacts "$name.msi"
if (Test-Path $msi) { Remove-Item $msi -Force }   # never leave an older build beside the new zip
# --no-incremental: a re-run after a failed validation must validate again, not report
# the stale MSI the failed run left behind as up to date.
Remove-Item (Join-Path $root "installer/obj") -Recurse -Force -ErrorAction SilentlyContinue
dotnet build "$root/installer/BruceEDR.Installer.wixproj" -c Release --nologo --no-incremental `
    "-p:Version=$Version" "-p:StageDir=$stage" -o $msiOut
if ($LASTEXITCODE -ne 0) { throw "msi build failed" }
Copy-Item (Join-Path $msiOut "$name.msi") $msi -Force

# cleanup intermediate publish dirs
Remove-Item $conOut,$guiOut,$msiOut -Recurse -Force -ErrorAction SilentlyContinue

foreach ($f in $zip, $msi) {
    Write-Host ("== done: {0} ({1:N1} MB) ==" -f $f, ((Get-Item $f).Length / 1MB)) -ForegroundColor Green
}

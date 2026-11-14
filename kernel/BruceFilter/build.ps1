<#
.SYNOPSIS
  Builds, analyses and tests the BruceFilter minifilter.
.DESCRIPTION
  Uses the WDK NuGet packages (packages.config) and the MSVC compiler from any Visual Studio
  2022 with the C++ x64 tools. Neither the WDK installer nor Visual Studio's "Windows Driver
  Kit" component is needed; with that component installed, BruceFilter.vcxproj builds the
  same sources from Visual Studio.
    1. compile the driver with the WDK's kernel-mode defaults, warnings as errors
    2. code analysis with the WDK's driver plugins and recommended driver rules
    3. link BruceFilter.sys
    4. stamp a copy of the INF, check it with InfVerif, and build its catalog with Inf2Cat
    5. build and run the user-mode policy tests against the same policy source
    6. build the VM lab harness (lab\BruceLab.c; see lab\README.md)
  Restore the packages first:  nuget restore packages.config -PackagesDirectory packages
.EXAMPLE
  ./build.ps1
.EXAMPLE
  ./build.ps1 -WdkPackages C:\wdk\packages -Configuration Debug
#>
[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [string]$WdkPackages = (Join-Path $PSScriptRoot "packages"),
    [switch]$SkipAnalysis,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

function Fail([string]$message) {
    Write-Host "FAILED: $message" -ForegroundColor Red
    exit 1
}

function Invoke-Tool([string]$exe, [string[]]$arguments, [string]$what) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { Fail "$what (exit $LASTEXITCODE)" }
}

# ---------------------------------------------------------------- toolchain
[xml]$packagesXml = Get-Content (Join-Path $PSScriptRoot "packages.config")
$kitVersion = ($packagesXml.packages.package | Where-Object { $_.id -eq "Microsoft.Windows.WDK.x64" }).version
if (-not $kitVersion) { Fail "packages.config names no Microsoft.Windows.WDK.x64 version" }
$kitFolder = (($kitVersion -split '\.')[0..2] -join '.') + ".0"
$wdk = Join-Path $WdkPackages "Microsoft.Windows.WDK.x64.$kitVersion\c"
$sdk = Join-Path $WdkPackages "Microsoft.Windows.SDK.CPP.$kitVersion\c"
$sdk64 = Join-Path $WdkPackages "Microsoft.Windows.SDK.CPP.x64.$kitVersion\c"
foreach ($required in $wdk, $sdk, $sdk64) {
    if (-not (Test-Path $required)) {
        Fail "missing $required. Run: nuget restore packages.config -PackagesDirectory packages"
    }
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { Fail "Visual Studio 2022 with the C++ x64 tools is required (no vswhere.exe)" }
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { Fail "no Visual Studio with the MSVC x64 tools" }
$msvc = Get-ChildItem (Join-Path $vs "VC\Tools\MSVC") | Sort-Object { [version]$_.Name } | Select-Object -Last 1
$bin = Join-Path $msvc.FullName "bin\Hostx64\x64"
$cl = Join-Path $bin "cl.exe"
$link = Join-Path $bin "link.exe"
$env:PATH = "$bin;$env:PATH"

$inc = Join-Path $wdk "Include\$kitFolder"
$sdkInc = Join-Path $sdk "Include\$kitFolder"
$kmLib = Join-Path $wdk "Lib\$kitFolder\km\x64"
$wdkBin = Join-Path $wdk "bin\$kitFolder\x64"
$out = Join-Path $PSScriptRoot "x64\$Configuration"
New-Item -ItemType Directory -Force $out | Out-Null
Write-Host "BruceFilter $Configuration | MSVC $($msvc.Name) | WDK $kitVersion" -ForegroundColor Cyan

# ---------------------------------------------------------------- 1-2) compile and analyse
# The WDK's kernel-mode defaults (WindowsDriver.Common, .KernelMode and .x64 props). The
# target is Windows 10 2004 and later: ExAllocatePool2 arrived there.
$compile = @(
    "/nologo", "/c", "/kernel", "/GS", "/Gy", "/GR-", "/Zp8", "/Zc:wchar_t-", "/Oi", "/Qspectre",
    "/W4", "/WX", "/wd4603", "/wd4627", "/wd4986", "/wd4987", "/wd4748", "/Zi", "/FS",
    "/D_WIN64", "/D_AMD64_", "/DAMD64", "/DDEPRECATE_DDK_FUNCTIONS=1",
    "/D_WIN32_WINNT=0x0A00", "/DWINVER=0x0A00", "/DWINNT=1", "/DNTDDI_VERSION=0x0A000008",
    # Kit headers are system headers, as Visual Studio treats them: their own warnings do not
    # fail this build, while BruceFilter's code stays at /W4 /WX.
    "/external:W0", "/external:I", "$inc\km", "/external:I", "$inc\km\crt", "/external:I", "$inc\shared",
    "/external:I", "$sdkInc\shared",
    "/Fo$out\", "/Fd$out\BruceFilter.pdb"
)
if ($Configuration -eq "Release") { $compile += "/O2", "/DNDEBUG" } else { $compile += "/Od", "/DDBG=1" }
if (-not $SkipAnalysis) {
    $compile += "/analyze", "/analyze:external-", "/analyze:plugin", "$wdkBin\WindowsPrefast.dll",
                "/analyze:plugin", "$wdkBin\drivers.dll",
                "/analyze:ruleset", "$wdk\CodeAnalysis\DriverRecommendedRules.ruleset",
                # The driver rule set includes MSVC's native rule sets by name.
                "/analyze:rulesetdirectory", "$wdk\CodeAnalysis;$($msvc.FullName)\CodeAnalysis\Rulesets"
}
$compile += (Join-Path $PSScriptRoot "BruceFilter.c"), (Join-Path $PSScriptRoot "BruceFilterPolicy.c")
Write-Host "-- compile$(if (-not $SkipAnalysis) { ' + driver code analysis' })" -ForegroundColor Cyan
Invoke-Tool $cl $compile "compile"

# ---------------------------------------------------------------- 3) link
$sys = Join-Path $out "BruceFilter.sys"
$linkArgs = @(
    "/nologo", "/DRIVER", "/SUBSYSTEM:NATIVE,10.00", "/ENTRY:GsDriverEntry", "/NODEFAULTLIB",
    "/OPT:REF", "/OPT:ICF", "/MERGE:_TEXT=.text", "/MERGE:_PAGE=PAGE", "/SECTION:INIT,d", "/RELEASE",
    "/DEBUG", "/INCREMENTAL:NO", "/MANIFEST:NO", "/osversion:10.0",
    "/IGNORE:4198,4010,4037,4039,4065,4070,4078,4087,4089,4221,4108,4088,4218,4235",
    "/OUT:$sys", "/PDB:$out\BruceFilter.pdb", "/LIBPATH:$kmLib",
    "BufferOverflowFastFailK.lib", "ntoskrnl.lib", "hal.lib", "wmilib.lib", "fltMgr.lib",
    (Join-Path $out "BruceFilter.obj"), (Join-Path $out "BruceFilterPolicy.obj")
)
Write-Host "-- link" -ForegroundColor Cyan
Invoke-Tool $link $linkArgs "link"

# ---------------------------------------------------------------- 4) INF
$propsXml = [xml](Get-Content (Join-Path $PSScriptRoot "..\..\Directory.Build.props"))
$productVersion = @($propsXml.Project.PropertyGroup | ForEach-Object { $_.Version } | Where-Object { $_ })[0]
$inf = Join-Path $out "BruceFilter.inf"
Copy-Item (Join-Path $PSScriptRoot "BruceFilter.inf") $inf -Force
Write-Host "-- stampinf + infverif" -ForegroundColor Cyan
Invoke-Tool (Join-Path $wdkBin "stampinf.exe") @("-f", $inf, "-d", "*", "-a", "amd64", "-v", "$productVersion.0") "stampinf"
# Driver isolation (/w) applies from the build of the INF's driver-store section on; the
# downlevel sections keep Windows 10 2004 to 23H2 working. /h is what a signing submission checks.
$infverif = Join-Path $wdk "tools\$kitFolder\x64\infverif.exe"
Invoke-Tool $infverif @("/v", "/w", "/wbuild", "10.0.25952", $inf) "infverif /w"
Invoke-Tool $infverif @("/v", "/h", $inf) "infverif /h"
# The catalog a signature goes on; building it also proves the INF and the files it names agree.
Invoke-Tool (Join-Path $wdk "bin\$kitFolder\x86\Inf2Cat.exe") @("/driver:$out", "/os:10_VB_X64") "inf2cat"

# ---------------------------------------------------------------- 5) policy tests
if (-not $SkipTests) {
    $testOut = Join-Path $out "test"
    New-Item -ItemType Directory -Force $testOut | Out-Null
    $testArgs = @(
        "/nologo", "/W4", "/WX", "/Zi", "/MT", "/analyze", "/analyze:external-", "/DUNICODE", "/D_UNICODE",
        "/external:W0", "/external:I", "$($msvc.FullName)\include", "/external:I", "$sdkInc\ucrt",
        "/external:I", "$sdkInc\um", "/external:I", "$sdkInc\shared",
        "/Fe$testOut\PolicyTests.exe", "/Fo$testOut\", "/Fd$testOut\PolicyTests.pdb",
        (Join-Path $PSScriptRoot "test\PolicyTests.c"), (Join-Path $PSScriptRoot "BruceFilterPolicy.c"),
        "/link", "/LIBPATH:$($msvc.FullName)\lib\x64", "/LIBPATH:$sdk64\um\x64", "/LIBPATH:$sdk64\ucrt\x64"
    )
    Write-Host "-- policy tests" -ForegroundColor Cyan
    Invoke-Tool $cl $testArgs "policy test build"
    Invoke-Tool (Join-Path $testOut "PolicyTests.exe") @() "policy tests"
}

# ---------------------------------------------------------------- 6) VM lab harness
# Static CRT, so it runs in a bare VM; lab\lab.ps1 stages it beside the driver.
$labOut = Join-Path $out "lab"
New-Item -ItemType Directory -Force $labOut | Out-Null
$labArgs = @(
    "/nologo", "/W4", "/WX", "/O2", "/MT", "/analyze", "/analyze:external-", "/DUNICODE", "/D_UNICODE",
    "/external:W0", "/external:I", "$($msvc.FullName)\include", "/external:I", "$sdkInc\ucrt",
    "/external:I", "$sdkInc\um", "/external:I", "$sdkInc\shared",
    "/Fe$labOut\BruceLab.exe", "/Fo$labOut\",
    (Join-Path $PSScriptRoot "lab\BruceLab.c"),
    "/link", "/LIBPATH:$($msvc.FullName)\lib\x64", "/LIBPATH:$sdk64\um\x64", "/LIBPATH:$sdk64\ucrt\x64"
)
Write-Host "-- lab harness" -ForegroundColor Cyan
Invoke-Tool $cl $labArgs "lab harness build"

$hash = (Get-FileHash $sys -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host ("OK  {0}  {1:N0} bytes  sha256 {2}" -f $sys, (Get-Item $sys).Length, $hash) -ForegroundColor Green

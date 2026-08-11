// Tests for ProcessShield.Monitoring.MonitorSupport and its companion
// SignalDeduplicator.
//
// Scope note: the four ETW monitors in this area (RegistryMonitor, DnsMonitor,
// AmsiMonitor, ProcessAccessMonitor) are deliberately NOT exercised here. Each of
// them needs Administrator, a free kernel/user ETW session slot, and a live trace
// pump before a single line of their logic runs, none of which a unit test can
// provide honestly. That is precisely why every decision those monitors make -- name
// normalisation, noise filtering, access-mask interpretation, script triage,
// duplicate suppression -- was pushed down into the pure helpers tested below, so the
// untestable part of each monitor is reduced to session setup and event dispatch.
//
// Nothing here touches the network, the registry, the filesystem or another process.
// The single environment-dependent function (IsIgnorableDomain reading the machine
// name) has an injecting overload, and that overload is what the assertions use.

using ProcessShield.Core;
using ProcessShield.Monitoring;
using Xunit;

namespace ProcessShield.Tests;

public class MonitorSupportRegistryTests
{
    [Fact]
    public void NormalizeRegistryKey_Maps_Machine_Hive_And_Appends_Value()
    {
        string result = MonitorSupport.NormalizeRegistryKey(
            @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Updater");

        Assert.Equal(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater", result);
    }

    [Fact]
    public void NormalizeRegistryKey_Maps_User_Hive()
    {
        string result = MonitorSupport.NormalizeRegistryKey(
            @"\REGISTRY\USER\S-1-5-21-1234\Software\Foo", null);

        Assert.Equal(@"HKU\S-1-5-21-1234\Software\Foo", result);
    }

    [Fact]
    public void NormalizeRegistryKey_Handles_Bare_Hive_With_No_Subkey()
    {
        Assert.Equal("HKLM", MonitorSupport.NormalizeRegistryKey(@"\REGISTRY\MACHINE", null));
        Assert.Equal("HKU", MonitorSupport.NormalizeRegistryKey(@"\REGISTRY\USER", ""));
    }

    [Fact]
    public void NormalizeRegistryKey_Accepts_Prefix_Without_Leading_Separator()
    {
        Assert.Equal(@"HKLM\SOFTWARE\X",
            MonitorSupport.NormalizeRegistryKey(@"REGISTRY\MACHINE\SOFTWARE\X", null));
    }

    // Adversarial: ETW hands out a name with '/' separators, doubled separators and a
    // trailing separator all at once. All three must collapse without losing a label.
    [Fact]
    public void NormalizeRegistryKey_Collapses_Mixed_And_Duplicated_Separators()
    {
        string result = MonitorSupport.NormalizeRegistryKey(@"\REGISTRY/MACHINE\\SOFTWARE//Test\", null);

        Assert.Equal(@"HKLM\SOFTWARE\Test", result);
    }

    [Fact]
    public void NormalizeRegistryKey_Preserves_Case_Outside_The_Hive_Token()
    {
        Assert.Equal(@"HKLM\SoFtWaRe\MiXeD",
            MonitorSupport.NormalizeRegistryKey(@"\Registry\Machine\SoFtWaRe\MiXeD", null));
    }

    [Fact]
    public void NormalizeRegistryKey_Leaves_Unknown_Registry_Roots_Verbatim()
    {
        // Application hives (\REGISTRY\A\...) have no Win32 abbreviation; inventing one
        // would be a lie in the alert text.
        Assert.Equal(@"\REGISTRY\A\{guid}\Software",
            MonitorSupport.NormalizeRegistryKey(@"\REGISTRY\A\{guid}\Software", null));
    }

    [Fact]
    public void NormalizeRegistryKey_Leaves_Kcb_Relative_Fragments_Alone()
    {
        // The realistic partial-name case: no hive at all, just what the KCB gave us.
        Assert.Equal(@"CurrentVersion\Run\Evil",
            MonitorSupport.NormalizeRegistryKey(@"CurrentVersion\Run", "Evil"));
    }

    [Theory]
    [InlineData(null, null, "")]
    [InlineData("", "", "")]
    [InlineData("   ", "   ", "")]
    [InlineData(@"\\\\", "", "")]
    [InlineData("", "Updater", "Updater")]
    public void NormalizeRegistryKey_Degrades_Gracefully_On_Empty_Input(
        string? key, string? value, string expected)
    {
        Assert.Equal(expected, MonitorSupport.NormalizeRegistryKey(key, value));
    }

    [Fact]
    public void NormalizeRegistryKey_Strips_Nul_Padding()
    {
        // ETW strings are frequently NUL padded; a stray NUL would otherwise become
        // part of the key and break every substring match downstream.
        Assert.Equal(@"HKLM\Foo\Bar",
            MonitorSupport.NormalizeRegistryKey("\\REGISTRY\\MACHINE\\Foo\0", "Bar\0"));
    }

    [Fact]
    public void NormalizeRegistryKey_Trims_Separators_Off_The_Value_Name()
    {
        Assert.Equal(@"HKLM\Foo\Bar", MonitorSupport.NormalizeRegistryKey(@"\REGISTRY\MACHINE\Foo", @"\Bar\"));
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater")]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\x")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run\z")]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\EvilSvc\ImagePath")]
    [InlineData(@"HKLM\System\ControlSet001\Services\EvilSvc\ImagePath")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe\MonitorProcess")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load")]
    [InlineData(@"HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls\x")]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup")]
    [InlineData(@"HKCU\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32")]
    [InlineData(@"HKCU\Software\Classes\CLSID\{guid}\TreatAs")]
    [InlineData(@"HKLM\SOFTWARE\Classes\CLSID\{guid}\LocalServer32")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\EvilTask")]
    [InlineData(@"HKCU\Software\Classes\ms-settings\Shell\Open\Command")]
    [InlineData(@"HKLM\System\CurrentControlSet\Control\Lsa\Security Packages")]
    [InlineData(@"HKCU\Environment\UserInitMprLogonScript")]
    public void IsPersistenceKey_Flags_Known_Autostart_Locations(string path)
    {
        Assert.True(MonitorSupport.IsPersistenceKey(path), path);
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced")]
    [InlineData(@"HKLM\SOFTWARE\Vendor\Product\Settings")]
    [InlineData(@"HKLM\SYSTEM\Setup")]
    [InlineData(@"HKCU\Control Panel\Desktop\Wallpaper")]
    [InlineData(@"HKLM\SOFTWARE\Classes\CLSID\{guid}\ProgID")]   // CLSID but no server rewrite
    [InlineData(@"HKLM\SOFTWARE\Vendor\Services\Config")]        // \Services\ without a control set
    [InlineData("")]
    [InlineData("   ")]
    public void IsPersistenceKey_Ignores_Ordinary_Keys(string path)
    {
        Assert.False(MonitorSupport.IsPersistenceKey(path), path);
    }

    [Fact]
    public void IsPersistenceKey_Is_Separator_And_Case_Agnostic()
    {
        Assert.True(MonitorSupport.IsPersistenceKey("HKLM/SOFTWARE/Microsoft/Windows/CURRENTVERSION/run"));
    }
}

public class MonitorSupportDomainTests
{
    [Theory]
    [InlineData("EXAMPLE.COM.", "example.com")]
    [InlineData("  *.Contoso.COM.  ", "contoso.com")]
    [InlineData("*.*.example.com", "example.com")]
    [InlineData("..example.com", "example.com")]
    [InlineData("example.com...", "example.com")]
    [InlineData(".example.com", "example.com")]
    [InlineData("Example.Com", "example.com")]
    public void NormalizeDomain_Canonicalises(string input, string expected)
    {
        Assert.Equal(expected, MonitorSupport.NormalizeDomain(input));
    }

    // Adversarial: a bare root dot, a bare wildcard, and a wildcard with nothing behind
    // it must all reduce to empty rather than to a one-character "domain" that would
    // then be scored, logged and compared against the IOC lists.
    [Theory]
    [InlineData((string?)null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(".")]
    [InlineData("...")]
    [InlineData("*")]
    [InlineData("*.")]
    [InlineData("*.*.")]
    public void NormalizeDomain_Returns_Empty_For_Degenerate_Input(string? input)
    {
        Assert.Equal("", MonitorSupport.NormalizeDomain(input));
    }

    [Fact]
    public void NormalizeDomain_Strips_Nul_Padding()
    {
        Assert.Equal("evil.com", MonitorSupport.NormalizeDomain("\0evil.com\0"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("localhost")]
    [InlineData("app.localhost")]
    [InlineData("1.0.0.127.in-addr.arpa")]
    [InlineData("in-addr.arpa")]
    [InlineData("0.0.0.0.ip6.arpa")]
    [InlineData("printer.local")]
    [InlineData("local")]
    [InlineData("wpad")]
    [InlineData("wpad.corp.example.com")]
    [InlineData("isatap")]
    [InlineData("isatap.corp.example.com")]
    public void IsIgnorableDomain_Suppresses_Documented_Noise(string domain)
    {
        Assert.True(MonitorSupport.IsIgnorableDomain(domain, "DESKTOP-ABC"), domain);
    }

    [Theory]
    [InlineData("evil.com")]
    [InlineData("cdn.evil.com")]
    [InlineData("mylocal")]                    // not ".local"
    [InlineData("attacker.local.evil.com")]    // ".local" in the middle, not the suffix
    [InlineData("wpadx.example.com")]          // "wpad" prefix without the label boundary
    [InlineData("in-addr.arpa.evil.com")]
    public void IsIgnorableDomain_Keeps_Real_Destinations(string domain)
    {
        Assert.False(MonitorSupport.IsIgnorableDomain(domain, "DESKTOP-ABC"), domain);
    }

    [Fact]
    public void IsIgnorableDomain_Suppresses_The_Hosts_Own_Name()
    {
        Assert.True(MonitorSupport.IsIgnorableDomain("desktop-abc", "DESKTOP-ABC"));
        Assert.True(MonitorSupport.IsIgnorableDomain("DESKTOP-ABC.corp.example.com", "DESKTOP-ABC"));
    }

    // Adversarial: a two-character hostname must not turn "pc.evil.com" into an
    // allow-listed name. Exact equality still applies; the prefix rule does not.
    [Fact]
    public void IsIgnorableDomain_Short_Machine_Name_Cannot_Whitelist_A_Registered_Domain()
    {
        Assert.False(MonitorSupport.IsIgnorableDomain("pc.evil.com", "PC"));
        Assert.True(MonitorSupport.IsIgnorableDomain("pc", "PC"));
    }

    [Fact]
    public void IsIgnorableDomain_Tolerates_A_Missing_Machine_Name()
    {
        Assert.False(MonitorSupport.IsIgnorableDomain("evil.com", null));
        Assert.False(MonitorSupport.IsIgnorableDomain("evil.com", ""));
    }

    [Fact]
    public void IsIgnorableDomain_Renormalises_Its_Input()
    {
        // Callers should normalise first, but a raw name must not slip through the
        // filter just because it kept its trailing root dot or its uppercase.
        Assert.True(MonitorSupport.IsIgnorableDomain("WPAD.Corp.Example.COM.", "DESKTOP-ABC"));
    }

    [Fact]
    public void IsIgnorableDomain_SingleArgument_Overload_Uses_The_Real_Machine_Name()
    {
        Assert.True(MonitorSupport.IsIgnorableDomain("localhost"));

        string self = MonitorSupport.NormalizeDomain(Environment.MachineName);
        if (self.Length > 0) Assert.True(MonitorSupport.IsIgnorableDomain(self));
    }
}

public class MonitorSupportPipeTests
{
    [Theory]
    [InlineData(@"\\.\pipe\srvsvc", "srvsvc")]
    [InlineData(@"\\?\pipe\srvsvc", "srvsvc")]
    [InlineData(@"\Device\NamedPipe\srvsvc", "srvsvc")]
    [InlineData(@"\??\pipe\srvsvc", "srvsvc")]
    [InlineData(@"\pipe\srvsvc", "srvsvc")]
    [InlineData(@"\\SERVER01\pipe\atsvc", "atsvc")]
    [InlineData(@"\\.\PIPE\MsFteWds", "MsFteWds")]          // case preserved on the name
    [InlineData(@"//./pipe/x", "x")]                        // forward slashes folded
    public void NormalizePipeName_Strips_Every_Prefix_Form(string raw, string expected)
    {
        Assert.Equal(expected, MonitorSupport.NormalizePipeName(raw));
    }

    // Adversarial: an already-stripped name must survive untouched -- normalising twice
    // must be a no-op, or a pipe name would be silently mangled by a second pass.
    [Fact]
    public void NormalizePipeName_Is_Idempotent()
    {
        string once = MonitorSupport.NormalizePipeName(@"\\.\pipe\atsvc");
        Assert.Equal("atsvc", once);
        Assert.Equal("atsvc", MonitorSupport.NormalizePipeName(once));
        Assert.Equal("plain-name", MonitorSupport.NormalizePipeName("plain-name"));
    }

    [Fact]
    public void NormalizePipeName_Preserves_Inner_Separators()
    {
        // Nested pipe names are legal and distinct; flattening them would merge pipes.
        Assert.Equal(@"wkssvc\sub", MonitorSupport.NormalizePipeName(@"\\.\pipe\wkssvc\sub"));
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("   ", "")]
    [InlineData(@"\\.\pipe\", "")]
    [InlineData(@"\Device\NamedPipe", "")]
    [InlineData(@"\\HOST\pipe", "")]
    public void NormalizePipeName_Yields_Empty_When_There_Is_No_Name(string? raw, string expected)
    {
        Assert.Equal(expected, MonitorSupport.NormalizePipeName(raw));
    }

    [Fact]
    public void NormalizePipeName_Discards_The_Remote_Host()
    {
        // The technique is identified by the pipe, not the peer; the peer is carried on
        // the network signal instead. Both spellings must compare equal.
        Assert.Equal(
            MonitorSupport.NormalizePipeName(@"\\.\pipe\atsvc"),
            MonitorSupport.NormalizePipeName(@"\\10.0.0.5\pipe\atsvc"));
    }
}

public class MonitorSupportAccessMaskTests
{
    [Theory]
    [InlineData(0x0002u)]   // PROCESS_CREATE_THREAD
    [InlineData(0x0008u)]   // PROCESS_VM_OPERATION
    [InlineData(0x0010u)]   // PROCESS_VM_READ
    [InlineData(0x0020u)]   // PROCESS_VM_WRITE
    [InlineData(0x0040u)]   // PROCESS_DUP_HANDLE
    [InlineData(0x001FFFFFu)] // PROCESS_ALL_ACCESS
    [InlineData(0x0410u)]   // VM_READ + QUERY_INFORMATION, the LSASS dump shape
    [InlineData(0xFFFFFFFFu)]
    public void IsSensitiveProcessAccess_Flags_Injection_And_Credential_Rights(uint mask)
    {
        Assert.True(MonitorSupport.IsSensitiveProcessAccess(mask));
    }

    [Theory]
    [InlineData(0x0000u)]       // nothing requested
    [InlineData(0x0001u)]       // PROCESS_TERMINATE alone: handled by the terminate event
    [InlineData(0x0400u)]       // PROCESS_QUERY_INFORMATION
    [InlineData(0x1000u)]       // PROCESS_QUERY_LIMITED_INFORMATION
    [InlineData(0x00100000u)]   // SYNCHRONIZE
    [InlineData(0x20000000u)]   // GENERIC_EXECUTE maps only to SYNCHRONIZE on a process
    public void IsSensitiveProcessAccess_Ignores_Benign_Rights(uint mask)
    {
        Assert.False(MonitorSupport.IsSensitiveProcessAccess(mask));
    }

    // Adversarial: asking for MAXIMUM_ALLOWED or a generic mapping gets the caller
    // VM_READ without ever naming it. Missing these would let a dumper walk past the
    // whole predicate with a mask of 0x02000000.
    [Theory]
    [InlineData(0x02000000u)]   // MAXIMUM_ALLOWED
    [InlineData(0x10000000u)]   // GENERIC_ALL
    [InlineData(0x40000000u)]   // GENERIC_WRITE -> VM_WRITE + CREATE_THREAD
    [InlineData(0x80000000u)]   // GENERIC_READ  -> VM_READ
    public void IsSensitiveProcessAccess_Flags_Wide_Requests_That_Name_No_Bit(uint mask)
    {
        Assert.True(MonitorSupport.IsSensitiveProcessAccess(mask));
    }

    [Fact]
    public void DescribeAccessMask_Zero_Is_None()
    {
        Assert.Equal("NONE", MonitorSupport.DescribeAccessMask(0));
    }

    [Fact]
    public void DescribeAccessMask_Names_Single_Rights()
    {
        Assert.Equal("PROCESS_VM_READ", MonitorSupport.DescribeAccessMask(0x0010));
        Assert.Equal("PROCESS_TERMINATE", MonitorSupport.DescribeAccessMask(0x0001));
    }

    [Fact]
    public void DescribeAccessMask_Joins_In_Stable_Bit_Order()
    {
        Assert.Equal("PROCESS_VM_READ|PROCESS_QUERY_INFORMATION", MonitorSupport.DescribeAccessMask(0x0410));
    }

    [Fact]
    public void DescribeAccessMask_Collapses_All_Access()
    {
        Assert.Equal("PROCESS_ALL_ACCESS", MonitorSupport.DescribeAccessMask(0x001FFFFF));
    }

    // Adversarial: every bit set. The named rights must be spelled out and the
    // undocumented remainder surfaced rather than silently discarded.
    [Fact]
    public void DescribeAccessMask_Reports_Undocumented_Bits_As_Hex_Residue()
    {
        Assert.Equal(
            "PROCESS_ALL_ACCESS|ACCESS_SYSTEM_SECURITY|MAXIMUM_ALLOWED|GENERIC_ALL|" +
            "GENERIC_EXECUTE|GENERIC_WRITE|GENERIC_READ|0x0CE00000",
            MonitorSupport.DescribeAccessMask(0xFFFFFFFF));

        Assert.Equal("0x00400000", MonitorSupport.DescribeAccessMask(0x00400000));
    }

    [Fact]
    public void DescribeAccessMask_Does_Not_Collapse_A_Near_Miss_Of_All_Access()
    {
        // One bit short of PROCESS_ALL_ACCESS must not be reported as full access --
        // that would overstate what the caller asked for in the alert.
        string text = MonitorSupport.DescribeAccessMask(0x001FFFFEu);

        Assert.DoesNotContain("PROCESS_ALL_ACCESS", text);
        Assert.DoesNotContain("PROCESS_TERMINATE", text);
        Assert.Contains("PROCESS_VM_READ", text);
        Assert.Contains("0x0000C000", text);   // the two undocumented bits inside ALL_ACCESS
    }

    [Fact]
    public void DescribeAccessMask_Never_Loses_A_Bit()
    {
        // Property check across the whole 32-bit space at a coarse stride: the rendering
        // is either NONE or contains at least one token, and never comes back empty.
        for (uint bit = 1; bit != 0; bit <<= 1)
        {
            string text = MonitorSupport.DescribeAccessMask(bit);
            Assert.False(string.IsNullOrWhiteSpace(text));
            Assert.NotEqual("NONE", text);
        }
    }
}

public class MonitorSupportScriptTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("abc", "abc")]
    public void TruncateScript_Passes_Short_Input_Through(string? input, string expected)
    {
        Assert.Equal(expected, MonitorSupport.TruncateScript(input));
    }

    [Fact]
    public void TruncateScript_Keeps_Exactly_Max_Characters_Untouched()
    {
        string input = new('x', 10);
        Assert.Equal(input, MonitorSupport.TruncateScript(input, 10));
    }

    [Fact]
    public void TruncateScript_Keeps_The_Head_And_Reports_The_Length()
    {
        string result = MonitorSupport.TruncateScript("abcdefghijk", 10);

        // Ordinal throughout: the marker starts with a newline, and a culture-sensitive
        // comparison can treat control characters as ignorable.
        Assert.True(result.StartsWith("abcdefghij", StringComparison.Ordinal), result);
        Assert.True(result.Contains(MonitorSupport.TruncationMarkerPrefix, StringComparison.Ordinal), result);
        Assert.Contains("11 chars total", result, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("a\r\nb", "a\nb")]
    [InlineData("a\rb", "a\nb")]
    [InlineData("a\nb", "a\nb")]
    [InlineData("a\r\n\r\nb", "a\n\nb")]
    public void TruncateScript_Normalises_Line_Endings(string input, string expected)
    {
        Assert.Equal(expected, MonitorSupport.TruncateScript(input));
    }

    [Fact]
    public void TruncateScript_Reports_The_Post_Normalisation_Length()
    {
        // "a\r\nb\r\nc" is 7 raw characters but 5 after normalisation, and 5 is the
        // length of the text actually being truncated.
        string result = MonitorSupport.TruncateScript("a\r\nb\r\nc", 2);

        Assert.Contains("5 chars total", result, StringComparison.Ordinal);
        Assert.True(result.StartsWith("a\n", StringComparison.Ordinal), result);
    }

    [Fact]
    public void TruncateScript_Max_Zero_Yields_Only_The_Marker()
    {
        string result = MonitorSupport.TruncateScript("abc", 0);

        Assert.True(result.StartsWith(MonitorSupport.TruncationMarkerPrefix, StringComparison.Ordinal), result);
        Assert.Contains("3 chars total", result, StringComparison.Ordinal);
    }

    [Fact]
    public void TruncateScript_Rejects_A_Negative_Limit()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => MonitorSupport.TruncateScript("abc", -1));
    }

    // Adversarial: cutting between a surrogate pair produces a lone surrogate, which
    // corrupts JSON serialisation of the resulting alert.
    [Fact]
    public void TruncateScript_Never_Splits_A_Surrogate_Pair()
    {
        string input = "abcdefghi" + "\uD83D\uDE00" + "xxxx";
        string result = MonitorSupport.TruncateScript(input, 10);

        Assert.True(
            result.StartsWith("abcdefghi" + MonitorSupport.TruncationMarkerPrefix, StringComparison.Ordinal),
            result);
        for (int i = 0; i < 9; i++) Assert.False(char.IsSurrogate(result[i]));
    }

    [Fact]
    public void TruncateScript_Handles_A_Ten_Megabyte_Body()
    {
        string big = BuildLargeScript();

        string result = MonitorSupport.TruncateScript(big, 4096);

        Assert.True(result.Length < 4200, "the bound must actually bound");
        Assert.True(result.StartsWith(big[..4096], StringComparison.Ordinal));
        Assert.Contains(big.Length + " chars total", result, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("[Convert]::FromBase64String($x)")]
    [InlineData("powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")]
    [InlineData("powershell -EncodedCommand whatever")]
    [InlineData("$k = 65 -bxor 42")]
    [InlineData("[Reflection.Assembly]::Load($bytes)")]
    [InlineData("$c = [char[]](105,101,120)")]
    public void LooksObfuscatedScript_Flags_Known_Markers(string script)
    {
        Assert.True(MonitorSupport.LooksObfuscatedScript(script), script);
    }

    [Fact]
    public void LooksObfuscatedScript_Flags_A_Char_Array_Join()
    {
        Assert.True(MonitorSupport.LooksObfuscatedScript(
            "& ( $eNv:cOmSpEc[4,26,25]-JoIn'')( \"iEx ( [ChAr[]](105,101,120) -join '' )\" )"));
    }

    [Fact]
    public void LooksObfuscatedScript_Flags_Heavy_Backtick_Escaping()
    {
        Assert.True(MonitorSupport.LooksObfuscatedScript("Write-Output he`l`l`o wo`r`l`d"));
    }

    [Fact]
    public void LooksObfuscatedScript_Flags_Repeated_Brace_Dollar_Constructs()
    {
        Assert.True(MonitorSupport.LooksObfuscatedScript("${a}=1;${b}=2;${c}=3"));
    }

    [Fact]
    public void LooksObfuscatedScript_Flags_A_Very_Long_Single_Line()
    {
        Assert.True(MonitorSupport.LooksObfuscatedScript(new string('a', 1500)));
    }

    [Fact]
    public void LooksObfuscatedScript_Flags_Punctuation_Dense_Text()
    {
        Assert.True(MonitorSupport.LooksObfuscatedScript(
            string.Concat(Enumerable.Repeat("()[]|&^%#@!+=~", 6))));
    }

    [Fact]
    public void LooksObfuscatedScript_Flags_A_Long_Base64_Blob()
    {
        Assert.True(MonitorSupport.LooksObfuscatedScript("$data = '" + new string('A', 250) + "'"));
    }

    [Theory]
    [InlineData((string?)null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\r\n\t")]
    [InlineData("$a = 1")]
    [InlineData("Get-ChildItem C:\\Temp")]
    [InlineData("Write-Host \"${x}\"")]                       // one brace-dollar is normal
    [InlineData("Get-Process | Where-Object { $_.CPU -gt 5 }")]
    [InlineData("$list = $items -join ', '")]                 // -join without a char source
    public void LooksObfuscatedScript_Leaves_Ordinary_Script_Alone(string? script)
    {
        Assert.False(MonitorSupport.LooksObfuscatedScript(script!));
    }

    [Fact]
    public void LooksObfuscatedScript_Does_Not_Fire_On_Wrapped_Long_Text()
    {
        // 1500 characters is only suspicious when it is one line.
        string wrapped = string.Join("\n", Enumerable.Repeat(new string('a', 80), 20));
        Assert.False(MonitorSupport.LooksObfuscatedScript(wrapped));
    }

    // Adversarial: a ten megabyte body must not wedge the pump, and padding a script
    // out to that size must not by itself look malicious.
    [Fact]
    public void LooksObfuscatedScript_Handles_A_Ten_Megabyte_Body_Without_False_Positive()
    {
        string big = BuildLargeScript();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        bool flagged = MonitorSupport.LooksObfuscatedScript(big);
        sw.Stop();

        Assert.False(flagged);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
    }

    [Fact]
    public void LooksObfuscatedScript_Still_Catches_A_Marker_Inside_A_Huge_Body()
    {
        // The literal markers are matched over the WHOLE body, so padding past the
        // regex scan window does not hide FromBase64String.
        string big = BuildLargeScript() + "\n[Convert]::FromBase64String($p)\n";

        Assert.True(MonitorSupport.LooksObfuscatedScript(big));
    }

    /// <summary>Roughly ten megabytes of ordinary, wrapped, low-punctuation script.</summary>
    private static string BuildLargeScript()
    {
        const string line = "Get-ChildItem C:\\Temp\n";
        var sb = new System.Text.StringBuilder(10 * 1024 * 1024 + line.Length);
        while (sb.Length < 10 * 1024 * 1024) sb.Append(line);
        return sb.ToString();
    }
}

public class MonitorSupportDeduplicatorTests
{
    private static SignalDeduplicator New(ManualClock clock, int seconds = 5, int capacity = 4096)
        => new(clock, TimeSpan.FromSeconds(seconds), capacity);

    [Fact]
    public void First_Occurrence_Is_Admitted()
    {
        var clock = new ManualClock();
        var dedupe = New(clock);

        Assert.True(dedupe.ShouldEmit("k"));
        Assert.Equal(1, dedupe.Count);
    }

    [Fact]
    public void Repeat_Inside_The_Window_Is_Suppressed()
    {
        var clock = new ManualClock();
        var dedupe = New(clock);

        Assert.True(dedupe.ShouldEmit("k"));
        clock.Advance(TimeSpan.FromSeconds(4.9));
        Assert.False(dedupe.ShouldEmit("k"));
    }

    [Fact]
    public void Repeat_After_The_Window_Is_Admitted_Again()
    {
        var clock = new ManualClock();
        var dedupe = New(clock);

        Assert.True(dedupe.ShouldEmit("k"));
        clock.Advance(TimeSpan.FromSeconds(5));
        Assert.True(dedupe.ShouldEmit("k"));
    }

    [Fact]
    public void Distinct_Keys_Do_Not_Interfere()
    {
        var clock = new ManualClock();
        var dedupe = New(clock);

        Assert.True(dedupe.ShouldEmit("a"));
        Assert.True(dedupe.ShouldEmit("b"));
        Assert.False(dedupe.ShouldEmit("a"));
    }

    [Fact]
    public void Keys_Are_Compared_Case_Insensitively()
    {
        // Registry paths and pipe names are case-insensitive on Windows; treating
        // "HKLM\...\Run" and "hklm\...\run" as different keys would defeat the filter.
        var clock = new ManualClock();
        var dedupe = New(clock);

        Assert.True(dedupe.ShouldEmit(@"HKLM\Run\X"));
        Assert.False(dedupe.ShouldEmit(@"hklm\run\x"));
    }

    [Fact]
    public void A_Zero_Window_Suppresses_Nothing()
    {
        var clock = new ManualClock();
        var dedupe = new SignalDeduplicator(clock, TimeSpan.Zero);

        Assert.True(dedupe.ShouldEmit("k"));
        Assert.True(dedupe.ShouldEmit("k"));
    }

    [Fact]
    public void Expired_Entries_Are_Pruned_Before_The_Table_Is_Dropped()
    {
        var clock = new ManualClock();
        var dedupe = New(clock, seconds: 1, capacity: 2);

        Assert.True(dedupe.ShouldEmit("a"));
        Assert.True(dedupe.ShouldEmit("b"));
        clock.Advance(TimeSpan.FromSeconds(2));

        Assert.True(dedupe.ShouldEmit("c"));
        Assert.Equal(1, dedupe.Count);   // a and b expired and were pruned
    }

    // Adversarial: a process that generates unbounded distinct keys (a scripted walk of
    // the registry, random pipe names) must not grow the table without limit.
    [Fact]
    public void Memory_Is_Bounded_Under_A_Flood_Of_Unique_Keys()
    {
        var clock = new ManualClock();
        var dedupe = New(clock, seconds: 300, capacity: 8);

        for (int i = 0; i < 1000; i++)
        {
            Assert.True(dedupe.ShouldEmit("key-" + i));
            Assert.True(dedupe.Count <= 8, $"count grew to {dedupe.Count}");
        }
    }

    [Fact]
    public void Dropping_The_Table_Fails_Open_Rather_Than_Closed()
    {
        // Losing dedupe state may cost a duplicate signal; it must never cause a
        // legitimate first occurrence to be swallowed.
        var clock = new ManualClock();
        var dedupe = New(clock, seconds: 300, capacity: 2);

        dedupe.ShouldEmit("a");
        dedupe.ShouldEmit("b");
        dedupe.ShouldEmit("c");   // forces the clear

        Assert.True(dedupe.ShouldEmit("brand-new"));
    }

    [Theory]
    [InlineData(-1)]
    public void Negative_Window_Is_Rejected(int seconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new SignalDeduplicator(new ManualClock(), TimeSpan.FromSeconds(seconds)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void Non_Positive_Capacity_Is_Rejected(int capacity)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new SignalDeduplicator(new ManualClock(), TimeSpan.FromSeconds(1), capacity));
    }

    [Fact]
    public void Time_Comes_Only_From_The_Injected_Clock()
    {
        // The whole window is exercised without sleeping; if the implementation ever
        // reached for DateTime.UtcNow this would suppress rather than admit.
        var clock = new ManualClock(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var dedupe = New(clock, seconds: 3600);

        Assert.True(dedupe.ShouldEmit("k"));
        clock.Advance(TimeSpan.FromHours(2));
        Assert.True(dedupe.ShouldEmit("k"));
    }
}

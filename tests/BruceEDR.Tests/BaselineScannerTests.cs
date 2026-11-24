using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Intel;
using BruceEDR.Security;
using Xunit;

namespace BruceEDR.Tests;

public sealed class BaselineScannerTests
{
    [Fact]
    public void BaselineScanner_Discovers_Live_Tree_Publishers_And_Builds_Safe_Watchlist_Rules()
    {
        var scan = BaselineScanner.Scan();
        Assert.NotEmpty(scan.Entries);
        Assert.True(scan.RunningProcessCount > 0);
        Assert.Contains(scan.Publishers, p => p.VerifiedAdminInstall && p.Name.Contains("Microsoft", StringComparison.OrdinalIgnoreCase));

        string tempFile = Path.Combine(Path.GetTempPath(), $"bruce-baseline-test-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(tempFile, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
        try
        {
            var adminApp = new BaselineEntry
            {
                ProcessName = "firefox.exe",
                DisplayName = "Mozilla Firefox",
                ImagePath = @"C:\Program Files\Mozilla Firefox\firefox.exe",
                IsRunning = true,
                IsInstalledApp = true,
                Signed = true,
                Publisher = "Mozilla Corporation",
                AdminOnly = true,
                ProtectedSystem = false
            };

            var userWritableApp = new BaselineEntry
            {
                ProcessName = Path.GetFileName(tempFile),
                DisplayName = "Portable Utility",
                ImagePath = tempFile,
                IsRunning = true,
                Signed = false,
                AdminOnly = false,
                ProtectedSystem = false
            };

            var sketchApp = new BaselineEntry
            {
                ProcessName = "sketchy-updater.exe",
                DisplayName = "Sketchy Updater",
                ImagePath = @"C:\ProgramData\Sketchy\sketchy-updater.exe",
                IsRunning = true,
                Signed = false,
                AdminOnly = false,
                ProtectedSystem = false
            };

            var protectedOs = new BaselineEntry
            {
                ProcessName = "csrss.exe",
                DisplayName = "Client Server Runtime Process",
                ImagePath = @"C:\Windows\System32\csrss.exe",
                IsRunning = true,
                Signed = true,
                Publisher = "Microsoft Windows",
                AdminOnly = true,
                ProtectedSystem = true
            };

            var existingTemplate = new WatchlistEntryConfig
            {
                Match = "name",
                Value = "mimikatz",
                Action = "quarantine",
                Enabled = false,
                Note = "template"
            };

            var merged = BaselineScanner.MergeWatchlistEntries(
                new[] { existingTemplate },
                new[]
                {
                    (adminApp, BaselineTrustChoice.Trusted),
                    (userWritableApp, BaselineTrustChoice.Trusted),
                    (sketchApp, BaselineTrustChoice.Untrusted),
                    (protectedOs, BaselineTrustChoice.Untrusted),
                });

            // Preserves existing template
            Assert.Contains(merged, e => e.Value == "mimikatz" && !e.Enabled);

            // Admin-only app trusted by path
            Assert.Contains(merged, e => e.Action == "allow" && e.Match == "path" && e.Value == adminApp.ImagePath);

            // User-writable app trusted by SHA-256 hash (never by hijacked path!)
            Assert.Contains(merged, e => e.Action == "allow" && e.Match == "hash" && e.Value.Length == 64);

            // Untrusted app quarantined on sight
            Assert.Contains(merged, e => e.Action == "quarantine" && e.Match == "path" && e.Value == sketchApp.ImagePath);

            // Protected system process refused for Untrusted
            Assert.DoesNotContain(merged, e => e.Value.Contains("csrss.exe", StringComparison.OrdinalIgnoreCase));

            // Every enabled entry compiles cleanly with 0 errors in Watchlist.Compile
            var errors = new List<string>();
            var compiled = Watchlist.Compile(merged, errors.Add);
            Assert.Empty(errors);
            Assert.Equal(3, compiled.Count);

            // InferExistingChoice round-trips all 3 states accurately
            Assert.Equal(BaselineTrustChoice.Trusted, BaselineScanner.InferExistingChoice(adminApp, merged));
            Assert.Equal(BaselineTrustChoice.Trusted, BaselineScanner.InferExistingChoice(userWritableApp, merged));
            Assert.Equal(BaselineTrustChoice.Untrusted, BaselineScanner.InferExistingChoice(sketchApp, merged));
            Assert.Equal(BaselineTrustChoice.Default, BaselineScanner.InferExistingChoice(protectedOs, merged));
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }
}

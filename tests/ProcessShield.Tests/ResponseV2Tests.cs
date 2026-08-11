using System.IO.Compression;
using System.Text;
using ProcessShield.Core;
using ProcessShield.Response;
using Xunit;

namespace ProcessShield.Tests;

/// <summary>
/// Scratch directory that always cleans itself up, so a failing assertion cannot leave
/// encrypted blobs or triage zips behind in %TEMP%.
/// </summary>
internal sealed class ResponseV2TempDir : IDisposable
{
    public string Root { get; }

    public ResponseV2TempDir()
    {
        Root = Path.Combine(Path.GetTempPath(), "psresponse-tests-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(Root);
    }

    public string Sub(string name)
    {
        string p = Path.Combine(Root, name);
        Directory.CreateDirectory(p);
        return p;
    }

    public string WriteFile(string name, string content)
    {
        string p = Path.Combine(Root, name);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllText(p, content);
        return p;
    }

    public string WriteFile(string name, byte[] content)
    {
        string p = Path.Combine(Root, name);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllBytes(p, content);
        return p;
    }

    public string Path_(string name) => Path.Combine(Root, name);

    public void Dispose()
    {
        try { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
        catch { /* a locked handle in a failing test must not mask the real assertion */ }
    }
}

// ===========================================================================
//  QuarantineVault
// ===========================================================================

public class ResponseV2QuarantineVaultTests
{
    private static ManualClock Clock() => new(new DateTime(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc));

    private static string BlobPath(string vaultDir, string id)
        => Path.Combine(vaultDir, "blobs", id + ".psvblob");

    private static byte[] ReadBlob(string vaultDir, string id) => File.ReadAllBytes(BlobPath(vaultDir, id));

    // ------------------------------------------------------------ happy path

    [Fact]
    public void Store_Creates_Entry_With_Metadata()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("loot.zip", "payload bytes");
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        var entry = vault.Store(src, "staged archive", 4242, "evil.exe");

        Assert.NotNull(entry);
        Assert.Equal(Path.GetFullPath(src), entry!.OriginalPath);
        Assert.Equal("staged archive", entry.Reason);
        Assert.Equal(4242, entry.Pid);
        Assert.Equal("evil.exe", entry.ProcessName);
        Assert.Equal(new DateTime(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc), entry.QuarantinedUtc);
        Assert.False(entry.Restored);
        Assert.Null(entry.RestoredUtc);
        Assert.Equal(13, entry.OriginalSize);
    }

    [Fact]
    public void Store_Records_Sha256_Of_The_Plaintext()
    {
        using var tmp = new ResponseV2TempDir();
        byte[] content = Encoding.UTF8.GetBytes("the quick brown fox");
        string src = tmp.WriteFile("sample.bin", content);
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        var entry = vault.Store(src, "r", 1, "p.exe");

        string expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content));
        Assert.Equal(expected, entry!.Sha256);
    }

    [Fact]
    public void Store_Deletes_The_Original_By_Default()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("live.exe", "MZ payload");
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        var entry = vault.Store(src, "r", 1, "p.exe");

        Assert.NotNull(entry);
        Assert.False(File.Exists(src));
    }

    [Fact]
    public void Store_Keeps_The_Original_When_Asked()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("live.exe", "MZ payload");
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        var entry = vault.Store(src, "r", 1, "p.exe", deleteOriginal: false, out string error);

        Assert.NotNull(entry);
        Assert.Equal("", error);
        Assert.True(File.Exists(src));
    }

    [Fact]
    public void Restore_Round_Trips_The_Exact_Bytes()
    {
        using var tmp = new ResponseV2TempDir();
        byte[] content = new byte[4096];
        new Random(1234).NextBytes(content);
        string src = tmp.WriteFile("blob.bin", content);
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        string dest = tmp.Path_("restored.bin");
        bool ok = vault.Restore(entry.Id, dest, out string error);

        Assert.True(ok, error);
        Assert.Equal("", error);
        Assert.Equal(content, File.ReadAllBytes(dest));
    }

    [Fact]
    public void EmptyFile_Stores_And_Restores()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("empty.dat", Array.Empty<byte>());
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        var entry = vault.Store(src, "r", 1, "p.exe");
        Assert.NotNull(entry);
        Assert.Equal(0, entry!.OriginalSize);

        string dest = tmp.Path_("empty-back.dat");
        Assert.True(vault.Restore(entry.Id, dest, out string error), error);
        Assert.Empty(File.ReadAllBytes(dest));
    }

    [Fact]
    public void Restore_Marks_The_Entry_Restored()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("a.bin", "abc");
        var clock = Clock();
        using var vault = new QuarantineVault(tmp.Sub("vault"), clock);
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.True(vault.Restore(entry.Id, tmp.Path_("out.bin"), out _));

        var after = vault.Get(entry.Id);
        Assert.NotNull(after);
        Assert.True(after!.Restored);
        Assert.Equal(entry.QuarantinedUtc.AddMinutes(5), after.RestoredUtc);
    }

    [Fact]
    public void Restore_Creates_Missing_Destination_Directories()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("a.bin", "abc");
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        string dest = Path.Combine(tmp.Root, "deep", "deeper", "a.bin");
        Assert.True(vault.Restore(entry.Id, dest, out string error), error);
        Assert.True(File.Exists(dest));
    }

    // --------------------------------------------------------- encryption at rest

    [Fact]
    public void Blob_Does_Not_Contain_The_Plaintext()
    {
        const string marker = "DISTINCTIVE-MALWARE-MARKER-0xC0FFEE";
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", marker + marker + marker);
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        string raw = Encoding.Latin1.GetString(ReadBlob(vaultDir, entry.Id));
        Assert.DoesNotContain(marker, raw);
    }

    [Fact]
    public void Blob_Starts_With_The_Versioned_Magic()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "abc");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        byte[] blob = ReadBlob(vaultDir, entry.Id);
        Assert.Equal("PSVLT1", Encoding.ASCII.GetString(blob, 0, 6));
        Assert.Equal(42 + 3, blob.Length);           // header + ciphertext, GCM adds no padding
    }

    [Fact]
    public void Blob_Filename_Does_Not_Carry_The_Original_Extension()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("dropper.exe", "MZ");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        var blobs = Directory.GetFiles(Path.Combine(vaultDir, "blobs"));
        Assert.Single(blobs);
        Assert.DoesNotContain(".exe", Path.GetFileName(blobs[0]));
        Assert.Equal(entry.Id + ".psvblob", Path.GetFileName(blobs[0]));
    }

    // ------------------------------------------------------------- tampering

    [Fact]
    public void Restore_Fails_And_Writes_Nothing_When_The_Ciphertext_Is_Tampered()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "sensitive payload content");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        string blobPath = BlobPath(vaultDir, entry.Id);
        byte[] blob = File.ReadAllBytes(blobPath);
        blob[45] ^= 0xFF;                                // a byte of ciphertext
        File.WriteAllBytes(blobPath, blob);

        string dest = tmp.Path_("out.bin");
        Assert.False(vault.Restore(entry.Id, dest, out string error));
        Assert.Contains("tag mismatch", error);
        Assert.False(File.Exists(dest));
        Assert.Empty(Directory.GetFiles(tmp.Root, "*.tmp"));
    }

    [Fact]
    public void Restore_Fails_When_The_Nonce_Is_Tampered()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "sensitive payload content");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        string blobPath = BlobPath(vaultDir, entry.Id);
        byte[] blob = File.ReadAllBytes(blobPath);
        blob[7] ^= 0x01;                                 // nonce byte
        File.WriteAllBytes(blobPath, blob);

        Assert.False(vault.Restore(entry.Id, tmp.Path_("out.bin"), out string error));
        Assert.Contains("tag mismatch", error);
    }

    [Fact]
    public void Restore_Fails_When_The_Tag_Is_Tampered()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "sensitive payload content");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        string blobPath = BlobPath(vaultDir, entry.Id);
        byte[] blob = File.ReadAllBytes(blobPath);
        blob[20] ^= 0x80;                                // tag byte
        File.WriteAllBytes(blobPath, blob);

        Assert.False(vault.Restore(entry.Id, tmp.Path_("out.bin"), out string error));
        Assert.Contains("tag mismatch", error);
    }

    [Fact]
    public void Restore_Fails_On_A_Bad_Magic()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "abc");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        string blobPath = BlobPath(vaultDir, entry.Id);
        byte[] blob = File.ReadAllBytes(blobPath);
        blob[0] = (byte)'X';
        File.WriteAllBytes(blobPath, blob);

        Assert.False(vault.Restore(entry.Id, tmp.Path_("out.bin"), out string error));
        Assert.Contains("magic", error);
    }

    [Fact]
    public void Restore_Fails_On_A_Truncated_Blob()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "abcdefghijklmnop");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        string blobPath = BlobPath(vaultDir, entry.Id);
        byte[] blob = File.ReadAllBytes(blobPath);
        File.WriteAllBytes(blobPath, blob[..20]);

        Assert.False(vault.Restore(entry.Id, tmp.Path_("out.bin"), out string error));
        Assert.Contains("truncated", error);
    }

    [Fact]
    public void Restore_Rejects_A_Blob_Swapped_In_From_Another_Entry()
    {
        using var tmp = new ResponseV2TempDir();
        string a = tmp.WriteFile("a.bin", "AAAAAAAAAAAAAAAA");   // same length, different content
        string b = tmp.WriteFile("b.bin", "BBBBBBBBBBBBBBBB");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var ea = vault.Store(a, "r", 1, "p.exe")!;
        var eb = vault.Store(b, "r", 2, "p.exe")!;

        // The associated data binds a blob to its own entry, so a same-size swap must
        // not silently restore the wrong sample under the wrong id.
        File.Copy(BlobPath(vaultDir, eb.Id), BlobPath(vaultDir, ea.Id), overwrite: true);

        Assert.False(vault.Restore(ea.Id, tmp.Path_("out.bin"), out string error));
        Assert.Contains("tag mismatch", error);
        Assert.False(File.Exists(tmp.Path_("out.bin")));
    }

    [Fact]
    public void VerifyIntegrity_Passes_Then_Fails_After_Tampering()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "content to verify");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        Assert.True(vault.VerifyIntegrity(entry.Id, out string ok));
        Assert.Equal("", ok);

        string blobPath = BlobPath(vaultDir, entry.Id);
        byte[] blob = File.ReadAllBytes(blobPath);
        blob[^1] ^= 0x55;
        File.WriteAllBytes(blobPath, blob);

        Assert.False(vault.VerifyIntegrity(entry.Id, out string bad));
        Assert.NotEqual("", bad);
    }

    [Fact]
    public void VerifyIntegrity_Fails_When_The_Blob_Is_Missing()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "abc");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        File.Delete(BlobPath(vaultDir, entry.Id));

        Assert.False(vault.VerifyIntegrity(entry.Id, out string error));
        Assert.Contains("unreadable", error);
    }

    // ------------------------------------------------------- malformed input

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Store_Rejects_A_Blank_Source_Path(string path)
    {
        using var tmp = new ResponseV2TempDir();
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        Assert.Null(vault.Store(path, "r", 1, "p.exe", true, out string error));
        Assert.Contains("empty", error);
    }

    [Fact]
    public void Store_Rejects_A_Missing_Source()
    {
        using var tmp = new ResponseV2TempDir();
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        Assert.Null(vault.Store(tmp.Path_("nope.bin"), "r", 1, "p.exe", true, out string error));
        Assert.Contains("not found", error);
    }

    [Fact]
    public void Store_Rejects_A_Directory()
    {
        using var tmp = new ResponseV2TempDir();
        string dir = tmp.Sub("adirectory");
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        Assert.Null(vault.Store(dir, "r", 1, "p.exe", true, out string error));
        Assert.Contains("not found or not a file", error);
    }

    [Fact]
    public void Store_Reports_A_Locked_Source_Instead_Of_Throwing()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("locked.bin", "abc");
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        using (new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.Null(vault.Store(src, "r", 1, "p.exe", true, out string error));
            Assert.Contains("cannot read source", error);
        }

        Assert.True(File.Exists(src));                   // never deleted on a failed store
        Assert.Empty(vault.List());
    }

    [Fact]
    public void Restore_Refuses_To_Overwrite_An_Existing_Destination()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "vault content");
        string dest = tmp.WriteFile("dest.bin", "PRE-EXISTING CONTENT");
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        Assert.False(vault.Restore(entry.Id, dest, out string error));
        Assert.Contains("already exists", error);
        Assert.Equal("PRE-EXISTING CONTENT", File.ReadAllText(dest));
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-such-id")]
    public void Restore_And_Purge_Reject_An_Unknown_Id(string id)
    {
        using var tmp = new ResponseV2TempDir();
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        Assert.False(vault.Restore(id, tmp.Path_("out.bin"), out string restoreError));
        Assert.Contains("unknown vault id", restoreError);

        Assert.False(vault.Purge(id, out string purgeError));
        Assert.Contains("unknown vault id", purgeError);

        Assert.False(vault.VerifyIntegrity(id, out string verifyError));
        Assert.Contains("unknown vault id", verifyError);
    }

    [Fact]
    public void Restore_Rejects_A_Blank_Destination()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "abc");
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        Assert.False(vault.Restore(entry.Id, "  ", out string error));
        Assert.Contains("empty", error);
    }

    // ------------------------------------------------------------ purge / list

    [Fact]
    public void Purge_Removes_The_Blob_And_The_Entry()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "abc");
        string vaultDir = tmp.Sub("vault");
        using var vault = new QuarantineVault(vaultDir, Clock());
        var entry = vault.Store(src, "r", 1, "p.exe")!;

        Assert.True(vault.Purge(entry.Id, out string error), error);
        Assert.False(File.Exists(BlobPath(vaultDir, entry.Id)));
        Assert.Null(vault.Get(entry.Id));
        Assert.Empty(vault.List());
        Assert.Equal(0, vault.TotalBytes);
    }

    [Fact]
    public void TotalBytes_Tracks_Header_Plus_Content()
    {
        using var tmp = new ResponseV2TempDir();
        string a = tmp.WriteFile("a.bin", new byte[100]);
        string b = tmp.WriteFile("b.bin", new byte[250]);
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        Assert.Equal(0, vault.TotalBytes);
        vault.Store(a, "r", 1, "p.exe");
        Assert.Equal(142, vault.TotalBytes);
        vault.Store(b, "r", 1, "p.exe");
        Assert.Equal(142 + 292, vault.TotalBytes);
    }

    [Fact]
    public void Ids_Are_Unique_And_Sort_Chronologically()
    {
        using var tmp = new ResponseV2TempDir();
        var clock = Clock();
        using var vault = new QuarantineVault(tmp.Sub("vault"), clock);

        var ordered = new List<string>();
        for (int i = 0; i < 25; i++)
        {
            string src = tmp.WriteFile($"f{i}.bin", "x" + i);
            ordered.Add(vault.Store(src, "r", i, "p.exe")!.Id);
            if (i % 3 == 0) clock.Advance(TimeSpan.FromSeconds(1));   // some ties, some not
        }

        Assert.Equal(25, ordered.Distinct().Count());
        Assert.Equal(ordered, vault.List().Select(e => e.Id).ToList());

        var sorted = ordered.OrderBy(x => x, StringComparer.Ordinal).ToList();
        Assert.Equal(sorted, ordered);
    }

    [Fact]
    public void Ids_Stay_Unique_When_The_Clock_Never_Moves()
    {
        using var tmp = new ResponseV2TempDir();
        using var vault = new QuarantineVault(tmp.Sub("vault"), Clock());

        var ids = new List<string>();
        for (int i = 0; i < 10; i++)
            ids.Add(vault.Store(tmp.WriteFile($"t{i}.bin", "y"), "r", i, "p.exe")!.Id);

        Assert.Equal(10, ids.Distinct().Count());
        Assert.Equal(ids.OrderBy(x => x, StringComparer.Ordinal).ToList(), ids);
    }

    // ---------------------------------------------------------- persistence

    [Fact]
    public void Vault_Reloads_Its_Index_And_Can_Still_Decrypt()
    {
        using var tmp = new ResponseV2TempDir();
        string vaultDir = tmp.Sub("vault");
        string src = tmp.WriteFile("s.bin", "persisted content");
        string id;

        using (var first = new QuarantineVault(vaultDir, Clock()))
            id = first.Store(src, "reason text", 77, "mal.exe")!.Id;

        using var second = new QuarantineVault(vaultDir, Clock());
        var entry = second.Get(id);
        Assert.NotNull(entry);
        Assert.Equal("reason text", entry!.Reason);
        Assert.Equal(77, entry.Pid);

        string dest = tmp.Path_("back.bin");
        Assert.True(second.Restore(id, dest, out string error), error);
        Assert.Equal("persisted content", File.ReadAllText(dest));
    }

    [Fact]
    public void A_Purged_Entry_Does_Not_Come_Back_After_Reload()
    {
        using var tmp = new ResponseV2TempDir();
        string vaultDir = tmp.Sub("vault");
        string id;

        using (var first = new QuarantineVault(vaultDir, Clock()))
        {
            id = first.Store(tmp.WriteFile("s.bin", "abc"), "r", 1, "p.exe")!.Id;
            Assert.True(first.Purge(id, out _));
        }

        using var second = new QuarantineVault(vaultDir, Clock());
        Assert.Null(second.Get(id));
        Assert.Empty(second.List());
    }

    [Fact]
    public void A_Restore_Recorded_Before_Reload_Survives_It()
    {
        using var tmp = new ResponseV2TempDir();
        string vaultDir = tmp.Sub("vault");
        string id;

        using (var first = new QuarantineVault(vaultDir, Clock()))
        {
            id = first.Store(tmp.WriteFile("s.bin", "abc"), "r", 1, "p.exe")!.Id;
            Assert.True(first.Restore(id, tmp.Path_("out.bin"), out _));
        }

        using var second = new QuarantineVault(vaultDir, Clock());
        Assert.True(second.Get(id)!.Restored);
    }

    [Fact]
    public void A_Malformed_Manifest_Line_Is_Skipped_Not_Fatal()
    {
        using var tmp = new ResponseV2TempDir();
        string vaultDir = tmp.Sub("vault");
        string id;

        using (var first = new QuarantineVault(vaultDir, Clock()))
            id = first.Store(tmp.WriteFile("s.bin", "abc"), "r", 1, "p.exe")!.Id;

        File.AppendAllText(Path.Combine(vaultDir, "manifest.jsonl"),
            "{this is not json" + Environment.NewLine);

        using var second = new QuarantineVault(vaultDir, Clock());
        Assert.Equal(1, second.MalformedManifestLines);
        Assert.NotNull(second.Get(id));
    }

    [Fact]
    public void New_Ids_Sort_After_Old_Ones_Across_A_Reload()
    {
        using var tmp = new ResponseV2TempDir();
        string vaultDir = tmp.Sub("vault");
        var clock = Clock();
        string first;

        using (var v1 = new QuarantineVault(vaultDir, clock))
            first = v1.Store(tmp.WriteFile("a.bin", "a"), "r", 1, "p.exe")!.Id;

        // Same instant on reload: the sequence must still continue past what is on disk.
        using var v2 = new QuarantineVault(vaultDir, clock);
        string second = v2.Store(tmp.WriteFile("b.bin", "b"), "r", 1, "p.exe")!.Id;

        Assert.True(string.CompareOrdinal(second, first) > 0, $"{second} should sort after {first}");
    }

    // ------------------------------------------------------------------ keys

    [Fact]
    public void Vault_Creates_Its_Directory_And_Key_On_First_Use()
    {
        using var tmp = new ResponseV2TempDir();
        string vaultDir = Path.Combine(tmp.Root, "does", "not", "exist", "yet");

        using var vault = new QuarantineVault(vaultDir, Clock());

        Assert.True(Directory.Exists(vaultDir));
        Assert.True(Directory.Exists(Path.Combine(vaultDir, "blobs")));
        Assert.Equal(64, File.ReadAllText(Path.Combine(vaultDir, "vault.key")).Trim().Length);
    }

    [Theory]
    [InlineData("")]
    [InlineData("tooshort")]
    [InlineData("zzzznotvalidhexzzzznotvalidhexzzzznotvalidhexzzzznotvalidhexzzzz")]
    public void A_Corrupt_Key_File_Is_Fatal_Rather_Than_Silently_Rekeying(string keyContent)
    {
        using var tmp = new ResponseV2TempDir();
        string vaultDir = tmp.Sub("vault");
        using (var v = new QuarantineVault(vaultDir, Clock()))
            v.Store(tmp.WriteFile("s.bin", "abc"), "r", 1, "p.exe");

        File.WriteAllText(Path.Combine(vaultDir, "vault.key"), keyContent);

        // Generating a fresh key here would leave every stored blob undecryptable while
        // the vault carried on looking healthy, so opening must fail loudly instead.
        var ex = Assert.Throws<InvalidOperationException>(() => new QuarantineVault(vaultDir, Clock()));
        Assert.Contains("orphan", ex.Message);
    }

    [Fact]
    public void A_Blob_From_A_Different_Vault_Key_Does_Not_Decrypt()
    {
        using var tmp = new ResponseV2TempDir();
        string vaultA = tmp.Sub("vaultA");
        string vaultB = tmp.Sub("vaultB");

        using var a = new QuarantineVault(vaultA, Clock());
        using var b = new QuarantineVault(vaultB, Clock());

        var ea = a.Store(tmp.WriteFile("a.bin", "sixteen bytes!!!"), "r", 1, "p.exe")!;
        var eb = b.Store(tmp.WriteFile("b.bin", "sixteen bytes!!!"), "r", 1, "p.exe")!;

        // Identical plaintext, so the swapped blob passes every structural check
        // (magic, declared length, manifest length). Only the key and the per-entry
        // associated data differ, and the tag check has to be what catches it.
        File.Copy(BlobPath(vaultB, eb.Id), BlobPath(vaultA, ea.Id), overwrite: true);

        Assert.False(a.Restore(ea.Id, tmp.Path_("out.bin"), out string error));
        Assert.Contains("tag mismatch", error);
    }

    [Fact]
    public void Vault_Ctor_Rejects_A_Blank_Directory()
    {
        Assert.Throws<ArgumentException>(() => new QuarantineVault("   "));
    }

    [Fact]
    public void Disposed_Vault_Returns_Typed_Failures_Instead_Of_Throwing()
    {
        using var tmp = new ResponseV2TempDir();
        string src = tmp.WriteFile("s.bin", "abc");
        var vault = new QuarantineVault(tmp.Sub("vault"), Clock());
        var entry = vault.Store(src, "r", 1, "p.exe", deleteOriginal: false, out _)!;

        vault.Dispose();
        vault.Dispose();                                  // idempotent

        Assert.Null(vault.Store(src, "r", 1, "p.exe", true, out string storeError));
        Assert.Contains("disposed", storeError);
        Assert.False(vault.Restore(entry.Id, tmp.Path_("o.bin"), out string restoreError));
        Assert.Contains("disposed", restoreError);
        Assert.False(vault.Purge(entry.Id, out string purgeError));
        Assert.Contains("disposed", purgeError);
        Assert.False(vault.VerifyIntegrity(entry.Id, out string verifyError));
        Assert.Contains("disposed", verifyError);
    }

    [Fact]
    public void MaxItemBytes_Is_Documented_And_Bounded()
    {
        // AesGcm is one-shot, so the cap is a real memory constraint, not a policy knob.
        Assert.Equal(512L * 1024 * 1024, QuarantineVault.MaxItemBytes);
    }
}

// ===========================================================================
//  Playbook
// ===========================================================================

public class ResponseV2PlaybookTests
{
    private static ProfileSnapshot Snap(int score, bool trusted = false, string name = "evil.exe",
                                        string[]? techniques = null)
    {
        var t = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        return new ProfileSnapshot
        {
            Pid = 1234,
            ProcessName = name,
            ImagePath = @"C:\tmp\" + name,
            Score = score,
            Trusted = trusted,
            Contained = false,
            SuspendedByAnalyst = false,
            Terminated = false,
            Reasons = Array.Empty<string>(),
            StagedArchives = Array.Empty<string>(),
            FirstSeenUtc = t,
            LastUpdatedUtc = t,
            Techniques = techniques ?? Array.Empty<string>()
        };
    }

    // ------------------------------------------------------------------ globs

    [Theory]
    [InlineData("*.exe", "evil.exe", true)]
    [InlineData("*.exe", "exe", false)]
    [InlineData("*", "", true)]
    [InlineData("*", "anything", true)]
    [InlineData("", "", true)]
    [InlineData("", "x", false)]
    [InlineData("?.exe", "a.exe", true)]
    [InlineData("?.exe", "ab.exe", false)]
    [InlineData("?", "", false)]
    [InlineData("power*.exe", "PowerShell.exe", true)]
    [InlineData("cmd.exe", "CMD.EXE", true)]
    [InlineData("*shell*", "powershell.exe", true)]
    [InlineData("a*b*c", "aXXbYYc", true)]
    [InlineData("a*b*c", "aXXbYY", false)]
    [InlineData("evil.exe", "evil.exe.txt", false)]           // anchored at the end
    [InlineData("evil.exe", "notevil.exe", false)]            // anchored at the start
    [InlineData("**.exe", "a.exe", true)]
    [InlineData("*a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaa", false)]  // must not blow up
    public void GlobMatching_Is_Anchored_And_Case_Insensitive(string pattern, string text, bool expected)
        => Assert.Equal(expected, Playbook.MatchesGlob(pattern, text));

    // --------------------------------------------------------------- defaults

    [Fact]
    public void Default_Never_Orders_Host_Isolation()
    {
        // Isolation can strand an administrator's session, so it must be opt-in only.
        Assert.DoesNotContain(Playbook.Default().Rules,
            r => r.Actions.Contains(PlaybookAction.IsolateHost));
    }

    [Fact]
    public void Default_Collects_Triage_Before_Killing()
    {
        foreach (var rule in Playbook.Default().Rules)
        {
            int kill = Array.IndexOf(rule.Actions, PlaybookAction.Kill);
            if (kill < 0) continue;
            int triage = Array.IndexOf(rule.Actions, PlaybookAction.CollectTriage);
            Assert.True(triage >= 0 && triage < kill,
                $"rule '{rule.Name}' kills before collecting triage");
        }
    }

    [Fact]
    public void Default_Escalates_Credential_Theft_To_Kill()
    {
        var d = Playbook.Default().Decide(Snap(95, techniques: new[] { "T1003" }));

        Assert.Equal("credential-theft-critical", d.MatchedRule);
        Assert.True(d.Orders(PlaybookAction.Kill));
        Assert.True(d.Orders(PlaybookAction.CollectTriage));
    }

    [Fact]
    public void Default_High_Score_Without_Credential_Theft_Does_Not_Kill()
    {
        var d = Playbook.Default().Decide(Snap(95));

        Assert.Equal("high-score-untrusted", d.MatchedRule);
        Assert.True(d.Orders(PlaybookAction.Suspend));
        Assert.False(d.Orders(PlaybookAction.Kill));
    }

    [Fact]
    public void Default_Trusted_High_Score_Only_Logs()
    {
        var d = Playbook.Default().Decide(Snap(95, trusted: true, name: "notepad.exe"));

        Assert.Equal("observe", d.MatchedRule);
        Assert.Equal(new[] { PlaybookAction.Log }, d.Actions);
    }

    [Fact]
    public void Default_Orders_Nothing_At_Score_Zero()
    {
        var d = Playbook.Default().Decide(Snap(0));

        Assert.Empty(d.Actions);
        Assert.Equal("", d.MatchedRule);
        Assert.Contains("no rule matched", d.Explanation);
    }

    // -------------------------------------------------------------- semantics

    [Fact]
    public void Matching_Rules_Union_Their_Actions_Without_Duplicates()
    {
        var pb = new Playbook(new[]
        {
            new PlaybookRule { Name = "a", MinScore = 10, Actions = new[] { PlaybookAction.Log, PlaybookAction.Suspend } },
            new PlaybookRule { Name = "b", MinScore = 20, Actions = new[] { PlaybookAction.Suspend, PlaybookAction.Kill } }
        });

        var d = pb.Decide(Snap(50));

        Assert.Equal(new[] { PlaybookAction.Log, PlaybookAction.Suspend, PlaybookAction.Kill }, d.Actions);
        Assert.Equal("a", d.MatchedRule);
    }

    [Fact]
    public void Stop_Halts_Evaluation_After_Contributing()
    {
        var pb = new Playbook(new[]
        {
            new PlaybookRule { Name = "a", MinScore = 10, Actions = new[] { PlaybookAction.Log }, Stop = true },
            new PlaybookRule { Name = "b", MinScore = 10, Actions = new[] { PlaybookAction.Kill } }
        });

        var d = pb.Decide(Snap(50));

        Assert.Equal(new[] { PlaybookAction.Log }, d.Actions);
        Assert.Contains("(stop)", d.Explanation);
    }

    [Fact]
    public void A_Stop_Rule_With_No_Actions_Suppresses_Everything_Below_It()
    {
        var pb = new Playbook(new[]
        {
            new PlaybookRule { Name = "allow-backup-agent", ProcessNameGlobs = new[] { "backup*.exe" }, Stop = true },
            new PlaybookRule { Name = "catch-all", Actions = new[] { PlaybookAction.Kill } }
        });

        var suppressed = pb.Decide(Snap(99, name: "backupsvc.exe"));
        Assert.Empty(suppressed.Actions);
        Assert.Equal("allow-backup-agent", suppressed.MatchedRule);

        var normal = pb.Decide(Snap(99, name: "evil.exe"));
        Assert.Equal(new[] { PlaybookAction.Kill }, normal.Actions);
    }

    [Theory]
    [InlineData(69, false)]
    [InlineData(70, true)]
    [InlineData(71, true)]
    public void MinScore_Is_Inclusive(int score, bool shouldMatch)
    {
        var pb = new Playbook(new[]
        {
            new PlaybookRule { Name = "r", MinScore = 70, Actions = new[] { PlaybookAction.Kill } }
        });

        Assert.Equal(shouldMatch, pb.Decide(Snap(score)).Orders(PlaybookAction.Kill));
    }

    [Fact]
    public void All_Required_Techniques_Must_Be_Present()
    {
        var pb = new Playbook(new[]
        {
            new PlaybookRule
            {
                Name = "r",
                RequiredTechniques = new[] { "T1003", "T1055" },
                Actions = new[] { PlaybookAction.Kill }
            }
        });

        Assert.Empty(pb.Decide(Snap(50, techniques: new[] { "T1003" })).Actions);
        Assert.Single(pb.Decide(Snap(50, techniques: new[] { "T1003", "T1055", "T1082" })).Actions);
    }

    [Fact]
    public void Technique_Matching_Is_Case_Insensitive_But_Not_Prefix_Based()
    {
        var pb = new Playbook(new[]
        {
            new PlaybookRule { Name = "r", RequiredTechniques = new[] { "t1003" }, Actions = new[] { PlaybookAction.Log } }
        });

        Assert.Single(pb.Decide(Snap(50, techniques: new[] { "T1003" })).Actions);

        // A sub-technique must not satisfy a rule written against the parent id.
        Assert.Empty(pb.Decide(Snap(50, techniques: new[] { "T1003.001" })).Actions);
    }

    [Fact]
    public void RequireUntrusted_Excludes_Signed_Processes()
    {
        var pb = new Playbook(new[]
        {
            new PlaybookRule { Name = "r", RequireUntrusted = true, Actions = new[] { PlaybookAction.Kill } }
        });

        Assert.Empty(pb.Decide(Snap(90, trusted: true)).Actions);
        Assert.Single(pb.Decide(Snap(90, trusted: false)).Actions);
    }

    [Fact]
    public void Any_Glob_Satisfies_The_Process_Name_Criterion()
    {
        var pb = new Playbook(new[]
        {
            new PlaybookRule
            {
                Name = "r",
                ProcessNameGlobs = new[] { "nothing*", "*shell.exe" },
                Actions = new[] { PlaybookAction.Log }
            }
        });

        Assert.Single(pb.Decide(Snap(1, name: "powershell.exe")).Actions);
        Assert.Empty(pb.Decide(Snap(1, name: "calc.exe")).Actions);
    }

    [Fact]
    public void An_Empty_Playbook_Orders_Nothing()
    {
        var pb = new Playbook(Array.Empty<PlaybookRule>());
        var d = pb.Decide(Snap(100));

        Assert.Empty(d.Actions);
        Assert.Equal("", d.MatchedRule);
    }

    [Fact]
    public void Decide_Tolerates_A_Null_Snapshot()
    {
        var d = Playbook.Default().Decide(null!);
        Assert.Empty(d.Actions);
        Assert.Equal("no snapshot supplied", d.Explanation);
    }

    // ----------------------------------------------------------------- FromJson

    [Fact]
    public void FromJson_Reads_A_Bare_Rule_Array()
    {
        const string json = """
        [
          { "name": "r1", "minScore": 55, "actions": ["Suspend", "kill"], "requireUntrusted": true, "stop": true }
        ]
        """;

        var pb = Playbook.FromJson(json, out var errors);

        Assert.Empty(errors);
        var rule = Assert.Single(pb.Rules);
        Assert.Equal("r1", rule.Name);
        Assert.Equal(55, rule.MinScore);
        Assert.True(rule.RequireUntrusted);
        Assert.True(rule.Stop);
        Assert.Equal(new[] { PlaybookAction.Suspend, PlaybookAction.Kill }, rule.Actions);
    }

    [Fact]
    public void FromJson_Reads_An_Object_With_A_Rules_Array()
    {
        const string json = """
        { "rules": [ { "name": "r1", "processNameGlobs": ["*.exe"], "actions": ["Log"] } ] }
        """;

        var pb = Playbook.FromJson(json, out var errors);

        Assert.Empty(errors);
        Assert.Single(pb.Rules);
        Assert.True(pb.Decide(Snap(0, name: "a.exe")).Orders(PlaybookAction.Log));
    }

    [Fact]
    public void FromJson_Falls_Back_To_The_Default_Playbook_On_Unparsable_Input()
    {
        // Falling back to an EMPTY playbook would silently disable every response.
        var pb = Playbook.FromJson("{ this is not json", out var errors);

        Assert.NotEmpty(errors);
        Assert.Contains(errors, e => e.Contains("falling back"));
        Assert.Equal(Playbook.Default().Rules.Count, pb.Rules.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("123")]
    [InlineData("\"a string\"")]
    [InlineData("{ \"notrules\": [] }")]
    public void FromJson_Falls_Back_On_A_Document_That_Is_Not_A_Rule_List(string json)
    {
        var pb = Playbook.FromJson(json, out var errors);

        Assert.NotEmpty(errors);
        Assert.Equal(Playbook.Default().Rules.Count, pb.Rules.Count);
    }

    [Fact]
    public void FromJson_Honours_An_Explicitly_Empty_Rule_List()
    {
        // "[]" is a legitimate detect-only posture, not a config error.
        var pb = Playbook.FromJson("[]", out var errors);

        Assert.Empty(errors);
        Assert.Empty(pb.Rules);
    }

    [Theory]
    [InlineData("""[{ "name": "r", "actions": ["Explode"] }]""", "unknown action")]
    [InlineData("""[{ "name": "r", "actions": [3] }]""", "must be strings")]
    [InlineData("""[{ "name": "r", "actions": ["3"] }]""", "unknown action")]
    [InlineData("""[{ "name": "r", "actions": "Log" }]""", "must be an array")]
    [InlineData("""[{ "minScore": 5, "actions": ["Log"] }]""", "'name' is required")]
    [InlineData("""[{ "name": "  ", "actions": ["Log"] }]""", "'name' is required")]
    [InlineData("""[{ "name": "r", "minScore": -1 }]""", "must be >= 0")]
    [InlineData("""[{ "name": "r", "minScore": "high" }]""", "must be an integer")]
    [InlineData("""[{ "name": "r", "requireUntrusted": "yes" }]""", "must be a boolean")]
    [InlineData("""[{ "name": "r", "stop": 1 }]""", "must be a boolean")]
    [InlineData("""["not an object"]""", "expected an object")]
    public void FromJson_Skips_An_Invalid_Rule_And_Explains_Why(string json, string expectedFragment)
    {
        var pb = Playbook.FromJson(json, out var errors);

        Assert.Empty(pb.Rules);
        Assert.Contains(errors, e => e.Contains(expectedFragment));
    }

    [Fact]
    public void FromJson_Keeps_Valid_Rules_Alongside_An_Invalid_One()
    {
        const string json = """
        [
          { "name": "good1", "actions": ["Log"] },
          { "name": "bad", "actions": ["Nonsense"] },
          { "name": "good2", "actions": ["Kill"] }
        ]
        """;

        var pb = Playbook.FromJson(json, out var errors);

        Assert.Equal(2, pb.Rules.Count);
        Assert.Single(errors);
        Assert.Equal(new[] { "good1", "good2" }, pb.Rules.Select(r => r.Name).ToArray());
    }

    [Fact]
    public void FromJson_Rejects_A_Duplicate_Rule_Name()
    {
        const string json = """
        [ { "name": "dup", "actions": ["Log"] }, { "name": "DUP", "actions": ["Kill"] } ]
        """;

        var pb = Playbook.FromJson(json, out var errors);

        Assert.Single(pb.Rules);
        Assert.Contains(errors, e => e.Contains("duplicate rule name"));
    }

    [Fact]
    public void FromJson_Drops_Blank_Globs_But_Keeps_The_Rule()
    {
        const string json = """
        [ { "name": "r", "processNameGlobs": ["", "  ", "*.exe"], "actions": ["Log"] } ]
        """;

        var pb = Playbook.FromJson(json, out var errors);

        var rule = Assert.Single(pb.Rules);
        Assert.Equal(new[] { "*.exe" }, rule.ProcessNameGlobs);
        Assert.Equal(2, errors.Count(e => e.Contains("blank entry")));
    }

    [Fact]
    public void FromJson_Deduplicates_Repeated_Actions()
    {
        var pb = Playbook.FromJson("""[{ "name": "r", "actions": ["Log", "log", "LOG"] }]""", out var errors);

        Assert.Empty(errors);
        Assert.Equal(new[] { PlaybookAction.Log }, Assert.Single(pb.Rules).Actions);
    }

    [Fact]
    public void FromJson_Round_Trips_Into_A_Working_Decision()
    {
        const string json = """
        [
          { "name": "quarantine-lolbin", "minScore": 60, "requireUntrusted": true,
            "processNameGlobs": ["powershell.exe", "cmd.exe"],
            "requiredTechniques": ["T1059.001"],
            "actions": ["Suspend", "QuarantineFiles", "NotifyWebhook"], "stop": true },
          { "name": "fallback", "minScore": 1, "actions": ["Log"] }
        ]
        """;

        var pb = Playbook.FromJson(json, out var errors);
        Assert.Empty(errors);

        var hit = pb.Decide(Snap(75, name: "PowerShell.exe", techniques: new[] { "T1059.001" }));
        Assert.Equal("quarantine-lolbin", hit.MatchedRule);
        Assert.Equal(
            new[] { PlaybookAction.Suspend, PlaybookAction.QuarantineFiles, PlaybookAction.NotifyWebhook },
            hit.Actions);

        var miss = pb.Decide(Snap(75, name: "calc.exe"));
        Assert.Equal("fallback", miss.MatchedRule);
        Assert.Equal(new[] { PlaybookAction.Log }, miss.Actions);
    }
}

// ===========================================================================
//  NetworkIsolation
// ===========================================================================

public class ResponseV2NetworkIsolationTests
{
    private static NetworkIsolation New() => new(new Logger(), new ManualClock());

    private static int IndexOfCommandContaining(IReadOnlyList<string[]> cmds, string token)
    {
        for (int i = 0; i < cmds.Count; i++)
            if (cmds[i].Any(a => a.Contains(token, StringComparison.OrdinalIgnoreCase))) return i;
        return -1;
    }

    [Fact]
    public void Isolate_Commands_Install_Every_Allow_Rule_Before_Anything_Blocks()
    {
        var cmds = NetworkIsolation.BuildIsolateCommands(new[] { "10.0.0.5", "10.0.0.6" });

        int lastAllow = -1;
        int firstBlock = int.MaxValue;
        for (int i = 0; i < cmds.Count; i++)
        {
            if (cmds[i].Any(a => a == "action=allow")) lastAllow = Math.Max(lastAllow, i);
            if (cmds[i].Any(a => a.Contains("blockoutbound", StringComparison.Ordinal)))
                firstBlock = Math.Min(firstBlock, i);
        }

        Assert.True(lastAllow >= 0, "expected allow rules");
        Assert.True(firstBlock < int.MaxValue, "expected a blocking policy change");
        Assert.True(lastAllow < firstBlock, "an allow rule must never be installed after the block");
    }

    [Fact]
    public void Isolate_Commands_Have_The_Expected_Shape()
    {
        var cmds = NetworkIsolation.BuildIsolateCommands(new[] { "10.0.0.5" });

        Assert.Equal(4, cmds.Count);
        Assert.Equal(new[]
        {
            "advfirewall", "firewall", "add", "rule",
            "name=ProcessShield Isolation Allow Out",
            "dir=out", "action=allow", "remoteip=10.0.0.5", "enable=yes", "profile=any"
        }, cmds[0]);
        Assert.Equal(new[]
        {
            "advfirewall", "firewall", "add", "rule",
            "name=ProcessShield Isolation Allow In",
            "dir=in", "action=allow", "remoteip=10.0.0.5", "enable=yes", "profile=any"
        }, cmds[1]);
        Assert.Equal(new[] { "advfirewall", "set", "allprofiles", "state", "on" }, cmds[2]);
        Assert.Equal(new[] { "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound" }, cmds[3]);
    }

    [Fact]
    public void Isolate_Uses_A_Default_Policy_Change_Not_An_Explicit_Block_Rule()
    {
        // An explicit block rule outranks an explicit allow in Windows Firewall and
        // would override the allowlist, locking the operator out.
        var cmds = NetworkIsolation.BuildIsolateCommands(new[] { "10.0.0.5" });

        Assert.DoesNotContain(cmds, c => c.Contains("action=block"));
        Assert.Contains(cmds, c => c.Contains("blockinbound,blockoutbound"));
    }

    [Fact]
    public void Isolate_Commands_Join_The_Allowlist_Into_One_Rule_Per_Direction()
    {
        var cmds = NetworkIsolation.BuildIsolateCommands(new[] { "10.0.0.5", "192.168.1.0/24", "LocalSubnet" });

        Assert.Equal(2, cmds.Count(c => c.Contains("action=allow")));
        Assert.Contains(cmds, c => c.Contains("remoteip=10.0.0.5,192.168.1.0/24,LocalSubnet"));
    }

    [Fact]
    public void Isolate_Commands_Deduplicate_The_Allowlist()
    {
        var cmds = NetworkIsolation.BuildIsolateCommands(new[] { "10.0.0.5", " 10.0.0.5 ", "10.0.0.6", "", "  " });

        Assert.Contains(cmds, c => c.Contains("remoteip=10.0.0.5,10.0.0.6"));
    }

    [Fact]
    public void Isolate_Commands_With_No_Allowlist_Contain_No_Allow_Rules()
    {
        var cmds = NetworkIsolation.BuildIsolateCommands(Array.Empty<string>());

        Assert.Equal(2, cmds.Count);
        Assert.DoesNotContain(cmds, c => c.Contains("action=allow"));
        Assert.Contains(cmds, c => c.Contains("blockinbound,blockoutbound"));
    }

    [Fact]
    public void Every_Argument_Is_A_Separate_Element_Never_A_Concatenated_Command_String()
    {
        var all = NetworkIsolation.BuildIsolateCommands(new[] { "10.0.0.5" })
            .Concat(NetworkIsolation.BuildReleaseCommands());

        foreach (var cmd in all)
        {
            foreach (var arg in cmd)
            {
                // Rule names legitimately contain spaces; nothing else may, or the
                // caller is building a shell string somewhere it should not.
                if (arg.StartsWith("name=", StringComparison.Ordinal)) continue;
                Assert.DoesNotContain(" ", arg);
            }
        }
    }

    [Fact]
    public void Release_Restores_The_Policy_First_Then_Removes_The_Rules()
    {
        var cmds = NetworkIsolation.BuildReleaseCommands();

        Assert.Equal(3, cmds.Count);
        Assert.Equal(new[] { "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound" }, cmds[0]);
        Assert.Equal(new[] { "advfirewall", "firewall", "delete", "rule", "name=ProcessShield Isolation Allow Out" }, cmds[1]);
        Assert.Equal(new[] { "advfirewall", "firewall", "delete", "rule", "name=ProcessShield Isolation Allow In" }, cmds[2]);
        Assert.True(IndexOfCommandContaining(cmds, "firewallpolicy") <
                    IndexOfCommandContaining(cmds, "delete"));
    }

    [Fact]
    public void Release_Deletes_Exactly_The_Rules_Isolate_Creates()
    {
        var created = NetworkIsolation.BuildIsolateCommands(new[] { "10.0.0.5" })
            .Where(c => c.Contains("add"))
            .Select(c => c.First(a => a.StartsWith("name=", StringComparison.Ordinal)))
            .ToArray();
        var deleted = NetworkIsolation.BuildReleaseCommands()
            .Where(c => c.Contains("delete"))
            .Select(c => c.First(a => a.StartsWith("name=", StringComparison.Ordinal)))
            .ToArray();

        Assert.Equal(created.OrderBy(x => x, StringComparer.Ordinal),
                     deleted.OrderBy(x => x, StringComparer.Ordinal));
    }

    [Fact]
    public void Every_Rule_Name_Carries_The_ProcessShield_Prefix()
    {
        var all = NetworkIsolation.BuildIsolateCommands(new[] { "10.0.0.5" })
            .Concat(NetworkIsolation.BuildReleaseCommands())
            .SelectMany(c => c)
            .Where(a => a.StartsWith("name=", StringComparison.Ordinal));

        foreach (var name in all)
            Assert.StartsWith("name=" + NetworkIsolation.RuleNamePrefix, name);
    }

    // -------------------------------------------------------------- guardrails

    [Fact]
    public void Isolate_Refuses_An_Empty_Allowlist()
    {
        var iso = New();

        var result = iso.Isolate(Array.Empty<string>());

        Assert.False(result.Ok);
        Assert.Contains("empty allowlist", result.Message);
        Assert.False(iso.State.Active);
    }

    [Fact]
    public void Isolate_Refuses_A_Null_Allowlist()
    {
        var iso = New();

        var result = iso.Isolate(null!);

        Assert.False(result.Ok);
        Assert.False(iso.State.Active);
    }

    [Fact]
    public void Isolate_Refuses_A_Whitespace_Only_Allowlist()
    {
        var iso = New();

        var result = iso.Isolate(new[] { "", "   ", "\t" });

        Assert.False(result.Ok);
        Assert.Contains("empty allowlist", result.Message);
    }

    [Fact]
    public void Isolate_Refuses_An_Allowlist_With_An_Invalid_Entry()
    {
        var iso = New();

        var result = iso.Isolate(new[] { "10.0.0.5", "evil.example.com" });

        Assert.False(result.Ok);
        Assert.Contains("evil.example.com", result.Message);
        Assert.False(iso.State.Active);
    }

    [Fact]
    public void Isolate_Refuses_An_Oversized_Allowlist()
    {
        var iso = New();
        var many = Enumerable.Range(1, NetworkIsolation.MaxAllowlistEntries + 1)
            .Select(i => "10.0.0." + i).ToArray();

        var result = iso.Isolate(many);

        Assert.False(result.Ok);
        Assert.Contains("above the", result.Message);
    }

    [Fact]
    public void State_Starts_Inactive()
    {
        var state = New().State;

        Assert.False(state.Active);
        Assert.Null(state.AppliedUtc);
        Assert.Empty(state.AllowedRemoteAddresses);
    }

    [Theory]
    [InlineData("10.0.0.5")]
    [InlineData("192.168.1.0/24")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("2001:db8::/32")]
    [InlineData("10.0.0.1-10.0.0.50")]
    [InlineData("LocalSubnet")]
    [InlineData("localsubnet")]
    [InlineData("DNS")]
    [InlineData("DefaultGateway")]
    public void Valid_Remote_Addresses_Are_Accepted(string value)
        => Assert.True(NetworkIsolation.IsValidRemoteAddress(value), value);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("any")]                                   // would silently defeat isolation
    [InlineData("Any")]
    [InlineData("0.0.0.0")]                               // ditto: "everything"
    [InlineData("0.0.0.0/0")]
    [InlineData("::")]
    [InlineData("::/0")]
    [InlineData("10.0.0.5,10.0.0.6")]                     // would split the remoteip list
    [InlineData("10.0.0.5 dir=in")]                       // would smuggle an extra netsh setting
    [InlineData("\"10.0.0.5\"")]
    [InlineData("10.0.0.5&calc.exe")]
    [InlineData("example.com")]
    [InlineData("10.0.0.0/33")]
    [InlineData("2001:db8::/129")]
    [InlineData("10.0.0.0/-1")]
    [InlineData("10.0.0.0/abc")]
    [InlineData("10.0.0.1-")]
    [InlineData("-10.0.0.1")]
    [InlineData("10.0.0.1-::1")]                          // mismatched families
    public void Invalid_Remote_Addresses_Are_Rejected(string? value)
        => Assert.False(NetworkIsolation.IsValidRemoteAddress(value));

    [Fact]
    public void An_Over_Long_Address_Is_Rejected()
        => Assert.False(NetworkIsolation.IsValidRemoteAddress(new string('1', 200)));
}

// ===========================================================================
//  TriageCollector
// ===========================================================================

public class ResponseV2TriageCollectorTests
{
    private static readonly DateTime Fixed = new(2026, 5, 6, 7, 8, 9, DateTimeKind.Utc);

    private static TriageCollector New() => new(new ManualClock(Fixed));

    [Fact]
    public void ZipFileName_Is_Deterministic_And_Descriptive()
        => Assert.Equal("triage-1234-20260506T070809Z.zip", TriageCollector.ZipFileName(1234, Fixed));

    [Fact]
    public void ZipFileName_Normalises_To_Utc()
    {
        var local = new DateTime(2026, 5, 6, 7, 8, 9, DateTimeKind.Utc).ToLocalTime();
        Assert.Equal("triage-7-20260506T070809Z.zip", TriageCollector.ZipFileName(7, local));
    }

    [Fact]
    public void UniqueZipPath_Returns_The_Plain_Name_When_Free()
    {
        using var tmp = new ResponseV2TempDir();
        Assert.Equal(Path.Combine(tmp.Root, "triage-9-20260506T070809Z.zip"),
                     TriageCollector.UniqueZipPath(tmp.Root, 9, Fixed));
    }

    [Fact]
    public void UniqueZipPath_Never_Overwrites_Existing_Evidence()
    {
        using var tmp = new ResponseV2TempDir();
        File.WriteAllText(Path.Combine(tmp.Root, "triage-9-20260506T070809Z.zip"), "first");
        Assert.EndsWith("triage-9-20260506T070809Z-2.zip", TriageCollector.UniqueZipPath(tmp.Root, 9, Fixed));

        File.WriteAllText(Path.Combine(tmp.Root, "triage-9-20260506T070809Z-2.zip"), "second");
        Assert.EndsWith("triage-9-20260506T070809Z-3.zip", TriageCollector.UniqueZipPath(tmp.Root, 9, Fixed));
    }

    // ------------------------------------------------------ staging accounting

    [Fact]
    public void Stage_Records_A_Written_Artifact_As_Included()
    {
        using var tmp = new ResponseV2TempDir();
        var stage = new TriageCollector.TriageStage(tmp.Root);

        stage.AddText("a.txt", () => "content");

        Assert.Equal(new[] { "a.txt" }, stage.Included);
        Assert.Empty(stage.Skipped);
        Assert.Equal("content", File.ReadAllText(Path.Combine(tmp.Root, "a.txt")));
    }

    [Fact]
    public void Stage_Turns_A_Throwing_Producer_Into_A_Skip()
    {
        using var tmp = new ResponseV2TempDir();
        var stage = new TriageCollector.TriageStage(tmp.Root);

        stage.AddText("boom.txt", () => throw new InvalidOperationException("nope"));

        Assert.Empty(stage.Included);
        Assert.Contains(stage.Skipped, s => s.StartsWith("boom.txt:") && s.Contains("nope"));
    }

    [Fact]
    public void Stage_Labels_Access_Denied_Explicitly()
    {
        using var tmp = new ResponseV2TempDir();
        var stage = new TriageCollector.TriageStage(tmp.Root);

        stage.AddText("denied.txt", () => throw new UnauthorizedAccessException("no rights"));

        Assert.Contains(stage.Skipped, s => s.Contains("access denied"));
    }

    [Fact]
    public void Stage_Treats_Empty_Output_As_Missing_Not_Collected()
    {
        using var tmp = new ResponseV2TempDir();
        var stage = new TriageCollector.TriageStage(tmp.Root);

        stage.AddText("empty.txt", () => "");

        Assert.Empty(stage.Included);
        Assert.Contains(stage.Skipped, s => s.Contains("no data available"));
        Assert.False(File.Exists(Path.Combine(tmp.Root, "empty.txt")));
    }

    [Fact]
    public void Stage_Records_An_Explicit_Skip()
    {
        using var tmp = new ResponseV2TempDir();
        var stage = new TriageCollector.TriageStage(tmp.Root);

        stage.Skip("thing.json", "not applicable");

        Assert.Equal(new[] { "thing.json: not applicable" }, stage.Skipped);
    }

    [Fact]
    public void Stage_Records_A_Write_Failure_Rather_Than_Throwing()
    {
        using var tmp = new ResponseV2TempDir();
        var stage = new TriageCollector.TriageStage(Path.Combine(tmp.Root, "no-such-dir"));

        stage.AddText("a.txt", () => "content");

        Assert.Empty(stage.Included);
        Assert.Contains(stage.Skipped, s => s.Contains("write failed"));
    }

    // ------------------------------------------------------- pure renderers

    [Fact]
    public void Environment_Artifact_Carries_Host_Context()
    {
        string text = TriageCollector.RenderEnvironment(Fixed);

        Assert.Contains("machine: ", text);
        Assert.Contains("os: ", text);
        Assert.Contains("agent_elevated: ", text);
        Assert.Contains("2026-05-06T07:08:09", text);
    }

    [Fact]
    public void Tcp_Artifact_Says_Why_It_Is_Host_Wide()
    {
        string text = TriageCollector.RenderTcpTable();

        Assert.Contains("no owning-pid column", text);
        Assert.Contains("TCP listeners", text);
    }

    [Fact]
    public void Process_List_Artifact_Has_A_Header_And_Includes_This_Process()
    {
        string text = TriageCollector.RenderProcessList();

        Assert.Contains("pid,parent_pid,name", text);
        Assert.Contains(Environment.ProcessId.ToString(), text);
    }

    // ------------------------------------------------------- end-to-end collect

    [Fact]
    public void Collect_Produces_A_Readable_Zip_For_The_Current_Process()
    {
        using var tmp = new ResponseV2TempDir();
        string temp = Path.GetTempPath();
        var stagingBefore = new HashSet<string>(Directory.GetDirectories(temp, "ProcessShield-triage-*"));

        var result = New().Collect(Environment.ProcessId, tmp.Root);

        Assert.True(result.Ok, result.Error);
        Assert.Equal("", result.Error);
        Assert.True(File.Exists(result.ZipPath));
        Assert.True(result.Bytes > 0);
        Assert.Contains("manifest.json", result.Included);
        Assert.Contains("environment.txt", result.Included);

        using (var zip = ZipFile.OpenRead(result.ZipPath))
        {
            Assert.NotNull(zip.GetEntry("manifest.json"));
            foreach (var name in result.Included)
                Assert.NotNull(zip.GetEntry(name));
        }

        // The staging directory must not survive: it holds incident data and disk.
        var leftovers = Directory.GetDirectories(temp, "ProcessShield-triage-*")
            .Where(d => !stagingBefore.Contains(d)).ToArray();
        Assert.Empty(leftovers);
    }

    [Fact]
    public void Collect_Includes_The_Profile_Snapshot_When_One_Is_Supplied()
    {
        using var tmp = new ResponseV2TempDir();
        var t = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var snap = new ProfileSnapshot
        {
            Pid = Environment.ProcessId,
            ProcessName = "testhost.exe",
            ImagePath = "",
            Score = 88,
            Trusted = false,
            Contained = true,
            SuspendedByAnalyst = false,
            Terminated = false,
            Reasons = new[] { "[+40] distinctive-reason-marker" },
            StagedArchives = Array.Empty<string>(),
            FirstSeenUtc = t,
            LastUpdatedUtc = t
        };

        var result = New().Collect(Environment.ProcessId, tmp.Root, snap);

        Assert.True(result.Ok, result.Error);
        Assert.Contains("profile-snapshot.json", result.Included);

        using var zip = ZipFile.OpenRead(result.ZipPath);
        using var reader = new StreamReader(zip.GetEntry("profile-snapshot.json")!.Open());
        Assert.Contains("distinctive-reason-marker", reader.ReadToEnd());
    }

    [Fact]
    public void Collect_Without_A_Snapshot_Records_It_As_Skipped()
    {
        using var tmp = new ResponseV2TempDir();

        var result = New().Collect(Environment.ProcessId, tmp.Root);

        Assert.True(result.Ok, result.Error);
        Assert.DoesNotContain("profile-snapshot.json", result.Included);
        Assert.Contains(result.Skipped, s => s.StartsWith("profile-snapshot.json:"));
    }

    [Fact]
    public void Collect_Still_Produces_A_Package_For_A_Dead_Pid()
    {
        using var tmp = new ResponseV2TempDir();

        // A process that has already exited (or a recycled pid) must degrade to a
        // partial package, never abort the collection.
        var result = New().Collect(int.MaxValue, tmp.Root);

        Assert.True(result.Ok, result.Error);
        Assert.True(File.Exists(result.ZipPath));
        Assert.Contains("environment.txt", result.Included);
        Assert.Contains(result.Skipped, s => s.StartsWith("process.txt:"));
        Assert.DoesNotContain("modules.txt", result.Included);
    }

    [Fact]
    public void Collect_Rejects_A_Blank_Output_Directory()
    {
        var result = New().Collect(Environment.ProcessId, "   ");

        Assert.False(result.Ok);
        Assert.Contains("output directory", result.Error);
        Assert.Equal("", result.ZipPath);
    }

    [Fact]
    public void Collect_Reports_An_Unusable_Output_Directory_Instead_Of_Throwing()
    {
        using var tmp = new ResponseV2TempDir();
        string asFile = Path.Combine(tmp.Root, "not-a-directory");
        File.WriteAllText(asFile, "in the way");

        var result = New().Collect(Environment.ProcessId, asFile);

        Assert.False(result.Ok);
        Assert.NotEqual("", result.Error);
    }
}

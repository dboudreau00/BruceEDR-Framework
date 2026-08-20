using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProcessShield.Core;

namespace ProcessShield.Response;

/// <summary>
/// One item held in the quarantine vault. The plaintext never appears here — only
/// the metadata an analyst needs to decide whether to restore or purge, plus the
/// SHA-256 of the ORIGINAL bytes so a restore can be proven byte-identical.
/// </summary>
public sealed record VaultEntry
{
    /// <summary>Vault id. Fixed width and timestamp-prefixed, so ordinal sort == chronological.</summary>
    public string Id { get; init; } = "";
    /// <summary>Where the file came from, for restore and for the incident report.</summary>
    public string OriginalPath { get; init; } = "";
    /// <summary>Plaintext length in bytes. Equals the ciphertext length (GCM is a stream cipher).</summary>
    public long OriginalSize { get; init; }
    /// <summary>Uppercase hex SHA-256 of the plaintext, computed BEFORE encryption.</summary>
    public string Sha256 { get; init; } = "";
    public DateTime QuarantinedUtc { get; init; }
    /// <summary>Why it was taken, e.g. the detection trigger. Free text for the analyst.</summary>
    public string Reason { get; init; } = "";
    /// <summary>PID that was responsible at quarantine time. May already be recycled.</summary>
    public int Pid { get; init; }
    public string ProcessName { get; init; } = "";
    /// <summary>True once the item has been written back out at least once.</summary>
    public bool Restored { get; init; }
    public DateTime? RestoredUtc { get; init; }
}

/// <summary>
/// Encrypted quarantine store. Replaces "move the malware into a folder", which
/// leaves a live, double-clickable payload on disk that AV will keep re-detecting
/// (and that a careless analyst can re-execute).
///
/// Each item is AES-256-GCM encrypted with a fresh random 12-byte nonce and a
/// 16-byte tag, written to a blob whose name carries no trace of the original
/// extension, and indexed by an append-only JSON Lines manifest.
///
/// HONEST THREAT MODEL / LIMITATION — this is the same posture as AuditLogSink and
/// it must not be oversold:
///  - The vault key is generated with <see cref="RandomNumberGenerator"/> on first
///    use and stored in a "vault.key" file NEXT TO THE DATA. Anyone who can read
///    that file can decrypt every blob.
///  - So this defeats ACCIDENTAL RE-EXECUTION, on-access AV re-detection, and
///    naive scanners/backup agents that would choke on a live sample. It does NOT
///    defeat a SAME-PRIVILEGE attacker who already owns the host, and it is not a
///    substitute for an admin-only ACL on the vault directory.
///  - It is also not a malware "sandbox": the bytes are intact and become dangerous
///    again the moment <see cref="Restore"/> writes them back out.
///
/// Every public method is exception-safe: expected conditions (missing file, locked
/// file, unknown id, oversized input, failed tag check) come back as a typed failure
/// with a message, never as an exception.
/// </summary>
public sealed class QuarantineVault : IDisposable
{
    /// <summary>Blob magic. The trailing digit is the on-disk format version.</summary>
    private static readonly byte[] Magic = "PSVLT1"u8.ToArray();

    private const int NonceBytes = 12;      // AesGcm.NonceByteSizes.MaxSize
    private const int TagBytes = 16;        // AesGcm.TagByteSizes.MaxSize
    private const int LengthBytes = 8;
    private const int HeaderBytes = 6 + NonceBytes + TagBytes + LengthBytes;   // 42

    /// <summary>
    /// Hard cap on a single item. AesGcm is a ONE-SHOT API: encrypting needs the whole
    /// plaintext and the whole ciphertext resident at once, so a 512 MB item already
    /// costs about a gigabyte of managed memory. Anything larger is refused with a clear
    /// error rather than being allowed to OOM the agent mid-containment. Chunked/framed
    /// encryption would lift this, at the cost of a more complex format.
    /// </summary>
    public const long MaxItemBytes = 512L * 1024 * 1024;

    private const string KeyFileName = "vault.key";
    private const string ManifestFileName = "manifest.jsonl";
    private const string BlobDirName = "blobs";
    private const string BlobExtension = ".psvblob";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    private readonly object _gate = new();
    private readonly IClock _clock;
    private readonly string _vaultDir;
    private readonly string _blobDir;
    private readonly string _manifestPath;
    private readonly string _keyPath;
    private readonly byte[] _key;
    private readonly Dictionary<string, VaultEntry> _index = new(StringComparer.Ordinal);

    private long _seq;
    // volatile: the fast-path disposed checks read this outside the lock, and a stale
    // read would let an operation run against a key that Dispose has already zeroed.
    private volatile bool _disposed;

    /// <summary>Directory holding the manifest, the key and the blobs subdirectory.</summary>
    public string VaultDirectory => _vaultDir;

    /// <summary>
    /// Manifest lines that could not be parsed while loading. Non-zero means part of the
    /// index was lost (hand-edited or partially written file); the blobs themselves are
    /// unaffected but become unreachable through this API. Exposed for diagnostics/tests.
    /// </summary>
    internal int MalformedManifestLines { get; private set; }

    /// <summary>
    /// Opens (and creates, if missing) a vault rooted at <paramref name="vaultDir"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a key file exists but is unusable. This is deliberately fatal rather
    /// than "generate a fresh key": silently re-keying would make every stored blob
    /// permanently undecryptable while the vault carried on looking healthy.
    /// </exception>
    public QuarantineVault(string vaultDir, IClock? clock = null)
    {
        if (string.IsNullOrWhiteSpace(vaultDir))
            throw new ArgumentException("vault directory must be a non-empty path", nameof(vaultDir));

        _clock = clock ?? SystemClock.Instance;
        _vaultDir = Path.GetFullPath(vaultDir);
        _blobDir = Path.Combine(_vaultDir, BlobDirName);
        _manifestPath = Path.Combine(_vaultDir, ManifestFileName);
        _keyPath = Path.Combine(_vaultDir, KeyFileName);

        Directory.CreateDirectory(_vaultDir);
        Directory.CreateDirectory(_blobDir);

        _key = LoadOrCreateKey(_keyPath);
        LoadManifest();
    }

    /// <summary>
    /// Total bytes this vault occupies on disk for the items it currently holds
    /// (blob headers included). Derived from the index rather than by stat'ing every
    /// blob, so it is cheap and safe to poll from a UI.
    /// </summary>
    public long TotalBytes
    {
        get
        {
            lock (_gate)
            {
                long total = 0;
                foreach (var e in _index.Values) total += HeaderBytes + e.OriginalSize;
                return total;
            }
        }
    }

    /// <summary>Entries currently held, oldest first.</summary>
    public IReadOnlyList<VaultEntry> List()
    {
        lock (_gate)
        {
            var all = _index.Values.ToList();
            all.Sort(static (a, b) => string.CompareOrdinal(a.Id, b.Id));
            return all;
        }
    }

    /// <summary>The entry with this id, or null when it is unknown or already purged.</summary>
    public VaultEntry? Get(string id)
    {
        if (string.IsNullOrEmpty(id)) return null;
        lock (_gate) { return _index.TryGetValue(id, out var e) ? e : null; }
    }

    /// <summary>
    /// Encrypts <paramref name="sourcePath"/> into the vault. Returns null on failure;
    /// use the <c>out string error</c> overload when you need the reason.
    /// </summary>
    public VaultEntry? Store(string sourcePath, string reason, int pid, string processName, bool deleteOriginal = true)
        => Store(sourcePath, reason, pid, processName, deleteOriginal, out _);

    /// <summary>
    /// Encrypts <paramref name="sourcePath"/> into the vault.
    ///
    /// A non-null return means the encrypted copy is COMMITTED (blob written, manifest
    /// row appended). <paramref name="error"/> can still be non-empty alongside a
    /// non-null entry: that means a best-effort follow-up step failed — in practice,
    /// deleting the original, which a running process can hold open. The caller should
    /// surface that, because the live payload is then still on disk.
    ///
    /// Commit order is blob -> manifest -> delete original, so a crash can leave an
    /// orphan blob (harmless, and reclaimable) but never a manifest row without a blob
    /// and never a deleted original without a stored copy.
    /// </summary>
    public VaultEntry? Store(string sourcePath, string reason, int pid, string processName,
                             bool deleteOriginal, out string error)
    {
        error = "";
        if (_disposed) { error = "vault is disposed"; return null; }
        if (string.IsNullOrWhiteSpace(sourcePath)) { error = "source path is empty"; return null; }

        string full;
        try { full = Path.GetFullPath(sourcePath); }
        catch (Exception ex) { error = $"invalid source path: {ex.Message}"; return null; }

        if (!File.Exists(full)) { error = $"source not found or not a file: {full}"; return null; }

        if (!TryReadShared(full, out byte[] plaintext, out string readError))
        {
            error = readError;
            return null;
        }

        try
        {
            string sha = Convert.ToHexString(SHA256.HashData(plaintext));
            DateTime now = _clock.UtcNow;

            lock (_gate)
            {
                // Re-checked under the lock: Dispose zeroes the key, and encrypting with
                // a zeroed key would produce a blob nothing can ever decrypt.
                if (_disposed) { error = "vault is disposed"; return null; }

                string id = NextId(now);
                var entry = new VaultEntry
                {
                    Id = id,
                    OriginalPath = full,
                    OriginalSize = plaintext.LongLength,
                    Sha256 = sha,
                    QuarantinedUtc = now,
                    Reason = reason ?? "",
                    Pid = pid,
                    ProcessName = processName ?? "",
                    Restored = false,
                    RestoredUtc = null
                };

                if (!TryWriteBlob(entry, plaintext, out string writeError))
                {
                    error = writeError;
                    return null;
                }

                if (!TryAppendManifest(new ManifestRow { Entry = entry, Purged = false }, out string manifestError))
                {
                    // The manifest is the index of record. Without a row the blob is
                    // unreachable, so roll it back rather than leaving silent garbage.
                    TryDeleteBlob(id, out _);
                    error = manifestError;
                    return null;
                }

                _index[id] = entry;

                if (deleteOriginal && !TryDeleteFile(full, out string deleteError))
                    error = $"stored, but the original could not be deleted ({deleteError}); the live payload is still at {full}";

                return entry;
            }
        }
        finally
        {
            // The plaintext of a malware sample should not linger in a pooled/collected
            // buffer any longer than necessary. This is hygiene, not a guarantee: the GC
            // may already have copied the array during a compaction.
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Decrypts an entry back to <paramref name="destinationPath"/>.
    ///
    /// Fails, writing NOTHING, when: the id is unknown, the destination already exists,
    /// the blob header is malformed, the GCM tag does not verify, or the recovered bytes
    /// do not hash to the recorded SHA-256. Decryption completes fully in memory before
    /// anything touches the destination, so a partially decrypted file can never appear.
    ///
    /// Refusing to overwrite is deliberate: restore usually targets the path the malware
    /// originally occupied, and clobbering whatever is there now (possibly a clean
    /// replacement, possibly evidence) is not a decision this class should make.
    /// </summary>
    public bool Restore(string id, string destinationPath, out string error)
    {
        error = "";
        if (_disposed) { error = "vault is disposed"; return false; }
        if (string.IsNullOrWhiteSpace(destinationPath)) { error = "destination path is empty"; return false; }

        string dest;
        try { dest = Path.GetFullPath(destinationPath); }
        catch (Exception ex) { error = $"invalid destination path: {ex.Message}"; return false; }

        lock (_gate)
        {
            if (string.IsNullOrEmpty(id) || !_index.TryGetValue(id, out var entry))
            {
                error = $"unknown vault id '{id}'";
                return false;
            }

            if (File.Exists(dest) || Directory.Exists(dest))
            {
                error = $"destination already exists: {dest}";
                return false;
            }

            if (!TryDecrypt(entry, out byte[] plaintext, out string decryptError))
            {
                error = decryptError;
                return false;
            }

            try
            {
                string? destDir = Path.GetDirectoryName(dest);
                if (!string.IsNullOrEmpty(destDir)) Directory.CreateDirectory(destDir);

                // Write to a sibling temp file then move: the destination either does not
                // exist or is the complete file, never a half-written one.
                string tmp = dest + ".psvrestore.tmp";
                try
                {
                    File.WriteAllBytes(tmp, plaintext);
                    File.Move(tmp, dest, overwrite: false);
                }
                catch (Exception ex)
                {
                    TryDeleteFile(tmp, out _);
                    error = $"write failed: {ex.GetType().Name}: {ex.Message}";
                    return false;
                }

                var updated = entry with { Restored = true, RestoredUtc = _clock.UtcNow };
                if (TryAppendManifest(new ManifestRow { Entry = updated, Purged = false }, out string manifestError))
                    _index[id] = updated;
                else
                    error = $"restored, but the manifest could not record it ({manifestError})";

                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    /// <summary>
    /// Permanently destroys an entry: deletes the blob and tombstones the manifest row.
    /// Idempotent with respect to a blob that has already vanished — the goal is that
    /// the vault stops claiming to hold something. Returns false (and keeps the entry)
    /// when the blob is present but cannot be deleted, so the operator can retry rather
    /// than lose track of ciphertext that is still on disk.
    /// </summary>
    public bool Purge(string id, out string error)
    {
        error = "";
        if (_disposed) { error = "vault is disposed"; return false; }

        lock (_gate)
        {
            if (string.IsNullOrEmpty(id) || !_index.TryGetValue(id, out var entry))
            {
                error = $"unknown vault id '{id}'";
                return false;
            }

            if (!TryDeleteBlob(id, out string deleteError))
            {
                error = $"blob could not be deleted: {deleteError}";
                return false;
            }

            if (!TryAppendManifest(new ManifestRow { Entry = entry, Purged = true }, out string manifestError))
            {
                // The ciphertext is gone; the index must agree even if the tombstone
                // failed to persist, otherwise this process keeps offering a dead id.
                _index.Remove(id);
                error = $"purged, but the manifest tombstone could not be written ({manifestError}); " +
                        "the entry will reappear as unreachable after a restart";
                return false;
            }

            _index.Remove(id);
            return true;
        }
    }

    /// <summary>
    /// Decrypts an entry in memory and discards it, confirming that the blob is intact,
    /// that the GCM tag verifies against this vault's key, and that the plaintext still
    /// hashes to the recorded SHA-256. Use it for a periodic vault health check or before
    /// promising an analyst that a restore will succeed.
    /// </summary>
    public bool VerifyIntegrity(string id, out string error)
    {
        error = "";
        if (_disposed) { error = "vault is disposed"; return false; }

        lock (_gate)
        {
            if (string.IsNullOrEmpty(id) || !_index.TryGetValue(id, out var entry))
            {
                error = $"unknown vault id '{id}'";
                return false;
            }

            if (!TryDecrypt(entry, out byte[] plaintext, out error)) return false;
            CryptographicOperations.ZeroMemory(plaintext);
            return true;
        }
    }

    /// <summary>
    /// Zeroes the in-memory key. The key FILE is untouched — the vault must stay
    /// readable across restarts — so this only shortens the window in which the key
    /// sits in this process's heap.
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            CryptographicOperations.ZeroMemory(_key);
            _index.Clear();
        }
    }

    // ------------------------------------------------------------------ crypto

    private bool TryWriteBlob(VaultEntry entry, byte[] plaintext, out string error)
    {
        error = "";
        string blobPath = BlobPath(entry.Id);
        string tmpPath = blobPath + ".tmp";
        byte[] blob;

        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            byte[] tag = new byte[TagBytes];
            byte[] ciphertext = new byte[plaintext.Length];

            using (var gcm = new AesGcm(_key, TagBytes))
                gcm.Encrypt(nonce, plaintext, ciphertext, tag, AssociatedData(entry));

            blob = new byte[HeaderBytes + ciphertext.Length];
            Magic.CopyTo(blob, 0);
            nonce.CopyTo(blob, 6);
            tag.CopyTo(blob, 6 + NonceBytes);
            BinaryPrimitives.WriteInt64LittleEndian(
                blob.AsSpan(6 + NonceBytes + TagBytes, LengthBytes), plaintext.LongLength);
            ciphertext.CopyTo(blob, HeaderBytes);
        }
        catch (Exception ex)
        {
            error = $"encryption failed: {ex.GetType().Name}: {ex.Message}";
            return false;
        }

        try
        {
            File.WriteAllBytes(tmpPath, blob);
            File.Move(tmpPath, blobPath, overwrite: false);
            return true;
        }
        catch (Exception ex)
        {
            TryDeleteFile(tmpPath, out _);
            error = $"blob write failed: {ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private bool TryDecrypt(VaultEntry entry, out byte[] plaintext, out string error)
    {
        plaintext = Array.Empty<byte>();
        error = "";
        string blobPath = BlobPath(entry.Id);

        byte[] blob;
        try { blob = File.ReadAllBytes(blobPath); }
        catch (Exception ex) { error = $"blob unreadable: {ex.GetType().Name}: {ex.Message}"; return false; }

        if (blob.Length < HeaderBytes) { error = "blob is truncated (shorter than its header)"; return false; }
        for (int i = 0; i < Magic.Length; i++)
        {
            if (blob[i] != Magic[i]) { error = "blob header magic mismatch (not a PSVLT1 blob)"; return false; }
        }

        long declared = BinaryPrimitives.ReadInt64LittleEndian(blob.AsSpan(6 + NonceBytes + TagBytes, LengthBytes));
        if (declared < 0 || declared > MaxItemBytes) { error = $"blob declares an implausible length ({declared})"; return false; }
        if (blob.LongLength - HeaderBytes != declared) { error = "blob length does not match its header"; return false; }
        if (declared != entry.OriginalSize) { error = "blob length disagrees with the manifest"; return false; }

        var nonce = blob.AsSpan(6, NonceBytes);
        var tag = blob.AsSpan(6 + NonceBytes, TagBytes);
        var ciphertext = blob.AsSpan(HeaderBytes);
        byte[] recovered = new byte[declared];

        try
        {
            using var gcm = new AesGcm(_key, TagBytes);
            gcm.Decrypt(nonce, ciphertext, tag, recovered, AssociatedData(entry));
        }
        catch (AuthenticationTagMismatchException)
        {
            CryptographicOperations.ZeroMemory(recovered);
            error = "authentication tag mismatch: the blob, its header or the manifest metadata has been altered, " +
                    "or it was encrypted under a different vault key";
            return false;
        }
        catch (Exception ex)
        {
            CryptographicOperations.ZeroMemory(recovered);
            error = $"decryption failed: {ex.GetType().Name}: {ex.Message}";
            return false;
        }

        // Defence in depth. GCM already covers the ciphertext and the associated data,
        // but this catches a manifest whose Sha256 was edited to match a swapped blob.
        string actual = Convert.ToHexString(SHA256.HashData(recovered));
        if (!FixedTimeHexEquals(actual, entry.Sha256))
        {
            CryptographicOperations.ZeroMemory(recovered);
            error = "content hash mismatch: recovered bytes do not match the recorded SHA-256";
            return false;
        }

        plaintext = recovered;
        return true;
    }

    /// <summary>
    /// GCM associated data. Binds the ciphertext to this specific entry so a blob file
    /// cannot be swapped for another entry's blob (or replayed under a new id) without
    /// the tag check failing.
    /// </summary>
    private static byte[] AssociatedData(VaultEntry e) => Encoding.UTF8.GetBytes(
        "PSVLT1|" + e.Id + "|" + e.OriginalSize.ToString(CultureInfo.InvariantCulture) + "|" + e.Sha256);

    private static bool FixedTimeHexEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(a), Encoding.ASCII.GetBytes(b));
    }

    // ----------------------------------------------------------------- storage

    private string BlobPath(string id) => Path.Combine(_blobDir, id + BlobExtension);

    /// <summary>
    /// Reads a file while tolerating other openers. FileShare.ReadWrite|Delete matters
    /// here: the file being quarantined is very often still open by the process that
    /// wrote it, and a plain File.ReadAllBytes would fail with a sharing violation.
    /// </summary>
    private static bool TryReadShared(string path, out byte[] data, out string error)
    {
        data = Array.Empty<byte>();
        error = "";
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, bufferSize: 81920, useAsync: false);

            long length = fs.Length;
            if (length > MaxItemBytes)
            {
                error = $"file is {length} bytes, above the {MaxItemBytes}-byte single-item limit";
                return false;
            }

            var buffer = new byte[length];
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = fs.Read(buffer, offset, buffer.Length - offset);
                if (read == 0) break;               // truncated under us; keep what we got
                offset += read;
            }

            data = offset == buffer.Length ? buffer : buffer[..offset];
            return true;
        }
        catch (Exception ex)
        {
            error = $"cannot read source ({ex.GetType().Name}: {ex.Message})";
            return false;
        }
    }

    private bool TryDeleteBlob(string id, out string error)
    {
        error = "";
        string path = BlobPath(id);
        if (!File.Exists(path)) return true;
        return TryDeleteFile(path, out error);
    }

    private static bool TryDeleteFile(string path, out string error)
    {
        error = "";
        try
        {
            if (File.Exists(path)) File.Delete(path);
            return true;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private bool TryAppendManifest(ManifestRow row, out string error)
    {
        error = "";
        try
        {
            File.AppendAllText(_manifestPath, JsonSerializer.Serialize(row, JsonOptions) + Environment.NewLine);
            return true;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Rebuilds the index from the append-only manifest. The LAST row for an id wins,
    /// which is what makes append-only work: a restore or a purge is recorded as a new
    /// row rather than by rewriting history. Unparsable lines (a hand edit, or a torn
    /// final line after a crash) are counted and skipped so one bad line cannot make an
    /// otherwise healthy vault unopenable.
    /// </summary>
    private void LoadManifest()
    {
        if (!File.Exists(_manifestPath)) return;

        long maxSeq = -1;
        foreach (var line in File.ReadLines(_manifestPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            ManifestRow? row;
            try { row = JsonSerializer.Deserialize<ManifestRow>(line, JsonOptions); }
            catch { MalformedManifestLines++; continue; }

            if (row?.Entry is null || string.IsNullOrEmpty(row.Entry.Id)) { MalformedManifestLines++; continue; }

            if (row.Purged) _index.Remove(row.Entry.Id);
            else _index[row.Entry.Id] = row.Entry;

            long seq = ParseSeq(row.Entry.Id);
            if (seq > maxSeq) maxSeq = seq;
        }

        // Continue the sequence past anything already on disk (purged rows included) so
        // a restart cannot mint an id that sorts before, or collides with, an old one.
        _seq = maxSeq + 1;
    }

    // ---------------------------------------------------------------------- ids

    /// <summary>
    /// Ids look like <c>20260810T142233.1234567Z-00000004-9f3a1c2b</c>: a fixed-width
    /// UTC timestamp, a monotonic per-vault sequence, and 4 random bytes.
    ///
    /// Fixed width means ordinal string sort equals chronological order. The sequence
    /// breaks ties when several items are stored inside one clock tick (which is the
    /// norm under a ManualClock and possible under a coarse system clock). The random
    /// suffix is the last line of defence against a collision if two vault instances are
    /// ever pointed at the same directory — an unsupported configuration, but one that
    /// should corrupt nothing when it happens.
    /// </summary>
    private string NextId(DateTime nowUtc)
    {
        for (int attempt = 0; attempt < 64; attempt++)
        {
            string id = string.Concat(
                nowUtc.ToString("yyyyMMdd'T'HHmmss'.'fffffff'Z'", CultureInfo.InvariantCulture),
                "-", _seq.ToString("D8", CultureInfo.InvariantCulture),
                "-", Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant());
            _seq++;
            if (!_index.ContainsKey(id) && !File.Exists(BlobPath(id))) return id;
        }
        // 64 consecutive collisions is not reachable with 32 bits of randomness plus a
        // monotonic counter; fall through to a GUID rather than loop forever.
        return string.Concat(
            nowUtc.ToString("yyyyMMdd'T'HHmmss'.'fffffff'Z'", CultureInfo.InvariantCulture),
            "-", _seq++.ToString("D8", CultureInfo.InvariantCulture),
            "-", Guid.NewGuid().ToString("n")[..8]);
    }

    private static long ParseSeq(string id)
    {
        // "<timestamp>-<seq>-<rand>"; tolerate anything that does not match.
        string[] parts = id.Split('-');
        if (parts.Length < 3) return -1;
        return long.TryParse(parts[^2], NumberStyles.None, CultureInfo.InvariantCulture, out long v) ? v : -1;
    }

    // ---------------------------------------------------------------------- key

    /// <summary>
    /// Reads the vault key, or creates one on first use.
    ///
    /// Creation is first-writer-wins rather than read-then-write: two vault instances
    /// opened on the same directory at the same time would otherwise BOTH see no key,
    /// both generate one, and the second write would destroy the first instance's key —
    /// permanently orphaning anything it had already stored, and surfacing later as a
    /// bogus tamper/authentication failure. The new key is therefore written to a temp
    /// file and moved into place with overwrite:false; if the move loses the race, the
    /// winner's key is re-read and the loser's key is discarded unused.
    /// </summary>
    private static byte[] LoadOrCreateKey(string keyPath)
    {
        if (File.Exists(keyPath)) return ReadKey(keyPath);

        byte[] key = RandomNumberGenerator.GetBytes(32);
        string tmpPath = keyPath + "." +
            Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant() + ".tmp";
        try
        {
            File.WriteAllText(tmpPath, Convert.ToHexString(key));
            File.Move(tmpPath, keyPath, overwrite: false);
            return key;
        }
        catch (IOException) when (File.Exists(keyPath))
        {
            // Someone else got there first. Their key is the one every blob in this
            // directory is encrypted under, so adopt it and throw ours away.
            TryDeleteFile(tmpPath, out _);
            return ReadKey(keyPath);
        }
        catch (Exception ex)
        {
            TryDeleteFile(tmpPath, out _);
            throw new InvalidOperationException(
                $"could not persist the vault key to '{keyPath}' ({ex.Message}); refusing to continue because " +
                "items stored under an unsaved key would be unrecoverable after a restart", ex);
        }
    }

    /// <summary>
    /// Reads and validates an existing key file. Every failure here is fatal on purpose:
    /// silently minting a replacement key would orphan every blob already stored.
    /// </summary>
    private static byte[] ReadKey(string keyPath)
    {
        string hex;
        try { hex = File.ReadAllText(keyPath).Trim(); }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"vault key '{keyPath}' exists but cannot be read ({ex.Message}); refusing to open the vault " +
                "because generating a replacement key would orphan every stored blob", ex);
        }

        if (hex.Length != 64)
            throw new InvalidOperationException(
                $"vault key '{keyPath}' is malformed (expected 64 hex characters, found {hex.Length}); " +
                "refusing to open the vault because generating a replacement key would orphan every stored blob");

        try { return Convert.FromHexString(hex); }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                $"vault key '{keyPath}' is not valid hex; refusing to open the vault because generating a " +
                "replacement key would orphan every stored blob", ex);
        }
    }

    /// <summary>
    /// One manifest line. Kept separate from <see cref="VaultEntry"/> so the public
    /// record stays free of storage bookkeeping and a purge can be expressed as an
    /// append (a tombstone) instead of a rewrite.
    /// </summary>
    private sealed class ManifestRow
    {
        public VaultEntry? Entry { get; set; }
        public bool Purged { get; set; }
    }
}

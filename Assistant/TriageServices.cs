using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using BruceEDR.Api;
using BruceEDR.Security;

namespace BruceEDR.Assistant;

/// <summary>
/// Recorded incidents and cached answers on disk. Incident logs carry command lines and
/// paths, so the folder is restricted to SYSTEM and Administrators (and the creating account
/// when it is not elevated).
///
/// The elevated GUI keeps this under %LOCALAPPDATA%, which non-elevated code of the same user
/// can rearrange. So the folders must not be links and, when this process is privileged,
/// must be owned by SYSTEM or Administrators; every write and delete goes through a handle
/// whose final path is checked (<see cref="SafePaths"/>), so a folder swapped for a junction
/// later turns into a refusal rather than an elevated write or delete somewhere else.
/// </summary>
public sealed class TriageStore
{
    public const int MaxIncidents = 100;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
    private readonly string _incidents;
    private readonly string _answers;
    private readonly object _gate = new();

    public string Root { get; }

    public TriageStore(string root)
    {
        Root = root;
        _incidents = Path.Combine(root, "incidents");
        _answers = Path.Combine(root, "answers");
        bool admin = SafePaths.ProcessIsAdministrative;
        // The analyst's own folders: they own them, so an owner other than SYSTEM, Administrators or
        // the analyst is what is refused.
        SafePaths.RequirePrivateDirectory(root, admin, allowCurrentUserOwner: true);
        SafePaths.RequirePrivateDirectory(_incidents, admin, allowCurrentUserOwner: true);
        SafePaths.RequirePrivateDirectory(_answers, admin, allowCurrentUserOwner: true);
    }

    public IReadOnlyList<IncidentCase> LoadIncidents()
    {
        var list = new List<IncidentCase>();
        lock (_gate)
            foreach (var f in Directory.EnumerateFiles(_incidents, "*.json"))
            {
                try
                {
                    var c = JsonSerializer.Deserialize<IncidentCase>(File.ReadAllText(f), Json);
                    if (c is not null && IncidentCase.IsValidKey(c.Key)) list.Add(c);
                }
                catch (Exception) { }
            }
        return list.OrderByDescending(c => c.UpdatedUtc).ToList();
    }

    public void SaveIncident(IncidentCase c)
    {
        if (!IncidentCase.IsValidKey(c.Key)) throw new ArgumentException("invalid incident key");
        lock (_gate)
        {
            SafePaths.WritePrivateFile(Path.Combine(_incidents, c.Key + ".json"), Encoding.UTF8.GetBytes(JsonSerializer.Serialize(c, Json)));
            Prune();
        }
    }

    public void DeleteIncident(string key)
    {
        if (!IncidentCase.IsValidKey(key)) return;
        lock (_gate)
        {
            TryDelete(Path.Combine(_incidents, key + ".json"));
            foreach (var f in Directory.EnumerateFiles(_answers, key + "--*.json")) TryDelete(f);
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            foreach (var f in Directory.EnumerateFiles(_incidents, "*.json")) TryDelete(f);
            foreach (var f in Directory.EnumerateFiles(_answers, "*.json")) TryDelete(f);
        }
    }

    public TriageAnswer? LoadAnswer(string key, string personaId)
    {
        string? path = AnswerPath(key, personaId);
        if (path is null) return null;
        lock (_gate)
        {
            try { return File.Exists(path) ? JsonSerializer.Deserialize<TriageAnswer>(File.ReadAllText(path), Json) : null; }
            catch (Exception) { return null; }
        }
    }

    public IReadOnlyList<string> AnsweredPersonas(string key)
    {
        if (!IncidentCase.IsValidKey(key)) return Array.Empty<string>();
        lock (_gate)
            return Directory.EnumerateFiles(_answers, key + "--*.json")
                .Select(f => Path.GetFileNameWithoutExtension(f)[(key.Length + 2)..])
                .ToArray();
    }

    public void SaveAnswer(TriageAnswer a)
    {
        string? path = AnswerPath(a.IncidentKey, a.PersonaId) ?? throw new ArgumentException("invalid answer key");
        lock (_gate) SafePaths.WritePrivateFile(path, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(a, Json)));
    }

    private string? AnswerPath(string key, string personaId)
    {
        if (!IncidentCase.IsValidKey(key) || Personas.All.All(p => p.Id != personaId)) return null;
        return Path.Combine(_answers, $"{key}--{personaId}.json");
    }

    private void Prune()
    {
        var files = new DirectoryInfo(_incidents).GetFiles("*.json").OrderByDescending(f => f.LastWriteTimeUtc).ToList();
        foreach (var old in files.Skip(MaxIncidents))
        {
            string key = Path.GetFileNameWithoutExtension(old.Name);
            TryDelete(old.FullName);
            foreach (var f in Directory.EnumerateFiles(_answers, key + "--*.json")) TryDelete(f);
        }
    }

    private static void TryDelete(string path)
    {
        try { SafePaths.DeleteFile(path); } catch (Exception) { }
    }
}

/// <summary>
/// Provider API keys, encrypted with Windows DPAPI for the current account (and an
/// application-specific entropy). DPAPI is the secrecy control: any process of the same user
/// can ask DPAPI to decrypt. The folder's DACL (SYSTEM and Administrators, plus the account
/// when not elevated) keeps other accounts out, and the folder rules of <see cref="TriageStore"/>
/// apply: no links, an administrative owner when privileged, verified writes and deletes.
/// </summary>
public sealed class ApiKeyStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("BruceEDR assistant key v1");
    private readonly string _dir;

    public ApiKeyStore(string dir)
    {
        _dir = dir;
        SafePaths.RequirePrivateDirectory(dir, SafePaths.ProcessIsAdministrative, allowCurrentUserOwner: true);
    }

    private string PathFor(LlmProvider p) => Path.Combine(_dir, p.ToString().ToLowerInvariant() + ".key");

    public bool Has(LlmProvider p) => File.Exists(PathFor(p));

    public void Save(LlmProvider p, string key)
    {
        if (string.IsNullOrWhiteSpace(key)) throw new ArgumentException("empty key");
        byte[] plain = Encoding.UTF8.GetBytes(key.Trim());
        try
        {
            byte[] blob = Dpapi.Protect(plain, Entropy);
            string path = PathFor(p);
            SafePaths.DeleteFile(path);
            SecretFiles.CreateProtected(path, blob);
        }
        finally { Array.Clear(plain); }
    }

    public string? Load(LlmProvider p)
    {
        string path = PathFor(p);
        if (!File.Exists(path)) return null;
        try
        {
            byte[] plain = Dpapi.Unprotect(File.ReadAllBytes(path), Entropy);
            try { return Encoding.UTF8.GetString(plain); }
            finally { Array.Clear(plain); }
        }
        catch (Exception) { return null; }
    }

    public void Delete(LlmProvider p)
    {
        try { SafePaths.DeleteFile(PathFor(p)); } catch (Exception) { }
    }

    private static class Dpapi
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct Blob
        {
            public int Size;
            public IntPtr Data;
        }

        private const int UiForbidden = 0x1;

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptProtectData(ref Blob dataIn, string? description, ref Blob entropy,
            IntPtr reserved, IntPtr prompt, int flags, ref Blob dataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(ref Blob dataIn, IntPtr description, ref Blob entropy,
            IntPtr reserved, IntPtr prompt, int flags, ref Blob dataOut);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr mem);

        public static byte[] Protect(byte[] data, byte[] entropy) => Run(data, entropy, protect: true);
        public static byte[] Unprotect(byte[] data, byte[] entropy) => Run(data, entropy, protect: false);

        private static byte[] Run(byte[] data, byte[] entropy, bool protect)
        {
            var hData = GCHandle.Alloc(data, GCHandleType.Pinned);
            var hEnt = GCHandle.Alloc(entropy, GCHandleType.Pinned);
            var output = new Blob();
            try
            {
                var input = new Blob { Size = data.Length, Data = hData.AddrOfPinnedObject() };
                var ent = new Blob { Size = entropy.Length, Data = hEnt.AddrOfPinnedObject() };
                bool ok = protect
                    ? CryptProtectData(ref input, "BruceEDR", ref ent, IntPtr.Zero, IntPtr.Zero, UiForbidden, ref output)
                    : CryptUnprotectData(ref input, IntPtr.Zero, ref ent, IntPtr.Zero, IntPtr.Zero, UiForbidden, ref output);
                if (!ok) throw new InvalidOperationException("DPAPI failed (" + Marshal.GetLastWin32Error() + ")");
                var result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, output.Size);
                return result;
            }
            finally
            {
                if (output.Data != IntPtr.Zero)
                {
                    for (int i = 0; i < output.Size; i++) Marshal.WriteByte(output.Data, i, 0);
                    LocalFree(output.Data);
                }
                hData.Free();
                hEnt.Free();
            }
        }
    }
}

public sealed record TriageRequest(LlmProvider Provider, string Model, string ApiKey, Persona Persona, IncidentCase Incident, bool Redact);

public sealed record TriageResult(string Text, bool Refused, string StopReason, string Error)
{
    public bool Ok => Error.Length == 0 && !Refused;
}

/// <summary>Produces an explanation. The desktop app's harness substitutes a scripted one.</summary>
public interface ITriageGenerator
{
    Task<TriageResult> GenerateAsync(TriageRequest request, Action<string> onText, CancellationToken ct);
}

/// <summary>Streams an answer from the configured provider through the agent's single HTTP client.</summary>
public sealed class TriageNarrator : ITriageGenerator
{
    private readonly Uri? _baseOverride;
    private readonly ApiSafetyPolicy _policy;

    public TriageNarrator() : this(null, null) { }

    /// <summary>Tests only: a loopback base and a loopback policy.</summary>
    internal TriageNarrator(Uri? baseOverride, ApiSafetyPolicy? policy)
    {
        _baseOverride = baseOverride;
        _policy = policy ?? LlmWire.Policy;
    }

    public async Task<TriageResult> GenerateAsync(TriageRequest r, Action<string> onText, CancellationToken ct)
    {
        LlmRequest request;
        try
        {
            request = LlmWire.Build(r.Provider, r.Model, r.ApiKey, TriagePrompt.System(r.Persona),
                TriagePrompt.User(r.Incident, r.Redact), _baseOverride);
        }
        catch (ArgumentException ex) { return new TriageResult("", false, "", ex.Message); }

        var text = new StringBuilder();
        bool refused = false;
        string stop = "", error = "";
        using var client = new ApiClient(_policy);
        var result = await client.StreamLinesAsync("POST", request.Uri, request.Headers, request.Body, line =>
        {
            var c = LlmWire.ParseLine(r.Provider, line);
            if (c.Text.Length > 0)
            {
                text.Append(c.Text);
                onText(c.Text);
            }
            if (c.Refused) refused = true;
            if (c.StopReason.Length > 0) stop = c.StopReason;
            if (c.Error.Length > 0) { error = c.Error; return false; }
            return !c.Done;
        }, TimeSpan.FromSeconds(180), ct).ConfigureAwait(false);

        if (!result.Ok && error.Length == 0) error = Describe(r.Provider, result);
        return new TriageResult(text.ToString(), refused, stop, error);
    }

    private static string Describe(LlmProvider p, ApiStreamResult r)
    {
        string said = LlmWire.ErrorMessage(r.ErrorBody);
        string who = LlmWire.Vendor(p);
        string head = r.Status switch
        {
            401 or 403 => $"{who} rejected the API key (HTTP {r.Status}).",
            404 => $"{who} does not know that model (HTTP 404). Check the model name in Settings.",
            429 => $"{who} is rate limiting this key or it is out of credit (HTTP 429).",
            >= 500 => $"{who} had a server error (HTTP {r.Status}). Try again shortly.",
            > 0 => $"{who} refused the request (HTTP {r.Status}).",
            _ => $"Could not reach {who}: {r.Error}.",
        };
        return said.Length > 0 ? head + " " + said : head;
    }
}

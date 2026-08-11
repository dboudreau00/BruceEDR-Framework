using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProcessShield.Api;

// ---------------------------------------------------------------------------
// Importers: turn a foreign API description into the ApiCollection contract in
// ApiModels.cs. Four formats are understood (Postman v2.x, OpenAPI 3.x /
// Swagger 2.0, HAR 1.2, curl) plus Postman environment files.
//
// Design notes:
//  * Every importer is total: malformed, hostile or simply unexpected input
//    yields an ImportResult carrying an Error, never an exception. Import runs
//    on whatever a user pasted into the GUI, so throwing is not an option.
//  * Nothing here performs I/O or resolves anything over the network. External
//    "$ref"s are reported as warnings, not fetched — an importer that fetched
//    URLs would be an SSRF primitive in a security tool.
//  * JavaScript in Postman scripts is NEVER executed. Only a couple of literal
//    assertion shapes are pattern-matched; everything else is reported as a
//    skipped statement so the operator knows coverage was lost.
//  * Recursion (folders, $ref graphs, schema examples) is depth-limited so a
//    crafted document cannot exhaust the stack.
// ---------------------------------------------------------------------------

/// <summary>
/// Outcome of an import. Exactly one of <see cref="Collection"/> and
/// <see cref="Error"/> is meaningful: the constructor forces an error string
/// whenever no collection was produced, so callers can never observe a
/// silent "nothing happened" result.
/// </summary>
public sealed record ImportResult(ApiCollection? Collection, IReadOnlyList<string> Warnings, string? Error)
{
    /// <summary>Non-fatal problems: things dropped, guessed at, or not supported.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = Warnings ?? Array.Empty<string>();

    /// <summary>Fatal reason the import produced nothing; null on success.</summary>
    public string? Error { get; init; } =
        Collection is null && string.IsNullOrWhiteSpace(Error) ? "import produced no collection" : Error;

    public bool Ok => Collection is not null;

    internal static ImportResult Fail(string error) => new(null, Array.Empty<string>(), error);

    internal static ImportResult From(ApiCollection collection, List<string> warnings) =>
        new(collection, Dedupe(warnings), null);

    // Importers can hit the same limitation on every one of a hundred requests;
    // collapsing identical messages keeps the warning pane readable.
    private static IReadOnlyList<string> Dedupe(List<string> warnings)
    {
        if (warnings.Count == 0) return Array.Empty<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var outp = new List<string>(warnings.Count);
        foreach (var w in warnings)
            if (seen.Add(w)) outp.Add(w);
        return outp;
    }
}

/// <summary>Readers for the API description formats API Studio can ingest.</summary>
public static class ApiImporters
{
    /// <summary>Folder nesting beyond this is dropped rather than recursed into.</summary>
    internal const int MaxFolderDepth = 24;

    /// <summary>How far a generated JSON example walks into a schema.</summary>
    internal const int MaxExampleDepth = 4;

    private static readonly JsonDocumentOptions DocOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 128
    };

    // A process-lifetime empty object used as the "resolved" value for a $ref we
    // refuse to follow. Intentionally never disposed: it owns 2 bytes.
    private static readonly JsonDocument EmptyDoc = JsonDocument.Parse("{}");
    private static readonly JsonElement EmptyObject = EmptyDoc.RootElement;

    private static readonly HashSet<string> HttpMethods = new(StringComparer.OrdinalIgnoreCase)
        { "get", "put", "post", "delete", "options", "head", "patch", "trace" };

    // ------------------------------------------------------------------ auto

    /// <summary>
    /// Sniffs the format from the content itself rather than the file extension —
    /// people rename these files constantly. <paramref name="sourceName"/> is only
    /// used to name the collection when the document carries no name of its own.
    /// </summary>
    public static ImportResult Auto(string content, string sourceName)
    {
        if (string.IsNullOrWhiteSpace(content))
            return ImportResult.Fail("nothing to import: the input is empty");

        string trimmed = content.TrimStart();
        string label = string.IsNullOrWhiteSpace(sourceName) ? "Imported collection" : sourceName;

        if (trimmed.Length > 0 && trimmed[0] != '{' && trimmed[0] != '[')
        {
            // Not JSON. The only text format we read is a curl command line, and it has
            // to announce itself: curl treats any bare word as a hostname, so without
            // this gate every unrecognised blob would "successfully" import as a request.
            bool looksLikeCurl =
                trimmed.StartsWith("curl", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            if (!looksLikeCurl)
                return ImportResult.Fail("unrecognised format: expected JSON (Postman, OpenAPI or HAR) or a curl command");

            var warnings = new List<string>();
            var request = ParseCurl(content, warnings);
            if (request is null)
                return ImportResult.Fail("unrecognised format: expected JSON (Postman, OpenAPI or HAR) or a curl command");
            var single = new ApiCollection
            {
                Name = label,
                Root = new ApiFolder { Name = label, Requests = new[] { request } }
            };
            return ImportResult.From(single, warnings);
        }

        JsonDocument doc;
        try { doc = JsonDocument.Parse(content, DocOptions); }
        catch (JsonException ex) { return ImportResult.Fail("not valid JSON: " + ex.Message); }

        string kind;
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return ImportResult.Fail("expected a JSON object at the top level");

            if (Jx.Str(root, "_postman_variable_scope").Length > 0 ||
                (Jx.Prop(root, "values", out var vals) && vals.ValueKind == JsonValueKind.Array &&
                 !Jx.Prop(root, "item", out _)))
                return ImportResult.Fail(
                    "this looks like a Postman environment, not a collection: import it with PostmanEnvironments()");

            if (Jx.Prop(root, "item", out var item) && item.ValueKind == JsonValueKind.Array) kind = "postman";
            else if (Jx.Str(root, "openapi").Length > 0 || Jx.Str(root, "swagger").Length > 0) kind = "openapi";
            else if (Jx.Prop(root, "log", out var log) && Jx.Prop(log, "entries", out _)) kind = "har";
            else return ImportResult.Fail(
                "unrecognised JSON: no Postman 'item', no 'openapi'/'swagger' version and no HAR 'log.entries'");
        }

        var result = kind switch
        {
            "postman" => FromPostman(content),
            "openapi" => FromOpenApi(content),
            _ => FromHar(content)
        };

        // Give an unnamed document the caller's label so it is not "Untitled" in the tree.
        if (result.Collection is { } c && string.IsNullOrWhiteSpace(c.Name))
            result = result with { Collection = c with { Name = label, Root = c.Root with { Name = label } } };
        return result;
    }

    // -------------------------------------------------------- shared helpers

    private static void SetVar(Dictionary<string, string> vars, string name, string value)
    {
        if (string.IsNullOrEmpty(name)) return;
        // First non-empty value wins: two operations may document the same path
        // parameter and only one of them supplies an example.
        if (vars.TryGetValue(name, out var existing) && existing.Length > 0) return;
        vars[name] = value;
    }

    private static string NameFromUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return "request";
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return string.IsNullOrEmpty(uri.AbsolutePath) ? "/" : uri.AbsolutePath;
        int q = url.IndexOf('?');
        return q >= 0 ? url[..q] : url;
    }

    // --------------------------------------------------------------- postman

    // Recognises the two literal assertion shapes Postman users write most often.
    // These are matched as TEXT: no JavaScript engine is involved, and anything
    // that is not one of these patterns is reported as skipped rather than guessed at.
    private static readonly Regex PmStatusCall = new(
        @"pm\s*\.\s*response\s*\.\s*to\s*\.\s*have\s*\.\s*status\s*\(\s*(\d{3})\s*\)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex PmTestName = new(
        "pm\\s*\\.\\s*test\\s*\\(\\s*[\"']([^\"']*)[\"']",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    // Braces, the pm.test(...) wrapper and comments carry no assertion, so they are
    // structural noise rather than "logic we failed to import".
    private static readonly Regex PmStructural = new(
        @"^(\}\s*\)?\s*;?|\)\s*;?|\{|function\s*\(\s*\)\s*\{)$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// Reads a Postman Collection v2.1 document. v2.0 quirks are tolerated: a request
    /// may be a bare URL string, headers may be a single "K: V" block, and auth
    /// parameters may be an object instead of an array.
    /// </summary>
    public static ImportResult FromPostman(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return ImportResult.Fail("nothing to import: the input is empty");

        JsonDocument doc;
        try { doc = JsonDocument.Parse(json, DocOptions); }
        catch (JsonException ex) { return ImportResult.Fail("not valid JSON: " + ex.Message); }

        using (doc)
        {
            try
            {
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                    return ImportResult.Fail("expected a JSON object at the top level");
                if (!Jx.Prop(root, "item", out var items) || items.ValueKind != JsonValueKind.Array)
                    return ImportResult.Fail("no 'item' array: this does not look like a Postman collection");

                var warnings = new List<string>();
                string name = "Imported collection";
                string description = "";

                if (Jx.Prop(root, "info", out var info) && info.ValueKind == JsonValueKind.Object)
                {
                    string infoName = Jx.Str(info, "name");
                    if (infoName.Length > 0) name = infoName;
                    description = Jx.Description(info);
                    string schema = Jx.Str(info, "schema");
                    if (schema.Length > 0 &&
                        schema.IndexOf("v2.1", StringComparison.OrdinalIgnoreCase) < 0 &&
                        schema.IndexOf("v2.0", StringComparison.OrdinalIgnoreCase) < 0)
                        warnings.Add($"collection schema '{schema}' is not v2.0/v2.1; it was parsed as v2.1 and fields may be missing");
                }

                var vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var v in Jx.Arr(root, "variable"))
                {
                    string key = Jx.Str(v, "key");
                    if (key.Length == 0) continue;
                    if (Jx.Bool(v, "disabled")) continue;   // Postman treats these as inactive
                    vars[key] = Jx.Str(v, "value");
                }

                var defaults = new List<ApiKeyValue>();
                if (Jx.Prop(root, "_processshield", out var ext) && ext.ValueKind == JsonValueKind.Object)
                    defaults.AddRange(PostmanKeyValues(ext, "defaultHeaders"));

                var rootFolder = PostmanFolder(name, description, items, 0, warnings);
                var collection = new ApiCollection
                {
                    Name = name,
                    Description = description,
                    Root = rootFolder,
                    Auth = PostmanAuth(root, "the collection", warnings),
                    DefaultHeaders = defaults,
                    Variables = vars
                };

                foreach (var ev in Jx.Arr(root, "event"))
                    if (PostmanScriptLines(ev).Any(l => l.Trim().Length > 0))
                    {
                        warnings.Add("collection-level scripts were not imported; ProcessShield never executes JavaScript");
                        break;
                    }

                return ImportResult.From(collection, warnings);
            }
            catch (Exception ex)
            {
                return ImportResult.Fail("could not read the Postman collection: " + ex.Message);
            }
        }
    }

    private static ApiFolder PostmanFolder(string name, string description, JsonElement items, int depth, List<string> warnings)
    {
        if (depth > MaxFolderDepth)
        {
            warnings.Add($"folder '{name}' is nested deeper than {MaxFolderDepth} levels; its contents were not imported");
            return new ApiFolder { Name = name, Description = description };
        }

        var requests = new List<ApiRequest>();
        var folders = new List<ApiFolder>();

        foreach (var item in items.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;
            string itemName = Jx.Str(item, "name");

            if (Jx.Prop(item, "item", out var sub) && sub.ValueKind == JsonValueKind.Array)
                folders.Add(PostmanFolder(itemName, Jx.Description(item), sub, depth + 1, warnings));
            else if (Jx.Prop(item, "request", out var req))
            {
                var parsed = PostmanRequest(itemName, item, req, warnings);
                if (parsed is not null) requests.Add(parsed);
            }
            else
                warnings.Add($"item '{itemName}' has neither 'item' nor 'request' and was skipped");
        }

        return new ApiFolder { Name = name, Description = description, Requests = requests, Folders = folders };
    }

    private static ApiRequest? PostmanRequest(string name, JsonElement item, JsonElement req, List<string> warnings)
    {
        string label = name.Length > 0 ? name : "(unnamed)";
        string method = "GET";
        string url;
        var query = new List<ApiKeyValue>();
        var headers = new List<ApiKeyValue>();
        var body = ApiBody.None;
        var auth = ApiAuth.None;
        string description = "";

        if (req.ValueKind == JsonValueKind.String)
        {
            // v2.0 shorthand: "request": "https://host/path" means GET that URL.
            url = req.GetString() ?? "";
        }
        else if (req.ValueKind == JsonValueKind.Object)
        {
            string m = Jx.Str(req, "method").Trim();
            if (m.Length > 0) method = m.ToUpperInvariant();
            description = Jx.Description(req);
            (url, query) = PostmanUrl(req);
            headers = PostmanKeyValues(req, "header");
            body = PostmanBody(req, headers, label, warnings);
            auth = PostmanAuth(req, "request '" + label + "'", warnings);
        }
        else return null;

        var request = new ApiRequest
        {
            Name = name,
            Method = method,
            Url = url,
            Description = description,
            Headers = headers,
            Query = query,
            Body = body,
            Auth = auth,
            Assertions = PostmanAssertions(item, label, warnings)
        };

        string id = Jx.Str(item, "id");
        return id.Length > 0 ? request with { Id = id } : request;
    }

    private static (string Url, List<ApiKeyValue> Query) PostmanUrl(JsonElement req)
    {
        var query = new List<ApiKeyValue>();
        if (!Jx.Prop(req, "url", out var u)) return ("", query);
        if (u.ValueKind == JsonValueKind.String) return (u.GetString() ?? "", query);
        if (u.ValueKind != JsonValueKind.Object) return ("", query);

        query = PostmanKeyValues(u, "query");

        string raw = Jx.Str(u, "raw");
        if (raw.Length > 0)
        {
            // The raw form repeats the query string. When the structured array is present
            // it is authoritative, so the raw copy is stripped rather than sent twice.
            int qm = raw.IndexOf('?');
            return (query.Count > 0 && qm >= 0 ? raw[..qm] : raw, query);
        }

        var sb = new StringBuilder();
        string protocol = Jx.Str(u, "protocol");
        if (protocol.Length > 0) sb.Append(protocol).Append("://");
        sb.Append(JoinParts(u, "host", "."));
        string port = Jx.Str(u, "port");
        if (port.Length > 0) sb.Append(':').Append(port);
        string path = JoinParts(u, "path", "/");
        if (path.Length > 0)
        {
            if (!path.StartsWith("/", StringComparison.Ordinal)) sb.Append('/');
            sb.Append(path);
        }
        return (sb.ToString(), query);
    }

    private static string JoinParts(JsonElement owner, string name, string separator)
    {
        if (!Jx.Prop(owner, name, out var v)) return "";
        if (v.ValueKind == JsonValueKind.String) return v.GetString() ?? "";
        if (v.ValueKind != JsonValueKind.Array) return "";
        var parts = new List<string>();
        foreach (var e in v.EnumerateArray())
        {
            string? s = e.ValueKind == JsonValueKind.Object ? Jx.Str(e, "value") : Jx.AsString(e);
            if (!string.IsNullOrEmpty(s)) parts.Add(s);
        }
        return string.Join(separator, parts);
    }

    /// <summary>Reads a Postman key/value array (header, query, urlencoded, formdata).</summary>
    private static List<ApiKeyValue> PostmanKeyValues(JsonElement owner, string name)
    {
        var list = new List<ApiKeyValue>();
        if (!Jx.Prop(owner, name, out var v)) return list;

        if (v.ValueKind == JsonValueKind.String)
        {
            // v2.0 sometimes stores headers as one raw block.
            foreach (var line in (v.GetString() ?? "").Split('\n'))
            {
                string t = line.Trim();
                if (t.Length == 0 || t.StartsWith("//", StringComparison.Ordinal)) continue;
                int colon = t.IndexOf(':');
                if (colon <= 0) continue;
                list.Add(new ApiKeyValue { Name = t[..colon].Trim(), Value = t[(colon + 1)..].Trim() });
            }
            return list;
        }

        if (v.ValueKind != JsonValueKind.Array) return list;
        foreach (var e in v.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.Object) continue;
            string key = Jx.Str(e, "key");
            if (key.Length == 0) key = Jx.Str(e, "name");
            if (key.Length == 0) continue;
            string value = Jx.Str(e, "value");
            // formdata file entries carry the path in "src" instead of "value".
            if (value.Length == 0 && string.Equals(Jx.Str(e, "type"), "file", StringComparison.OrdinalIgnoreCase))
                value = JoinParts(e, "src", ",");
            list.Add(new ApiKeyValue
            {
                Name = key,
                Value = value,
                Enabled = !Jx.Bool(e, "disabled"),
                Description = Jx.Description(e)
            });
        }
        return list;
    }

    private static ApiBody PostmanBody(JsonElement req, List<ApiKeyValue> headers, string label, List<string> warnings)
    {
        if (!Jx.Prop(req, "body", out var b) || b.ValueKind != JsonValueKind.Object) return ApiBody.None;
        string mode = Jx.Str(b, "mode").ToLowerInvariant();

        switch (mode)
        {
            case "":
            case "none":
                return ApiBody.None;

            case "urlencoded":
                return new ApiBody { Kind = ApiBodyKind.UrlEncoded, Form = PostmanKeyValues(b, "urlencoded") };

            case "formdata":
                return new ApiBody { Kind = ApiBodyKind.Multipart, Form = PostmanKeyValues(b, "formdata") };

            case "file":
            {
                string src = Jx.Prop(b, "file", out var f) ? Jx.Str(f, "src") : "";
                if (src.Length == 0)
                    warnings.Add($"request '{label}' has a file body with no path; nothing will be sent");
                return new ApiBody { Kind = ApiBodyKind.File, FilePath = src };
            }

            case "graphql":
            {
                // Flattened to the JSON envelope a GraphQL server actually receives.
                string q = Jx.Prop(b, "graphql", out var g) ? Jx.Str(g, "query") : "";
                string variables = "{}";
                if (Jx.Prop(b, "graphql", out var g2) && Jx.Prop(g2, "variables", out var gv))
                    variables = gv.ValueKind == JsonValueKind.String ? (gv.GetString() ?? "{}") : gv.GetRawText();
                if (variables.Trim().Length == 0) variables = "{}";
                warnings.Add($"request '{label}' uses a GraphQL body; it was flattened into the equivalent JSON envelope");
                return ApiBody.Json("{\"query\":" + JsonSerializer.Serialize(q) + ",\"variables\":" + variables + "}");
            }

            case "raw":
            {
                string text = Jx.Str(b, "raw");
                string language = "";
                if (Jx.Prop(b, "options", out var opts) && Jx.Prop(opts, "raw", out var rawOpts))
                    language = Jx.Str(rawOpts, "language").ToLowerInvariant();

                switch (language)
                {
                    case "json": return new ApiBody { Kind = ApiBodyKind.Json, Text = text };
                    case "xml": return new ApiBody { Kind = ApiBodyKind.Raw, Text = text, ContentType = "application/xml" };
                    case "html": return new ApiBody { Kind = ApiBodyKind.Raw, Text = text, ContentType = "text/html" };
                    case "javascript": return new ApiBody { Kind = ApiBodyKind.Raw, Text = text, ContentType = "application/javascript" };
                    case "text": return new ApiBody { Kind = ApiBodyKind.Raw, Text = text };
                }

                // No declared language. Believe an explicit Content-Type header, then
                // fall back to sniffing. An explicit "text" above is respected so a
                // JSON-looking body the user deliberately marked as text stays raw.
                string ct = headers.FirstOrDefault(h =>
                    string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase))?.Value ?? "";
                if (ct.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0)
                    return new ApiBody { Kind = ApiBodyKind.Json, Text = text };
                if (ct.Length > 0)
                    return new ApiBody { Kind = ApiBodyKind.Raw, Text = text, ContentType = ct };
                return LooksLikeJson(text)
                    ? new ApiBody { Kind = ApiBodyKind.Json, Text = text }
                    : new ApiBody { Kind = ApiBodyKind.Raw, Text = text };
            }

            default:
                warnings.Add($"request '{label}' uses body mode '{mode}', which is not supported; the body was dropped");
                return ApiBody.None;
        }
    }

    private static bool LooksLikeJson(string text)
    {
        string t = text.TrimStart();
        if (t.Length == 0 || (t[0] != '{' && t[0] != '[')) return false;
        try { using var _ = JsonDocument.Parse(text, DocOptions); return true; }
        catch (JsonException) { return false; }
    }

    private static ApiAuth PostmanAuth(JsonElement owner, string label, List<string> warnings)
    {
        if (!Jx.Prop(owner, "auth", out var a) || a.ValueKind != JsonValueKind.Object) return ApiAuth.None;
        string type = Jx.Str(a, "type").ToLowerInvariant();
        var p = PostmanAuthParams(a, type);

        switch (type)
        {
            case "":
            case "noauth":
            case "inherit":
                return ApiAuth.None;

            case "basic":
                return new ApiAuth
                {
                    Kind = ApiAuthKind.Basic,
                    Username = p.GetValueOrDefault("username", ""),
                    Password = p.GetValueOrDefault("password", "")
                };

            case "bearer":
                return new ApiAuth { Kind = ApiAuthKind.Bearer, Token = p.GetValueOrDefault("token", "") };

            case "apikey":
            {
                // Postman defaults an unspecified location to the header.
                bool inQuery = string.Equals(p.GetValueOrDefault("in", "header"), "query", StringComparison.OrdinalIgnoreCase);
                return new ApiAuth
                {
                    Kind = inQuery ? ApiAuthKind.ApiKeyQuery : ApiAuthKind.ApiKeyHeader,
                    KeyName = p.GetValueOrDefault("key", ""),
                    KeyValue = p.GetValueOrDefault("value", "")
                };
            }

            default:
                warnings.Add($"auth type '{type}' on {label} is not supported and was dropped; the request will send no credentials");
                return ApiAuth.None;
        }
    }

    private static Dictionary<string, string> PostmanAuthParams(JsonElement auth, string type)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (type.Length == 0 || !Jx.Prop(auth, type, out var node)) return d;

        if (node.ValueKind == JsonValueKind.Array)
        {
            foreach (var e in node.EnumerateArray())
            {
                string k = Jx.Str(e, "key");
                if (k.Length > 0) d[k] = Jx.Str(e, "value");
            }
        }
        else if (node.ValueKind == JsonValueKind.Object)
        {
            // v2.0 stored the parameters as a plain object.
            foreach (var prop in node.EnumerateObject())
            {
                string? s = Jx.AsString(prop.Value);
                if (s is not null) d[prop.Name] = s;
            }
        }
        return d;
    }

    private static IEnumerable<string> PostmanScriptLines(JsonElement ev)
    {
        if (!Jx.Prop(ev, "script", out var script)) yield break;
        if (!Jx.Prop(script, "exec", out var exec))
        {
            string src = Jx.Str(script, "src");
            if (src.Length > 0) yield return src;
            yield break;
        }
        if (exec.ValueKind == JsonValueKind.String)
        {
            foreach (var l in (exec.GetString() ?? "").Split('\n')) yield return l;
            yield break;
        }
        if (exec.ValueKind != JsonValueKind.Array) yield break;
        foreach (var l in exec.EnumerateArray())
            yield return l.ValueKind == JsonValueKind.String ? (l.GetString() ?? "") : "";
    }

    private static IReadOnlyList<ApiAssertion> PostmanAssertions(JsonElement item, string label, List<string> warnings)
    {
        var found = new List<ApiAssertion>();

        foreach (var ev in Jx.Arr(item, "event"))
        {
            string listen = Jx.Str(ev, "listen").ToLowerInvariant();
            var lines = PostmanScriptLines(ev).ToList();

            if (listen != "test")
            {
                if (listen.Length > 0 && lines.Any(l => l.Trim().Length > 0))
                    warnings.Add($"'{listen}' script on request '{label}' was not imported; ProcessShield never executes JavaScript");
                continue;
            }

            int skipped = 0;
            string pendingName = "";
            foreach (var raw in lines)
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal)) continue;

                var nameMatch = PmTestName.Match(line);
                if (nameMatch.Success) pendingName = nameMatch.Groups[1].Value;

                // Status calls are matched first so a whole pm.test(...) written on one
                // line still yields its assertion instead of being treated as wrapper noise.
                var statuses = PmStatusCall.Matches(line);
                if (statuses.Count > 0)
                {
                    foreach (Match m in statuses)
                        if (int.TryParse(m.Groups[1].Value, out int code))
                            found.Add(new ApiAssertion
                            {
                                Kind = AssertionKind.StatusEquals,
                                Expected = code.ToString(),
                                Name = pendingName
                            });
                    pendingName = "";
                    continue;
                }

                if (nameMatch.Success || PmStructural.IsMatch(line)) continue;
                skipped++;
            }

            if (skipped > 0)
                warnings.Add($"test script on request '{label}' contains {skipped} statement(s) that were not imported; ProcessShield never executes JavaScript, so only literal pm.response.to.have.status(N) checks are recognised");
        }

        return found;
    }

    /// <summary>
    /// Reads a Postman environment export (or an array of them). Values whose Postman
    /// type is "secret", and values whose name matches a conservative credential
    /// pattern, are listed in <see cref="ApiEnvironment.Secrets"/> so reports mask
    /// them even when the exporting user never labelled them.
    /// </summary>
    public static IReadOnlyList<ApiEnvironment> PostmanEnvironments(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Array.Empty<ApiEnvironment>();

        JsonDocument doc;
        try { doc = JsonDocument.Parse(json, DocOptions); }
        catch (JsonException) { return Array.Empty<ApiEnvironment>(); }

        using (doc)
        {
            var results = new List<ApiEnvironment>();
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var e in root.EnumerateArray())
                {
                    var env = ReadEnvironment(e);
                    if (env is not null) results.Add(env);
                }
            }
            else
            {
                var env = ReadEnvironment(root);
                if (env is not null) results.Add(env);
            }
            return results;
        }
    }

    private static readonly string[] SecretNameHints =
    {
        "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "api-key",
        "authorization", "bearer", "credential", "private_key", "client_secret", "access_key", "session"
    };

    private static bool LooksSecret(string name) =>
        SecretNameHints.Any(h => name.IndexOf(h, StringComparison.OrdinalIgnoreCase) >= 0);

    private static ApiEnvironment? ReadEnvironment(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.Object) return null;
        if (!Jx.Prop(e, "values", out var values) || values.ValueKind != JsonValueKind.Array) return null;

        var vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var secrets = new List<string>();

        foreach (var v in values.EnumerateArray())
        {
            if (v.ValueKind != JsonValueKind.Object) continue;
            string key = Jx.Str(v, "key");
            if (key.Length == 0) continue;
            // "enabled" is absent on many exports; only an explicit false disables.
            if (Jx.Prop(v, "enabled", out var en) && en.ValueKind == JsonValueKind.False) continue;

            vars[key] = Jx.Str(v, "value");
            if (string.Equals(Jx.Str(v, "type"), "secret", StringComparison.OrdinalIgnoreCase) || LooksSecret(key))
                if (!secrets.Contains(key, StringComparer.OrdinalIgnoreCase))
                    secrets.Add(key);
        }

        string name = Jx.Str(e, "name");
        return new ApiEnvironment
        {
            Name = name.Length > 0 ? name : "default",
            Variables = vars,
            Secrets = secrets
        };
    }

    // --------------------------------------------------------------- openapi

    private static readonly Regex BracedParam = new(@"\{([^{}/]+)\}",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex SuccessCode = new(@"^2\d\d$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// Reads an OpenAPI 3.0/3.1 or Swagger 2.0 document. JSON only — YAML would need a
    /// third-party parser and this project takes no extra dependencies. One request is
    /// produced per path+operation, grouped into folders by the operation's first tag.
    /// </summary>
    public static ImportResult FromOpenApi(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return ImportResult.Fail("nothing to import: the input is empty");

        JsonDocument doc;
        try { doc = JsonDocument.Parse(json, DocOptions); }
        catch (JsonException ex) { return ImportResult.Fail("not valid JSON: " + ex.Message); }

        using (doc)
        {
            try
            {
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                    return ImportResult.Fail("expected a JSON object at the top level");

                bool v3 = Jx.Str(root, "openapi").StartsWith("3", StringComparison.Ordinal);
                bool v2 = !v3 && Jx.Str(root, "swagger").StartsWith("2", StringComparison.Ordinal);
                if (!v3 && !v2)
                    return ImportResult.Fail(
                        "no 'openapi: 3.x' or 'swagger: 2.0' field: this does not look like an OpenAPI document (YAML is not supported, convert to JSON first)");

                if (!Jx.Prop(root, "paths", out var paths) || paths.ValueKind != JsonValueKind.Object)
                    return ImportResult.Fail("no 'paths' object: there is nothing to import");

                var warnings = new List<string>();
                var vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                string title = "OpenAPI import";
                string description = "";
                if (Jx.Prop(root, "info", out var info) && info.ValueKind == JsonValueKind.Object)
                {
                    string t = Jx.Str(info, "title");
                    if (t.Length > 0) title = t;
                    description = Jx.Description(info);
                }

                string baseUrl = v3 ? Oas3Server(root, vars, warnings) : Swagger2Server(root, vars, warnings);

                var groups = new List<(string Name, List<ApiRequest> Items)>();
                foreach (var pathProp in paths.EnumerateObject())
                {
                    string rawPath = pathProp.Name;
                    if (!rawPath.StartsWith("/", StringComparison.Ordinal)) continue;   // x- extensions
                    var pathItem = Deref(root, pathProp.Value, warnings);
                    if (pathItem.ValueKind != JsonValueKind.Object) continue;

                    foreach (var opProp in pathItem.EnumerateObject())
                    {
                        if (!HttpMethods.Contains(opProp.Name)) continue;
                        if (opProp.Value.ValueKind != JsonValueKind.Object) continue;

                        var request = OpenApiOperation(root, v3, baseUrl, rawPath, opProp.Name,
                                                       pathItem, opProp.Value, vars, warnings);

                        string group = FirstTag(opProp.Value) ?? FirstSegment(rawPath);
                        int idx = groups.FindIndex(g => string.Equals(g.Name, group, StringComparison.Ordinal));
                        if (idx < 0) { groups.Add((group, new List<ApiRequest> { request })); }
                        else groups[idx].Items.Add(request);
                    }
                }

                if (groups.Count == 0)
                    warnings.Add("the document declares no operations; the imported collection is empty");

                var collection = new ApiCollection
                {
                    Name = title,
                    Description = description,
                    Root = new ApiFolder
                    {
                        Name = title,
                        Folders = groups.Select(g => new ApiFolder { Name = g.Name, Requests = g.Items }).ToList()
                    },
                    Variables = vars
                };
                return ImportResult.From(collection, warnings);
            }
            catch (Exception ex)
            {
                return ImportResult.Fail("could not read the OpenAPI document: " + ex.Message);
            }
        }
    }

    /// <summary>Braced OpenAPI path/server parameters become ProcessShield template variables.</summary>
    private static string Templatize(string s) => BracedParam.Replace(s, "{{$1}}");

    private static string Oas3Server(JsonElement root, Dictionary<string, string> vars, List<string> warnings)
    {
        foreach (var s in Jx.Arr(root, "servers"))
        {
            string url = Jx.Str(s, "url");
            if (url.Length == 0) continue;
            if (Jx.Prop(s, "variables", out var sv) && sv.ValueKind == JsonValueKind.Object)
                foreach (var p in sv.EnumerateObject())
                    SetVar(vars, p.Name, Jx.Str(p.Value, "default"));
            return Templatize(url).TrimEnd('/');
        }
        warnings.Add("no 'servers' entry: request URLs were prefixed with a {{baseUrl}} variable you must fill in");
        SetVar(vars, "baseUrl", "");
        return "{{baseUrl}}";
    }

    private static string Swagger2Server(JsonElement root, Dictionary<string, string> vars, List<string> warnings)
    {
        string host = Jx.Str(root, "host");
        string basePath = Jx.Str(root, "basePath").TrimEnd('/');
        string scheme = "https";
        foreach (var s in Jx.Arr(root, "schemes"))
        {
            string v = Jx.AsString(s) ?? "";
            // Prefer https when the document offers it; only fall back to http when it does not.
            if (string.Equals(v, "https", StringComparison.OrdinalIgnoreCase)) { scheme = "https"; break; }
            if (v.Length > 0) scheme = v.ToLowerInvariant();
        }
        if (host.Length == 0)
        {
            warnings.Add("no 'host' field: request URLs were prefixed with a {{baseUrl}} variable you must fill in");
            SetVar(vars, "baseUrl", "");
            return "{{baseUrl}}" + Templatize(basePath);
        }
        return (scheme + "://" + host + Templatize(basePath)).TrimEnd('/');
    }

    private static string? FirstTag(JsonElement op)
    {
        foreach (var t in Jx.Arr(op, "tags"))
        {
            string s = Jx.AsString(t) ?? "";
            if (s.Trim().Length > 0) return s.Trim();
        }
        return null;
    }

    private static string FirstSegment(string path)
    {
        string p = path.Trim('/');
        int slash = p.IndexOf('/');
        if (slash >= 0) p = p[..slash];
        p = p.Replace("{", "").Replace("}", "").Trim();
        return p.Length == 0 ? "root" : p;
    }

    private static ApiRequest OpenApiOperation(
        JsonElement root, bool v3, string baseUrl, string rawPath, string methodKey,
        JsonElement pathItem, JsonElement op, Dictionary<string, string> vars, List<string> warnings)
    {
        string method = methodKey.ToUpperInvariant();
        string name = Jx.Str(op, "summary");
        if (name.Length == 0) name = Jx.Str(op, "operationId");
        if (name.Length == 0) name = method + " " + rawPath;

        var headers = new List<ApiKeyValue>();
        var query = new List<ApiKeyValue>();
        var formData = new List<ApiKeyValue>();
        var body = ApiBody.None;

        // Path-item parameters apply to every operation; an operation parameter with the
        // same (name, in) pair overrides the inherited one in place, preserving order.
        var merged = new List<(string Key, JsonElement El)>();
        void AddParam(JsonElement p)
        {
            var d = Deref(root, p, warnings);
            if (d.ValueKind != JsonValueKind.Object) return;
            string key = Jx.Str(d, "in").ToLowerInvariant() + " " + Jx.Str(d, "name");
            int i = merged.FindIndex(x => string.Equals(x.Key, key, StringComparison.Ordinal));
            if (i >= 0) merged[i] = (key, d); else merged.Add((key, d));
        }
        foreach (var p in Jx.Arr(pathItem, "parameters")) AddParam(p);
        foreach (var p in Jx.Arr(op, "parameters")) AddParam(p);

        foreach (var (_, p) in merged)
        {
            string pin = Jx.Str(p, "in").ToLowerInvariant();
            string pname = Jx.Str(p, "name");
            if (pname.Length == 0) continue;
            bool required = Jx.Bool(p, "required");
            string value = ParamExample(root, p, warnings);
            string pdesc = Jx.Description(p);

            switch (pin)
            {
                // Optional parameters are imported disabled: they are documented, so the
                // operator can see and toggle them, but they are not sent by default.
                case "query":
                    query.Add(new ApiKeyValue { Name = pname, Value = value, Enabled = required, Description = pdesc });
                    break;
                case "header":
                    headers.Add(new ApiKeyValue { Name = pname, Value = value, Enabled = required, Description = pdesc });
                    break;
                case "path":
                    SetVar(vars, pname, value);
                    break;
                case "formdata":
                    formData.Add(new ApiKeyValue { Name = pname, Value = value, Enabled = required, Description = pdesc });
                    break;
                case "body":
                    if (Jx.Prop(p, "schema", out var bodySchema))
                        body = ApiBody.Json(ExampleJson(root, bodySchema, warnings));
                    break;
                case "cookie":
                    warnings.Add($"cookie parameter '{pname}' on {method} {rawPath} was not imported");
                    break;
            }
        }

        if (formData.Count > 0 && body.Kind == ApiBodyKind.None)
        {
            bool multipart = Jx.Arr(op, "consumes").Concat(Jx.Arr(root, "consumes"))
                .Any(c => (Jx.AsString(c) ?? "").IndexOf("multipart", StringComparison.OrdinalIgnoreCase) >= 0);
            body = new ApiBody { Kind = multipart ? ApiBodyKind.Multipart : ApiBodyKind.UrlEncoded, Form = formData };
        }

        if (v3 && body.Kind == ApiBodyKind.None && Jx.Prop(op, "requestBody", out var rb))
            body = Oas3Body(root, Deref(root, rb, warnings), warnings);

        var assertions = new List<ApiAssertion>();
        if (Jx.Prop(op, "responses", out var responses) && responses.ValueKind == JsonValueKind.Object)
        {
            var success = responses.EnumerateObject()
                .Select(r => r.Name)
                .Where(k => SuccessCode.IsMatch(k))
                .ToList();
            // Only assert when the contract is unambiguous. Two documented 2xx codes mean
            // either could be correct, and a wrong assertion is worse than none.
            if (success.Count == 1 && int.TryParse(success[0], out int code))
                assertions.Add(ApiAssertion.Status(code));
        }

        return new ApiRequest
        {
            Name = name,
            Method = method,
            Url = baseUrl + Templatize(rawPath),
            Description = Jx.Description(op),
            Headers = headers,
            Query = query,
            Body = body,
            Auth = OpenApiAuth(root, v3, op, vars, warnings),
            Assertions = assertions
        };
    }

    private static ApiBody Oas3Body(JsonElement root, JsonElement requestBody, List<string> warnings)
    {
        if (requestBody.ValueKind != JsonValueKind.Object) return ApiBody.None;
        if (!Jx.Prop(requestBody, "content", out var content) || content.ValueKind != JsonValueKind.Object)
            return ApiBody.None;

        string chosen = "";
        JsonElement media = default;
        foreach (var m in content.EnumerateObject())
        {
            if (chosen.Length == 0) { chosen = m.Name; media = m.Value; }
            if (m.Name.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                chosen = m.Name; media = m.Value;
                break;   // JSON is preferred whenever it is offered
            }
        }
        if (chosen.Length == 0) return ApiBody.None;

        string explicitExample = MediaExample(media);

        if (chosen.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            if (explicitExample.Length > 0) return ApiBody.Json(explicitExample);
            return Jx.Prop(media, "schema", out var schema)
                ? ApiBody.Json(ExampleJson(root, schema, warnings))
                : ApiBody.Json("{}");
        }

        if (chosen.IndexOf("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) >= 0 ||
            chosen.IndexOf("multipart/form-data", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            var form = new List<ApiKeyValue>();
            if (Jx.Prop(media, "schema", out var schema))
            {
                var s = Deref(root, schema, warnings);
                var required = new HashSet<string>(
                    Jx.Arr(s, "required").Select(r => Jx.AsString(r) ?? "").Where(r => r.Length > 0),
                    StringComparer.Ordinal);
                if (Jx.Prop(s, "properties", out var props) && props.ValueKind == JsonValueKind.Object)
                    foreach (var p in props.EnumerateObject())
                        form.Add(new ApiKeyValue
                        {
                            Name = p.Name,
                            Value = ScalarPlaceholder(Deref(root, p.Value, warnings)),
                            Enabled = required.Count == 0 || required.Contains(p.Name)
                        });
            }
            bool multipart = chosen.IndexOf("multipart", StringComparison.OrdinalIgnoreCase) >= 0;
            return new ApiBody { Kind = multipart ? ApiBodyKind.Multipart : ApiBodyKind.UrlEncoded, Form = form };
        }

        return new ApiBody { Kind = ApiBodyKind.Raw, Text = explicitExample, ContentType = chosen };
    }

    private static string MediaExample(JsonElement media)
    {
        if (media.ValueKind != JsonValueKind.Object) return "";
        if (Jx.Prop(media, "example", out var ex))
            return ex.ValueKind == JsonValueKind.String ? (ex.GetString() ?? "") : ex.GetRawText();
        if (Jx.Prop(media, "examples", out var exs) && exs.ValueKind == JsonValueKind.Object)
            foreach (var e in exs.EnumerateObject())
                if (Jx.Prop(e.Value, "value", out var v))
                    return v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "") : v.GetRawText();
        return "";
    }

    private static string ParamExample(JsonElement root, JsonElement p, List<string> warnings)
    {
        if (Jx.Prop(p, "example", out var ex)) return Jx.AsString(ex) ?? ex.GetRawText();
        if (Jx.Prop(p, "schema", out var s))
        {
            var sd = Deref(root, s, warnings);
            if (Jx.Prop(sd, "example", out var se)) return Jx.AsString(se) ?? se.GetRawText();
            if (Jx.Prop(sd, "default", out var sdf)) return Jx.AsString(sdf) ?? sdf.GetRawText();
            foreach (var e in Jx.Arr(sd, "enum")) return Jx.AsString(e) ?? "";
        }
        // Swagger 2.0 puts type/default/enum directly on the parameter object.
        if (Jx.Prop(p, "default", out var df)) return Jx.AsString(df) ?? df.GetRawText();
        foreach (var e in Jx.Arr(p, "enum")) return Jx.AsString(e) ?? "";
        return "";
    }

    private static ApiAuth OpenApiAuth(JsonElement root, bool v3, JsonElement op,
                                       Dictionary<string, string> vars, List<string> warnings)
    {
        JsonElement sec;
        bool have = Jx.Prop(op, "security", out sec) && sec.ValueKind == JsonValueKind.Array;
        if (!have) have = Jx.Prop(root, "security", out sec) && sec.ValueKind == JsonValueKind.Array;
        if (!have || sec.GetArrayLength() == 0) return ApiAuth.None;

        var first = sec[0];
        if (first.ValueKind != JsonValueKind.Object) return ApiAuth.None;
        string schemeName = "";
        foreach (var p in first.EnumerateObject()) { schemeName = p.Name; break; }
        if (schemeName.Length == 0) return ApiAuth.None;   // {} means "no auth required here"

        JsonElement defs;
        if (v3)
        {
            if (!Jx.Prop(root, "components", out var comp) ||
                !Jx.Prop(comp, "securitySchemes", out defs)) return ApiAuth.None;
        }
        else if (!Jx.Prop(root, "securityDefinitions", out defs)) return ApiAuth.None;

        if (!Jx.Prop(defs, schemeName, out var schemeRaw)) return ApiAuth.None;
        var scheme = Deref(root, schemeRaw, warnings);

        // Credentials are never invented: each kind gets a template variable the operator
        // fills in, so an imported collection carries no secret material at all.
        switch (Jx.Str(scheme, "type").ToLowerInvariant())
        {
            case "basic":
                SetVar(vars, "username", "");
                SetVar(vars, "password", "");
                return new ApiAuth { Kind = ApiAuthKind.Basic, Username = "{{username}}", Password = "{{password}}" };

            case "http":
            {
                string s = Jx.Str(scheme, "scheme").ToLowerInvariant();
                if (s == "basic")
                {
                    SetVar(vars, "username", "");
                    SetVar(vars, "password", "");
                    return new ApiAuth { Kind = ApiAuthKind.Basic, Username = "{{username}}", Password = "{{password}}" };
                }
                if (s == "bearer")
                {
                    SetVar(vars, "token", "");
                    return new ApiAuth { Kind = ApiAuthKind.Bearer, Token = "{{token}}" };
                }
                warnings.Add($"http security scheme '{s}' on '{schemeName}' is not supported; the request carries no credentials");
                return ApiAuth.None;
            }

            case "apikey":
            {
                SetVar(vars, "apiKey", "");
                bool inQuery = string.Equals(Jx.Str(scheme, "in"), "query", StringComparison.OrdinalIgnoreCase);
                return new ApiAuth
                {
                    Kind = inQuery ? ApiAuthKind.ApiKeyQuery : ApiAuthKind.ApiKeyHeader,
                    KeyName = Jx.Str(scheme, "name"),
                    KeyValue = "{{apiKey}}"
                };
            }

            case "oauth2":
            case "openidconnect":
                SetVar(vars, "token", "");
                warnings.Add($"security scheme '{schemeName}' needs an OAuth flow, which ProcessShield does not perform; the request sends a bearer {{{{token}}}} you must obtain yourself");
                return new ApiAuth { Kind = ApiAuthKind.Bearer, Token = "{{token}}" };

            default:
                return ApiAuth.None;
        }
    }

    // ------------------------------------------------ $ref and example bodies

    private static JsonElement Deref(JsonElement root, JsonElement node, List<string> warnings)
    {
        int hops = 0;
        while (node.ValueKind == JsonValueKind.Object &&
               Jx.Prop(node, "$ref", out var r) && r.ValueKind == JsonValueKind.String)
        {
            if (++hops > 16)
            {
                warnings.Add("a $ref chain was longer than 16 hops or circular; that part of the document was ignored");
                return EmptyObject;
            }
            string pointer = r.GetString() ?? "";
            if (!pointer.StartsWith("#", StringComparison.Ordinal))
            {
                // Fetching an external document would make the importer an SSRF primitive.
                warnings.Add($"external $ref '{pointer}' was not fetched; that schema was treated as empty");
                return EmptyObject;
            }
            if (!TryPointer(root, pointer[1..], out var target))
            {
                warnings.Add($"$ref '{pointer}' does not resolve inside this document");
                return EmptyObject;
            }
            node = target;
        }
        return node;
    }

    private static bool TryPointer(JsonElement root, string pointer, out JsonElement target)
    {
        var current = root;
        foreach (var segment in pointer.Split('/'))
        {
            if (segment.Length == 0) continue;
            string name = Uri.UnescapeDataString(segment).Replace("~1", "/").Replace("~0", "~");
            if (current.ValueKind == JsonValueKind.Array && int.TryParse(name, out int idx))
            {
                if (idx < 0 || idx >= current.GetArrayLength()) { target = EmptyObject; return false; }
                current = current[idx];
                continue;
            }
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(name, out var next))
            {
                target = EmptyObject;
                return false;
            }
            current = next;
        }
        target = current;
        return true;
    }

    /// <summary>Renders a schema as an indented JSON example with placeholder values.</summary>
    private static string ExampleJson(JsonElement root, JsonElement schema, List<string> warnings)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            WriteExample(root, schema, w, 0, new HashSet<string>(StringComparer.Ordinal), warnings);
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WriteExample(JsonElement root, JsonElement schema, Utf8JsonWriter w,
                                     int depth, HashSet<string> seen, List<string> warnings)
    {
        if (schema.ValueKind != JsonValueKind.Object) { w.WriteStartObject(); w.WriteEndObject(); return; }

        // Cycle guard: a schema that references itself (Node.children -> Node) would
        // otherwise recurse forever. The second visit renders as an empty object.
        if (Jx.Prop(schema, "$ref", out var refNode) && refNode.ValueKind == JsonValueKind.String)
        {
            string pointer = refNode.GetString() ?? "";
            if (!seen.Add(pointer)) { w.WriteStartObject(); w.WriteEndObject(); return; }
            WriteExample(root, Deref(root, schema, warnings), w, depth, seen, warnings);
            seen.Remove(pointer);
            return;
        }

        if (Jx.Prop(schema, "example", out var example)) { example.WriteTo(w); return; }
        if (Jx.Prop(schema, "default", out var dflt)) { dflt.WriteTo(w); return; }
        foreach (var e in Jx.Arr(schema, "enum")) { e.WriteTo(w); return; }

        if (Jx.Prop(schema, "allOf", out var allOf) && allOf.ValueKind == JsonValueKind.Array)
        {
            w.WriteStartObject();
            if (depth < MaxExampleDepth)
            {
                var written = new HashSet<string>(StringComparer.Ordinal);
                foreach (var branch in allOf.EnumerateArray())
                {
                    string? pointer = null;
                    var target = branch;
                    if (Jx.Prop(branch, "$ref", out var br) && br.ValueKind == JsonValueKind.String)
                    {
                        pointer = br.GetString();
                        if (pointer is not null && !seen.Add(pointer)) continue;
                        target = Deref(root, branch, warnings);
                    }
                    if (Jx.Prop(target, "properties", out var props) && props.ValueKind == JsonValueKind.Object)
                        foreach (var p in props.EnumerateObject())
                        {
                            if (!written.Add(p.Name)) continue;
                            w.WritePropertyName(p.Name);
                            WriteExample(root, p.Value, w, depth + 1, seen, warnings);
                        }
                    if (pointer is not null) seen.Remove(pointer);
                }
            }
            w.WriteEndObject();
            return;
        }

        // oneOf/anyOf: the first branch is the only defensible deterministic choice.
        foreach (var key in new[] { "oneOf", "anyOf" })
            if (Jx.Prop(schema, key, out var union) && union.ValueKind == JsonValueKind.Array && union.GetArrayLength() > 0)
            {
                WriteExample(root, union[0], w, depth, seen, warnings);
                return;
            }

        string type = Jx.Str(schema, "type").ToLowerInvariant();
        bool hasProps = Jx.Prop(schema, "properties", out var properties) &&
                        properties.ValueKind == JsonValueKind.Object;
        if (type.Length == 0 && hasProps) type = "object";

        switch (type)
        {
            case "object":
                w.WriteStartObject();
                if (hasProps && depth < MaxExampleDepth)
                    foreach (var p in properties.EnumerateObject())
                    {
                        w.WritePropertyName(p.Name);
                        WriteExample(root, p.Value, w, depth + 1, seen, warnings);
                    }
                w.WriteEndObject();
                return;

            case "array":
                w.WriteStartArray();
                if (Jx.Prop(schema, "items", out var items) && depth < MaxExampleDepth)
                    WriteExample(root, items, w, depth + 1, seen, warnings);
                w.WriteEndArray();
                return;

            case "integer":
            case "number":
                w.WriteNumberValue(0);
                return;

            case "boolean":
                w.WriteBooleanValue(false);
                return;

            case "null":
                w.WriteNullValue();
                return;

            case "string":
                w.WriteStringValue(StringPlaceholder(schema));
                return;

            default:
                // Untyped schema (common in loosely written documents): an empty string is
                // the least surprising placeholder and never looks like real data.
                w.WriteStringValue("");
                return;
        }
    }

    private static string ScalarPlaceholder(JsonElement schema)
    {
        if (Jx.Prop(schema, "example", out var ex)) return Jx.AsString(ex) ?? "";
        if (Jx.Prop(schema, "default", out var df)) return Jx.AsString(df) ?? "";
        return Jx.Str(schema, "type").ToLowerInvariant() switch
        {
            "integer" or "number" => "0",
            "boolean" => "false",
            "string" => StringPlaceholder(schema),
            _ => ""
        };
    }

    private static string StringPlaceholder(JsonElement schema) =>
        Jx.Str(schema, "format").ToLowerInvariant() switch
        {
            "date-time" => "1970-01-01T00:00:00Z",
            "date" => "1970-01-01",
            "time" => "00:00:00",
            "uuid" => "00000000-0000-0000-0000-000000000000",
            "email" => "user@example.com",
            "uri" or "url" => "https://example.com",
            "hostname" => "example.com",
            "ipv4" => "127.0.0.1",
            "ipv6" => "::1",
            // Never fabricate something that looks like a credential or a file.
            "password" or "byte" or "binary" => "",
            _ => "string"
        };

    // ------------------------------------------------------------------- har

    /// <summary>
    /// Reads an HTTP Archive 1.2 export (browser devtools "Save all as HAR").
    /// One request per entry, grouped into a folder per host. Responses in the archive
    /// are ignored: this produces something to replay, not a recording to inspect.
    /// </summary>
    public static ImportResult FromHar(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return ImportResult.Fail("nothing to import: the input is empty");

        JsonDocument doc;
        try { doc = JsonDocument.Parse(json, DocOptions); }
        catch (JsonException ex) { return ImportResult.Fail("not valid JSON: " + ex.Message); }

        using (doc)
        {
            try
            {
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                    return ImportResult.Fail("expected a JSON object at the top level");
                if (!Jx.Prop(root, "log", out var log) || log.ValueKind != JsonValueKind.Object)
                    return ImportResult.Fail("no 'log' object: this does not look like a HAR file");
                if (!Jx.Prop(log, "entries", out var entries) || entries.ValueKind != JsonValueKind.Array)
                    return ImportResult.Fail("no 'log.entries' array: this does not look like a HAR file");

                var warnings = new List<string>();
                var groups = new List<(string Host, List<ApiRequest> Items)>();
                bool sawCredentials = false;

                foreach (var entry in entries.EnumerateArray())
                {
                    if (entry.ValueKind != JsonValueKind.Object) continue;
                    if (!Jx.Prop(entry, "request", out var req) || req.ValueKind != JsonValueKind.Object) continue;

                    string url = Jx.Str(req, "url");
                    if (url.Length == 0) continue;
                    string method = Jx.Str(req, "method").Trim();
                    if (method.Length == 0) method = "GET";

                    var headers = new List<ApiKeyValue>();
                    foreach (var h in Jx.Arr(req, "headers"))
                    {
                        string hn = Jx.Str(h, "name");
                        // HTTP/2 pseudo-headers (:method, :authority, ...) are protocol
                        // framing, not headers; sending them would be rejected.
                        if (hn.Length == 0 || hn[0] == ':') continue;
                        if (LooksSecret(hn)) sawCredentials = true;
                        headers.Add(new ApiKeyValue { Name = hn, Value = Jx.Str(h, "value") });
                    }

                    string host = "unknown";
                    if (Uri.TryCreate(url, UriKind.Absolute, out var uri)) host = uri.Host;

                    var request = new ApiRequest
                    {
                        // The URL already carries its query string, so query parameters are
                        // deliberately not split out: doing both would send them twice.
                        Name = NameFromUrl(url),
                        Method = method.ToUpperInvariant(),
                        Url = url,
                        Headers = headers,
                        Body = HarBody(req)
                    };

                    int idx = groups.FindIndex(g => string.Equals(g.Host, host, StringComparison.OrdinalIgnoreCase));
                    if (idx < 0) groups.Add((host, new List<ApiRequest> { request }));
                    else groups[idx].Items.Add(request);
                }

                if (sawCredentials)
                    warnings.Add("some entries carry credential headers (Authorization/Cookie/API key); they were imported verbatim and every export redacts them, but treat this collection as sensitive");
                if (groups.Count == 0)
                    warnings.Add("the archive contained no usable requests");

                var collection = new ApiCollection
                {
                    Name = "HAR import",
                    Root = new ApiFolder
                    {
                        Name = "HAR import",
                        Folders = groups.Select(g => new ApiFolder { Name = g.Host, Requests = g.Items }).ToList()
                    }
                };
                return ImportResult.From(collection, warnings);
            }
            catch (Exception ex)
            {
                return ImportResult.Fail("could not read the HAR file: " + ex.Message);
            }
        }
    }

    private static ApiBody HarBody(JsonElement req)
    {
        if (!Jx.Prop(req, "postData", out var pd) || pd.ValueKind != JsonValueKind.Object) return ApiBody.None;
        string mime = Jx.Str(pd, "mimeType");
        string text = Jx.Str(pd, "text");

        var parameters = new List<ApiKeyValue>();
        foreach (var p in Jx.Arr(pd, "params"))
        {
            string pn = Jx.Str(p, "name");
            if (pn.Length == 0) continue;
            parameters.Add(new ApiKeyValue { Name = pn, Value = Jx.Str(p, "value") });
        }

        if (mime.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0)
            return new ApiBody { Kind = ApiBodyKind.Json, Text = text };
        if (mime.IndexOf("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) >= 0 && parameters.Count > 0)
            return new ApiBody { Kind = ApiBodyKind.UrlEncoded, Form = parameters };
        if (mime.IndexOf("multipart/form-data", StringComparison.OrdinalIgnoreCase) >= 0 && parameters.Count > 0)
            return new ApiBody { Kind = ApiBodyKind.Multipart, Form = parameters };
        if (text.Length == 0 && parameters.Count == 0) return ApiBody.None;

        return new ApiBody
        {
            Kind = ApiBodyKind.Raw,
            Text = text,
            // Strip the ";charset=..." suffix: the client sets the charset itself.
            ContentType = mime.Split(';')[0].Trim()
        };
    }

    // ------------------------------------------------------------------ curl

    /// <summary>
    /// Parses one curl command line into a request. Returns null when no URL can be
    /// found, which is the only way this can fail. Unknown options are skipped rather
    /// than treated as errors, because "Copy as cURL" output varies between browsers.
    /// </summary>
    public static ApiRequest? FromCurl(string curlCommand) => ParseCurl(curlCommand, new List<string>());

    private static readonly HashSet<string> CurlValueFlags = new(StringComparer.Ordinal)
    {
        "-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
        "--data-ascii", "--data-urlencode", "--json", "-u", "--user", "--url", "-F", "--form",
        "-A", "--user-agent", "-b", "--cookie", "-e", "--referer", "--oauth2-bearer",
        "-m", "--max-time", "-T", "--upload-file",
        // Consumed and ignored: their values must not be mistaken for the URL.
        "-o", "--output", "-c", "--cookie-jar", "-w", "--write-out", "--connect-timeout",
        "--retry", "--cacert", "--cert", "-E", "--key", "-x", "--proxy", "--proxy-user",
        "--limit-rate", "--interface", "--resolve"
    };

    // Short flags that take no value, so "-sSL" can be split into its parts.
    private const string CurlBooleanShorts = "LkKsSvifgINR#";

    private static ApiRequest? ParseCurl(string curlCommand, List<string> warnings)
    {
        if (string.IsNullOrWhiteSpace(curlCommand)) return null;

        var tokens = TokenizeShell(curlCommand);
        int start = 0;
        if (tokens.Count > 0)
        {
            string first = tokens[0];
            if (first.Equals("curl", StringComparison.OrdinalIgnoreCase) ||
                first.EndsWith("/curl", StringComparison.OrdinalIgnoreCase) ||
                first.EndsWith("\\curl.exe", StringComparison.OrdinalIgnoreCase) ||
                first.EndsWith("curl.exe", StringComparison.OrdinalIgnoreCase))
                start = 1;
        }

        string? method = null, url = null;
        var headers = new List<ApiKeyValue>();
        var form = new List<ApiKeyValue>();
        var data = new List<string>();
        string jsonData = "";
        bool hasJson = false, follow = false, head = false;
        string user = "", bearer = "", uploadFile = "";
        int timeout = 0;
        var notes = new List<string>();

        void ApplyFlag(string flag)
        {
            switch (flag)
            {
                case "-L": case "--location": follow = true; break;
                case "-I": case "--head": head = true; break;
                case "-k": case "--insecure":
                    notes.Add("curl --insecure was ignored: ProcessShield never disables certificate validation.");
                    break;
                case "-G": case "--get":
                    notes.Add("curl -G was ignored: data was left in the body instead of being moved into the query string.");
                    break;
                // --compressed and the noise flags (-s, -v, -i, ...) affect curl's own
                // output, not the request, so they are dropped silently.
            }
        }

        for (int i = start; i < tokens.Count; i++)
        {
            string tok = tokens[i];
            if (tok.Length == 0) continue;

            if (tok[0] != '-' || tok == "-")
            {
                if (url is null) url = tok;
                else warnings.Add($"the curl command lists more than one URL; only '{url}' was imported");
                continue;
            }

            string name = tok;
            string attached = "";
            bool hasAttached = false;

            if (tok.StartsWith("--", StringComparison.Ordinal))
            {
                int eq = tok.IndexOf('=');
                if (eq > 2 && CurlValueFlags.Contains(tok[..eq]))
                {
                    name = tok[..eq];
                    attached = tok[(eq + 1)..];
                    hasAttached = true;
                }
            }
            else if (tok.Length > 2 && CurlValueFlags.Contains(tok[..2]))
            {
                // curl allows the value to be glued on: -H'X: y', -XPOST.
                name = tok[..2];
                attached = tok[2..];
                hasAttached = true;
            }
            else if (tok.Length > 2 && tok.Skip(1).All(c => CurlBooleanShorts.IndexOf(c) >= 0))
            {
                foreach (char c in tok[1..]) ApplyFlag("-" + c);
                continue;
            }

            string value = "";
            if (CurlValueFlags.Contains(name))
            {
                if (hasAttached) value = attached;
                else if (i + 1 < tokens.Count) value = tokens[++i];
                else { warnings.Add($"curl option {name} has no value and was ignored"); continue; }
            }
            else { ApplyFlag(name); continue; }

            switch (name)
            {
                case "-X": case "--request": method = value.Trim().ToUpperInvariant(); break;
                case "--url": url = value; break;

                case "-H": case "--header":
                {
                    int colon = value.IndexOf(':');
                    if (colon > 0)
                        headers.Add(new ApiKeyValue { Name = value[..colon].Trim(), Value = value[(colon + 1)..].Trim() });
                    else if (value.EndsWith(";", StringComparison.Ordinal))
                        headers.Add(new ApiKeyValue { Name = value[..^1].Trim(), Value = "" });   // curl's "send empty header"
                    else
                        warnings.Add($"header '{value}' is not in 'Name: value' form and was ignored");
                    break;
                }

                case "-d": case "--data": case "--data-raw":
                case "--data-binary": case "--data-ascii": case "--data-urlencode":
                    data.Add(value);
                    break;

                case "--json": jsonData = value; hasJson = true; break;

                case "-u": case "--user": user = value; break;
                case "--oauth2-bearer": bearer = value; break;

                case "-F": case "--form":
                {
                    int eq = value.IndexOf('=');
                    if (eq <= 0) { warnings.Add($"form field '{value}' is not in 'name=value' form and was ignored"); break; }
                    form.Add(new ApiKeyValue { Name = value[..eq], Value = value[(eq + 1)..] });
                    break;
                }

                case "-A": case "--user-agent": headers.Add(ApiKeyValue.Of("User-Agent", value)); break;
                case "-b": case "--cookie": headers.Add(ApiKeyValue.Of("Cookie", value)); break;
                case "-e": case "--referer": headers.Add(ApiKeyValue.Of("Referer", value)); break;

                case "-m": case "--max-time":
                    if (double.TryParse(value, System.Globalization.NumberStyles.Float,
                                        System.Globalization.CultureInfo.InvariantCulture, out double secs) && secs > 0)
                        timeout = (int)Math.Clamp(Math.Ceiling(secs), 1, 3600);
                    break;

                case "-T": case "--upload-file": uploadFile = value; break;
            }
        }

        if (url is null) return null;
        if (url.IndexOf("://", StringComparison.Ordinal) < 0)
        {
            // curl would default to http. ProcessShield defaults to https instead: a silent
            // downgrade to cleartext is the wrong default for a security tool.
            url = "https://" + url.TrimStart('/');
            notes.Add("the URL had no scheme; https:// was assumed (curl would have used http://).");
        }

        var body = ApiBody.None;
        if (uploadFile.Length > 0)
            body = new ApiBody { Kind = ApiBodyKind.File, FilePath = uploadFile };
        else if (form.Count > 0)
            body = new ApiBody { Kind = ApiBodyKind.Multipart, Form = form };
        else if (hasJson)
            body = ApiBody.Json(jsonData);
        else if (data.Count > 0)
            body = CurlDataBody(string.Join("&", data), headers);

        string resolvedMethod = method
            ?? (head ? "HEAD"
                : uploadFile.Length > 0 ? "PUT"
                : body.Kind != ApiBodyKind.None ? "POST"
                : "GET");

        var auth = ApiAuth.None;
        if (bearer.Length > 0)
            auth = new ApiAuth { Kind = ApiAuthKind.Bearer, Token = bearer };
        else if (user.Length > 0)
        {
            int colon = user.IndexOf(':');
            auth = new ApiAuth
            {
                Kind = ApiAuthKind.Basic,
                Username = colon >= 0 ? user[..colon] : user,
                Password = colon >= 0 ? user[(colon + 1)..] : ""
            };
        }

        foreach (var n in notes) warnings.Add(n);

        return new ApiRequest
        {
            Name = NameFromUrl(url),
            Method = resolvedMethod,
            Url = url,
            // curl does NOT follow redirects unless -L is given; that fidelity is kept
            // even though ApiRequest defaults to following them.
            FollowRedirects = follow,
            Headers = headers,
            Body = body,
            Auth = auth,
            Description = string.Join(" ", notes),
            TimeoutSeconds = timeout > 0 ? timeout : 30
        };
    }

    private static ApiBody CurlDataBody(string text, List<ApiKeyValue> headers)
    {
        string ct = headers.FirstOrDefault(h =>
            string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase))?.Value ?? "";

        if (ct.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0 ||
            (ct.Length == 0 && LooksLikeJson(text)))
            return new ApiBody { Kind = ApiBodyKind.Json, Text = text };

        // curl's default content type for -d is x-www-form-urlencoded, so a well-formed
        // pair list becomes a real form; anything else is kept as raw bytes.
        if (ct.Length == 0 || ct.IndexOf("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            var form = new List<ApiKeyValue>();
            bool wellFormed = text.Length > 0;
            foreach (var pair in text.Split('&'))
            {
                int eq = pair.IndexOf('=');
                if (eq <= 0) { wellFormed = false; break; }
                form.Add(new ApiKeyValue
                {
                    Name = Uri.UnescapeDataString(pair[..eq]),
                    Value = Uri.UnescapeDataString(pair[(eq + 1)..])
                });
            }
            if (wellFormed) return new ApiBody { Kind = ApiBodyKind.UrlEncoded, Form = form };
        }

        return new ApiBody
        {
            Kind = ApiBodyKind.Raw,
            Text = text,
            ContentType = ct.Length > 0 ? ct : "application/x-www-form-urlencoded"
        };
    }

    /// <summary>
    /// Splits a POSIX-sh style command line. Handles single quotes (literal), double
    /// quotes (with backslash escapes) and backslash/caret line continuations, which is
    /// everything "Copy as cURL" emits. It is not a shell: no expansion, no substitution.
    /// </summary>
    internal static List<string> TokenizeShell(string command)
    {
        var tokens = new List<string>();
        var cur = new StringBuilder();
        bool started = false;   // distinguishes an empty quoted token from no token at all
        int i = 0;

        while (i < command.Length)
        {
            char c = command[i];

            if ((c == '\\' || c == '^') && i + 1 < command.Length &&
                (command[i + 1] == '\n' || command[i + 1] == '\r'))
            {
                i++;
                if (command[i] == '\r' && i + 1 < command.Length && command[i + 1] == '\n') i++;
                i++;
                continue;
            }

            if (char.IsWhiteSpace(c))
            {
                if (started) { tokens.Add(cur.ToString()); cur.Clear(); started = false; }
                i++;
                continue;
            }

            if (c == '\'')
            {
                started = true;
                i++;
                while (i < command.Length && command[i] != '\'') { cur.Append(command[i]); i++; }
                if (i < command.Length) i++;
                continue;
            }

            if (c == '"')
            {
                started = true;
                i++;
                while (i < command.Length && command[i] != '"')
                {
                    if (command[i] == '\\' && i + 1 < command.Length)
                    {
                        char next = command[i + 1];
                        if (next == '\n') { i += 2; continue; }
                        if (next is '\\' or '"' or '$' or '`') { cur.Append(next); i += 2; continue; }
                    }
                    cur.Append(command[i]);
                    i++;
                }
                if (i < command.Length) i++;
                continue;
            }

            if (c == '\\' && i + 1 < command.Length)
            {
                cur.Append(command[i + 1]);
                started = true;
                i += 2;
                continue;
            }

            cur.Append(c);
            started = true;
            i++;
        }

        if (started) tokens.Add(cur.ToString());
        return tokens;
    }
}

/// <summary>
/// Small tolerant reader over <see cref="JsonElement"/>. File-local so it cannot
/// collide with any other helper in the assembly.
/// </summary>
file static class Jx
{
    /// <summary>
    /// Property lookup that falls back to a case-insensitive scan. JSON is
    /// case-sensitive, but hand-edited collections routinely get the casing wrong and
    /// silently dropping the field is worse than accepting it.
    /// </summary>
    public static bool Prop(JsonElement e, string name, out JsonElement value)
    {
        value = default;
        if (e.ValueKind != JsonValueKind.Object) return false;
        if (e.TryGetProperty(name, out value)) return true;
        foreach (var p in e.EnumerateObject())
            if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = p.Value;
                return true;
            }
        return false;
    }

    public static string? AsString(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => v.GetString(),
        JsonValueKind.Number => v.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        _ => null
    };

    public static string Str(JsonElement e, string name, string fallback = "")
        => Prop(e, name, out var v) ? AsString(v) ?? fallback : fallback;

    public static bool Bool(JsonElement e, string name, bool fallback = false)
    {
        if (!Prop(e, name, out var v)) return fallback;
        return v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => bool.TryParse(v.GetString(), out bool b) ? b : fallback,
            _ => fallback
        };
    }

    public static IEnumerable<JsonElement> Arr(JsonElement e, string name)
    {
        if (!Prop(e, name, out var v) || v.ValueKind != JsonValueKind.Array) yield break;
        foreach (var item in v.EnumerateArray()) yield return item;
    }

    /// <summary>Descriptions are a string in most documents and {content: "..."} in Postman.</summary>
    public static string Description(JsonElement e, string name = "description")
    {
        if (!Prop(e, name, out var v)) return "";
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString() ?? "",
            JsonValueKind.Object => Str(v, "content"),
            _ => ""
        };
    }
}

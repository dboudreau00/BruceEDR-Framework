using System.Buffers;
using System.Text;
using System.Text.Json;

namespace BruceEDR.Api;

// ---------------------------------------------------------------------------
// Exporters: render an ApiCollection into the formats people hand to other
// tools and to each other.
//
// Design notes:
//  * Every exporter is pure and deterministic. Nothing here reads the clock,
//    generates a GUID or enumerates the environment, so the same collection
//    always produces byte-identical output and a diff of two exports means a
//    real change. That is why no IClock is injected: no timestamps are emitted.
//  * Secrets are removed on the way out. ApiAuth.Redacted() covers the auth
//    record; header, query and shell exports additionally redact by NAME using
//    a deliberately over-broad pattern. Over-redaction is an inconvenience,
//    a leaked bearer token in a pasted command is an incident.
//  * HONEST LIMITATION: request BODIES are exported verbatim. A body can carry a
//    password or a signed assertion and no name-based rule can find it, so every
//    textual export says so in a header comment.
// ---------------------------------------------------------------------------

/// <summary>Writers that turn an <see cref="ApiCollection"/> into a portable document.</summary>
public static class ApiExporters
{
    /// <summary>Replaces any value considered secret in textual exports.</summary>
    public const string RedactedPlaceholder = "REDACTED";

    internal const string PostmanSchema =
        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json";

    // Substrings that make a header or query-parameter NAME suspicious. Matching on the
    // name rather than the value is crude and over-inclusive on purpose: an
    // "Idempotency-Key" that gets redacted costs a retype, a leaked "X-Api-Key" does not.
    private static readonly string[] SecretNameFragments =
    {
        "auth", "token", "secret", "password", "passwd", "pwd", "cookie",
        "key", "credential", "signature", "sig", "session", "csrf"
    };

    /// <summary>True when a header or parameter name looks like it carries a credential.</summary>
    internal static bool IsSecretName(string name) =>
        !string.IsNullOrEmpty(name) &&
        SecretNameFragments.Any(f => name.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0);

    private static string RedactByName(string name, string value) =>
        value.Length > 0 && IsSecretName(name) ? RedactedPlaceholder : value;

    // ---------------------------------------------------------------- postman

    /// <summary>
    /// Writes a Postman Collection v2.1 document. Auth material is passed through
    /// <see cref="ApiAuth.Redacted"/> first, so the file carries {{token}}-style
    /// placeholders instead of credentials and is safe to attach to a ticket.
    /// </summary>
    public static string ToPostman(ApiCollection collection)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();

            w.WriteStartObject("info");
            w.WriteString("name", collection.Name);
            if (collection.Description.Length > 0) w.WriteString("description", collection.Description);
            w.WriteString("schema", PostmanSchema);
            w.WriteEndObject();

            w.WriteStartArray("item");
            foreach (var r in collection.Root.Requests) WritePostmanRequest(w, r);
            foreach (var f in collection.Root.Folders) WritePostmanFolder(w, f, 0);
            w.WriteEndArray();

            if (collection.Auth.Kind != ApiAuthKind.None)
                WritePostmanAuth(w, collection.Auth);

            if (collection.Variables.Count > 0)
            {
                w.WriteStartArray("variable");
                // Sorted so the output does not depend on dictionary insertion order.
                foreach (var kv in collection.Variables.OrderBy(k => k.Key, StringComparer.Ordinal))
                {
                    w.WriteStartObject();
                    w.WriteString("key", kv.Key);
                    w.WriteString("value", IsSecretName(kv.Key) && kv.Value.Length > 0 ? RedactedPlaceholder : kv.Value);
                    w.WriteEndObject();
                }
                w.WriteEndArray();
            }

            if (collection.DefaultHeaders.Count > 0)
            {
                // Postman has no collection-level header concept. This extension block is
                // ignored by Postman and read back by ApiImporters.FromPostman, so a
                // BruceEDR round trip keeps them and other tools simply lose them.
                w.WriteStartObject("_bruceedr");
                w.WriteStartArray("defaultHeaders");
                foreach (var h in collection.DefaultHeaders) WritePostmanKeyValue(w, h, redact: true);
                w.WriteEndArray();
                w.WriteEndObject();
            }

            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WritePostmanFolder(Utf8JsonWriter w, ApiFolder folder, int depth)
    {
        w.WriteStartObject();
        w.WriteString("name", folder.Name);
        if (folder.Description.Length > 0) w.WriteString("description", folder.Description);
        w.WriteStartArray("item");
        foreach (var r in folder.Requests) WritePostmanRequest(w, r);
        // Guarded to mirror the importer's limit; a cyclic tree cannot occur with
        // immutable records, but a pathological depth would still blow the stack.
        if (depth < ApiImporters.MaxFolderDepth)
            foreach (var f in folder.Folders) WritePostmanFolder(w, f, depth + 1);
        w.WriteEndArray();
        w.WriteEndObject();
    }

    private static void WritePostmanRequest(Utf8JsonWriter w, ApiRequest r)
    {
        w.WriteStartObject();
        w.WriteString("id", r.Id);
        w.WriteString("name", r.Name);

        w.WriteStartObject("request");
        w.WriteString("method", r.Method);
        if (r.Description.Length > 0) w.WriteString("description", r.Description);

        w.WriteStartArray("header");
        foreach (var h in r.Headers) WritePostmanKeyValue(w, h, redact: true);
        w.WriteEndArray();

        WritePostmanUrl(w, r);
        WritePostmanBody(w, r.Body);
        if (r.Auth.Kind != ApiAuthKind.None) WritePostmanAuth(w, r.Auth);

        w.WriteEndObject();   // request

        WritePostmanEvents(w, r);
        w.WriteEndObject();   // item
    }

    private static void WritePostmanKeyValue(Utf8JsonWriter w, ApiKeyValue kv, bool redact)
    {
        w.WriteStartObject();
        w.WriteString("key", kv.Name);
        w.WriteString("value", redact ? RedactByName(kv.Name, kv.Value) : kv.Value);
        if (!kv.Enabled) w.WriteBoolean("disabled", true);
        if (kv.Description.Length > 0) w.WriteString("description", kv.Description);
        w.WriteEndObject();
    }

    /// <summary>
    /// Splits the request URL into Postman's structured form. Query parameters already
    /// written into <see cref="ApiRequest.Url"/> are merged with
    /// <see cref="ApiRequest.Query"/> so nothing is sent twice on re-import.
    /// </summary>
    private static void WritePostmanUrl(Utf8JsonWriter w, ApiRequest r)
    {
        string basePart = r.Url;
        var query = new List<ApiKeyValue>();

        int qm = r.Url.IndexOf('?');
        if (qm >= 0)
        {
            basePart = r.Url[..qm];
            foreach (var pair in r.Url[(qm + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = pair.IndexOf('=');
                query.Add(new ApiKeyValue
                {
                    Name = eq < 0 ? pair : pair[..eq],
                    Value = eq < 0 ? "" : pair[(eq + 1)..]
                });
            }
        }
        query.AddRange(r.Query);

        var enabled = query.Where(q => q.Enabled).ToList();
        string raw = basePart;
        if (enabled.Count > 0)
            raw += "?" + string.Join("&", enabled.Select(q =>
            {
                // Redacted here as well as in the structured array, otherwise the raw
                // string would leak the very value the array hides.
                string v = RedactByName(q.Name, q.Value);
                return v.Length == 0 ? q.Name : q.Name + "=" + v;
            }));

        w.WriteStartObject("url");
        w.WriteString("raw", raw);

        // Only a plain absolute http(s) URL can be decomposed. Anything templated
        // ("{{baseUrl}}/x") is left as raw, which Postman accepts.
        if (Uri.TryCreate(basePart, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            w.WriteString("protocol", uri.Scheme);
            w.WriteStartArray("host");
            foreach (var part in uri.Host.Split('.')) w.WriteStringValue(part);
            w.WriteEndArray();
            if (!uri.IsDefaultPort) w.WriteString("port", uri.Port.ToString());
            w.WriteStartArray("path");
            foreach (var seg in uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries))
                w.WriteStringValue(seg);
            w.WriteEndArray();
        }

        if (query.Count > 0)
        {
            w.WriteStartArray("query");
            foreach (var q in query) WritePostmanKeyValue(w, q, redact: true);
            w.WriteEndArray();
        }
        w.WriteEndObject();
    }

    private static void WritePostmanBody(Utf8JsonWriter w, ApiBody body)
    {
        if (body.Kind == ApiBodyKind.None) return;

        w.WriteStartObject("body");
        switch (body.Kind)
        {
            case ApiBodyKind.Json:
                w.WriteString("mode", "raw");
                w.WriteString("raw", body.Text);
                WriteRawLanguage(w, "json");
                break;

            case ApiBodyKind.Raw:
                w.WriteString("mode", "raw");
                w.WriteString("raw", body.Text);
                // Postman only models a handful of languages; an exotic content type
                // degrades to "text" and is not recovered on re-import.
                WriteRawLanguage(w, body.ContentType.ToLowerInvariant() switch
                {
                    "application/xml" or "text/xml" => "xml",
                    "text/html" => "html",
                    "application/javascript" or "text/javascript" => "javascript",
                    _ => "text"
                });
                break;

            case ApiBodyKind.UrlEncoded:
                w.WriteString("mode", "urlencoded");
                w.WriteStartArray("urlencoded");
                foreach (var f in body.Form) WritePostmanKeyValue(w, f, redact: true);
                w.WriteEndArray();
                break;

            case ApiBodyKind.Multipart:
                w.WriteString("mode", "formdata");
                w.WriteStartArray("formdata");
                foreach (var f in body.Form) WritePostmanKeyValue(w, f, redact: true);
                w.WriteEndArray();
                break;

            case ApiBodyKind.File:
                w.WriteString("mode", "file");
                w.WriteStartObject("file");
                w.WriteString("src", body.FilePath);
                w.WriteEndObject();
                break;
        }
        w.WriteEndObject();
    }

    private static void WriteRawLanguage(Utf8JsonWriter w, string language)
    {
        w.WriteStartObject("options");
        w.WriteStartObject("raw");
        w.WriteString("language", language);
        w.WriteEndObject();
        w.WriteEndObject();
    }

    private static void WritePostmanAuth(Utf8JsonWriter w, ApiAuth auth)
    {
        var a = auth.Redacted();
        w.WriteStartObject("auth");
        switch (a.Kind)
        {
            case ApiAuthKind.Basic:
                w.WriteString("type", "basic");
                w.WriteStartArray("basic");
                WriteAuthParam(w, "username", a.Username);
                WriteAuthParam(w, "password", a.Password);
                w.WriteEndArray();
                break;

            case ApiAuthKind.Bearer:
                w.WriteString("type", "bearer");
                w.WriteStartArray("bearer");
                WriteAuthParam(w, "token", a.Token);
                w.WriteEndArray();
                break;

            case ApiAuthKind.ApiKeyHeader:
            case ApiAuthKind.ApiKeyQuery:
                w.WriteString("type", "apikey");
                w.WriteStartArray("apikey");
                WriteAuthParam(w, "key", a.KeyName);
                WriteAuthParam(w, "value", a.KeyValue);
                WriteAuthParam(w, "in", a.Kind == ApiAuthKind.ApiKeyQuery ? "query" : "header");
                w.WriteEndArray();
                break;

            case ApiAuthKind.RawHeader:
                // Postman has no "send this Authorization value verbatim" mode, so it is
                // exported as an Authorization api-key. Re-importing yields ApiKeyHeader,
                // not RawHeader: the transport is preserved, the kind is not.
                w.WriteString("type", "apikey");
                w.WriteStartArray("apikey");
                WriteAuthParam(w, "key", "Authorization");
                WriteAuthParam(w, "value", a.RawValue);
                WriteAuthParam(w, "in", "header");
                w.WriteEndArray();
                break;

            default:
                w.WriteString("type", "noauth");
                break;
        }
        w.WriteEndObject();
    }

    private static void WriteAuthParam(Utf8JsonWriter w, string key, string value)
    {
        w.WriteStartObject();
        w.WriteString("key", key);
        w.WriteString("value", value);
        w.WriteString("type", "string");
        w.WriteEndObject();
    }

    private static void WritePostmanEvents(Utf8JsonWriter w, ApiRequest r)
    {
        if (r.Assertions.Count == 0) return;

        var lines = new List<string>();
        foreach (var a in r.Assertions)
        {
            if (a.Kind == AssertionKind.StatusEquals && int.TryParse(a.Expected, out int code))
            {
                string label = string.IsNullOrWhiteSpace(a.Name) ? "Status is " + code : a.Name;
                lines.Add($"pm.test(\"{EscapeJsString(label)}\", function () {{");
                lines.Add($"    pm.response.to.have.status({code});");
                lines.Add("});");
            }
            else
            {
                // Emitted as a comment: generating JavaScript for the other assertion
                // kinds would mean shipping a second, silently divergent implementation.
                lines.Add("// BruceEDR assertion not expressible in Postman: " + EscapeJsComment(a.DisplayName));
            }
        }
        if (lines.Count == 0) return;

        w.WriteStartArray("event");
        w.WriteStartObject();
        w.WriteString("listen", "test");
        w.WriteStartObject("script");
        w.WriteString("type", "text/javascript");
        w.WriteStartArray("exec");
        foreach (var l in lines) w.WriteStringValue(l);
        w.WriteEndArray();
        w.WriteEndObject();
        w.WriteEndObject();
        w.WriteEndArray();
    }

    // Only quotes and backslashes matter inside the generated string literal; the
    // Utf8JsonWriter escapes everything else on the way into the JSON document.
    private static string EscapeJsString(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", " ").Replace("\n", " ");

    private static string EscapeJsComment(string s) => s.Replace("\r", " ").Replace("\n", " ");

    // ------------------------------------------------------------------- curl

    /// <summary>Template expansion depth for exports; deep enough for nested variables, shallow enough to terminate.</summary>
    private const int TemplateDepth = 8;

    private static string Sub(string text, IReadOnlyDictionary<string, string>? vars) =>
        vars is null || vars.Count == 0 || string.IsNullOrEmpty(text)
            ? text
            : Templating.Resolve(text, vars, TemplateDepth);

    /// <summary>
    /// Renders a request as a POSIX sh curl command. Every value is single-quoted with
    /// the '\'' idiom, so no part of a URL, header or body can escape its quotes and
    /// become a second command. Credentials are replaced with
    /// <see cref="RedactedPlaceholder"/>; the comment header says so, because a command
    /// that silently sent REDACTED would be baffling.
    /// </summary>
    public static string ToCurl(ApiRequest request, IReadOnlyDictionary<string, string>? vars = null)
    {
        var parts = new List<string>();

        string url = Sub(request.Url, vars);
        var enabledQuery = request.Query.Where(q => q.Enabled).ToList();
        if (request.Auth.Kind == ApiAuthKind.ApiKeyQuery && request.Auth.KeyName.Length > 0)
            enabledQuery.Add(new ApiKeyValue { Name = request.Auth.KeyName, Value = RedactedPlaceholder });

        if (enabledQuery.Count > 0)
        {
            var encoded = enabledQuery.Select(q =>
            {
                string value = RedactByName(q.Name, Sub(q.Value, vars));
                return Encode(q.Name) + "=" + Encode(value);
            });
            url += (url.Contains('?') ? "&" : "?") + string.Join("&", encoded);
        }

        parts.Add("-X " + ShQuote(request.Method));
        parts.Add(ShQuote(url));

        bool hasContentType = false;
        foreach (var h in request.Headers)
        {
            if (!h.Enabled) continue;
            if (string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase)) hasContentType = true;
            string value = RedactByName(h.Name, Sub(h.Value, vars));
            parts.Add("-H " + ShQuote(h.Name + ": " + value));
        }

        switch (request.Auth.Kind)
        {
            case ApiAuthKind.Basic:
                // -u keeps the credential out of a base64 blob that looks opaque but is not.
                parts.Add("-u " + ShQuote(Sub(request.Auth.Username, vars) + ":" + RedactedPlaceholder));
                break;
            case ApiAuthKind.Bearer:
                parts.Add("-H " + ShQuote("Authorization: Bearer " + RedactedPlaceholder));
                break;
            case ApiAuthKind.ApiKeyHeader when request.Auth.KeyName.Length > 0:
                parts.Add("-H " + ShQuote(request.Auth.KeyName + ": " + RedactedPlaceholder));
                break;
            case ApiAuthKind.RawHeader when request.Auth.RawValue.Length > 0:
                parts.Add("-H " + ShQuote("Authorization: " + RedactedPlaceholder));
                break;
        }

        var body = request.Body;
        if (body.Kind != ApiBodyKind.None && !hasContentType)
        {
            string ct = body.EffectiveContentType();
            // curl builds the multipart content type itself, boundary included.
            if (ct.Length > 0 && body.Kind != ApiBodyKind.Multipart)
                parts.Add("-H " + ShQuote("Content-Type: " + ct));
        }

        switch (body.Kind)
        {
            case ApiBodyKind.Json:
            case ApiBodyKind.Raw:
                parts.Add("--data-raw " + ShQuote(Sub(body.Text, vars)));
                break;
            case ApiBodyKind.UrlEncoded:
                parts.Add("--data-raw " + ShQuote(string.Join("&", body.Form.Where(f => f.Enabled)
                    .Select(f => Encode(f.Name) + "=" + Encode(RedactByName(f.Name, Sub(f.Value, vars)))))));
                break;
            case ApiBodyKind.Multipart:
                foreach (var f in body.Form.Where(f => f.Enabled))
                    parts.Add("-F " + ShQuote(f.Name + "=" + RedactByName(f.Name, Sub(f.Value, vars))));
                break;
            case ApiBodyKind.File:
                parts.Add("--data-binary " + ShQuote("@" + Sub(body.FilePath, vars)));
                break;
        }

        if (request.FollowRedirects) parts.Add("-L");
        if (request.TimeoutSeconds > 0) parts.Add("--max-time " + request.TimeoutSeconds);

        var sb = new StringBuilder();
        sb.Append("# ").Append(string.IsNullOrWhiteSpace(request.Name) ? request.DisplayName : request.Name).Append('\n');
        sb.Append("# Credentials are replaced with ").Append(RedactedPlaceholder)
          .Append(" -- substitute the real values before running this.\n");
        sb.Append("# The request body is exported verbatim and may still contain sensitive data.\n");
        sb.Append("curl");
        foreach (var p in parts) sb.Append(" \\\n  ").Append(p);
        return sb.ToString();
    }

    /// <summary>
    /// Wraps a value for POSIX sh. Single quotes suppress every expansion; an embedded
    /// single quote is closed, escaped and reopened, which is the only safe form.
    /// </summary>
    internal static string ShQuote(string value)
    {
        if (value.Length == 0) return "''";
        return "'" + value.Replace("'", "'\\''") + "'";
    }

    // Percent-encoding is skipped for values that carry an unresolved {{template}},
    // because encoding the braces would destroy the placeholder the user still has to fill in.
    private static string Encode(string value) =>
        value.Contains("{{", StringComparison.Ordinal) ? value : Uri.EscapeDataString(value);

    // ---------------------------------------------------------------- openapi

    /// <summary>
    /// Describes the collection as an OpenAPI 3.0.3 document. This is a description of
    /// what the collection SENDS, reconstructed from concrete requests — it is not a
    /// substitute for a specification the API owner maintains. Response schemas are not
    /// invented; each operation documents only the status code its assertions expect.
    /// </summary>
    public static string ToOpenApi(ApiCollection collection, string title, string version)
    {
        var requests = collection.Requests().ToList();
        string server = MostCommonServer(requests);

        // path -> method -> (request, tag)
        var paths = new List<(string Path, List<(string Method, ApiRequest Request, string Tag)> Ops)>();
        var operationIds = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (folder, request) in WalkTagged(collection.Root, ""))
        {
            string path = OpenApiPath(request.Url, server);
            string method = request.Method.ToLowerInvariant();
            int idx = paths.FindIndex(p => string.Equals(p.Path, path, StringComparison.Ordinal));
            if (idx < 0) { paths.Add((path, new List<(string, ApiRequest, string)> { (method, request, folder) })); continue; }
            // OpenAPI cannot express the same path+method twice; the first wins.
            if (paths[idx].Ops.Any(o => string.Equals(o.Method, method, StringComparison.Ordinal))) continue;
            paths[idx].Ops.Add((method, request, folder));
        }

        var schemes = requests.Select(r => r.Auth.Kind == ApiAuthKind.None ? collection.Auth.Kind : r.Auth.Kind)
                              .Where(k => k != ApiAuthKind.None)
                              .Distinct()
                              .ToList();

        var buffer = new ArrayBufferWriter<byte>();
        using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            w.WriteString("openapi", "3.0.3");

            w.WriteStartObject("info");
            w.WriteString("title", string.IsNullOrWhiteSpace(title) ? collection.Name : title);
            w.WriteString("version", string.IsNullOrWhiteSpace(version) ? "1.0.0" : version);
            if (collection.Description.Length > 0) w.WriteString("description", collection.Description);
            w.WriteEndObject();

            if (server.Length > 0)
            {
                w.WriteStartArray("servers");
                w.WriteStartObject();
                w.WriteString("url", TemplateToOpenApi(server));
                var serverVars = TemplateNames(server).ToList();
                if (serverVars.Count > 0)
                {
                    w.WriteStartObject("variables");
                    foreach (var v in serverVars)
                    {
                        w.WriteStartObject(v);
                        w.WriteString("default", collection.Variables.TryGetValue(v, out var dv) && !IsSecretName(v) ? dv : "");
                        w.WriteEndObject();
                    }
                    w.WriteEndObject();
                }
                w.WriteEndObject();
                w.WriteEndArray();
            }

            w.WriteStartObject("paths");
            foreach (var (path, ops) in paths)
            {
                w.WriteStartObject(path);
                foreach (var (method, request, tag) in ops)
                    WriteOpenApiOperation(w, method, request, tag, path, operationIds);
                w.WriteEndObject();
            }
            w.WriteEndObject();

            if (schemes.Count > 0)
            {
                w.WriteStartObject("components");
                w.WriteStartObject("securitySchemes");
                foreach (var kind in schemes)
                {
                    switch (kind)
                    {
                        case ApiAuthKind.Basic:
                            w.WriteStartObject("basicAuth");
                            w.WriteString("type", "http");
                            w.WriteString("scheme", "basic");
                            w.WriteEndObject();
                            break;
                        case ApiAuthKind.Bearer:
                            w.WriteStartObject("bearerAuth");
                            w.WriteString("type", "http");
                            w.WriteString("scheme", "bearer");
                            w.WriteEndObject();
                            break;
                        case ApiAuthKind.ApiKeyHeader:
                        case ApiAuthKind.ApiKeyQuery:
                        case ApiAuthKind.RawHeader:
                        {
                            string keyName = requests
                                .Select(r => r.Auth.Kind == kind ? r.Auth.KeyName : "")
                                .FirstOrDefault(n => n.Length > 0) ?? "";
                            if (keyName.Length == 0) keyName = "Authorization";
                            w.WriteStartObject(kind == ApiAuthKind.ApiKeyQuery ? "apiKeyQuery" : "apiKeyHeader");
                            w.WriteString("type", "apiKey");
                            w.WriteString("name", keyName);
                            w.WriteString("in", kind == ApiAuthKind.ApiKeyQuery ? "query" : "header");
                            w.WriteEndObject();
                            break;
                        }
                    }
                }
                w.WriteEndObject();
                w.WriteEndObject();
            }

            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WriteOpenApiOperation(Utf8JsonWriter w, string method, ApiRequest r,
                                              string tag, string path, HashSet<string> usedIds)
    {
        w.WriteStartObject(method);
        if (tag.Length > 0)
        {
            w.WriteStartArray("tags");
            w.WriteStringValue(tag);
            w.WriteEndArray();
        }
        if (r.Name.Length > 0) w.WriteString("summary", r.Name);
        if (r.Description.Length > 0) w.WriteString("description", r.Description);
        w.WriteString("operationId", UniqueOperationId(method, path, r.Name, usedIds));

        // Taken from the already server-stripped path, so a {{baseUrl}} that became a
        // server variable is not also declared as a path parameter.
        var pathVars = BracedNames(path).ToList();
        bool anyParams = pathVars.Count > 0 || r.Query.Count > 0 || r.Headers.Count > 0;
        if (anyParams)
        {
            w.WriteStartArray("parameters");
            foreach (var v in pathVars)
            {
                w.WriteStartObject();
                w.WriteString("name", v);
                w.WriteString("in", "path");
                w.WriteBoolean("required", true);
                w.WriteStartObject("schema");
                w.WriteString("type", "string");
                w.WriteEndObject();
                w.WriteEndObject();
            }
            foreach (var q in r.Query) WriteOpenApiParam(w, q, "query");
            foreach (var h in r.Headers)
            {
                // Content-Type is expressed by requestBody and Authorization by a security
                // scheme; declaring them as parameters as well is invalid OpenAPI.
                if (string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(h.Name, "Authorization", StringComparison.OrdinalIgnoreCase)) continue;
                WriteOpenApiParam(w, h, "header");
            }
            w.WriteEndArray();
        }

        WriteOpenApiRequestBody(w, r.Body);

        w.WriteStartObject("responses");
        var expected = r.Assertions.FirstOrDefault(a => a.Kind == AssertionKind.StatusEquals);
        string code = expected is not null && int.TryParse(expected.Expected, out int c) ? c.ToString() : "200";
        w.WriteStartObject(code);
        w.WriteString("description", "Response observed by BruceEDR API Studio");
        w.WriteEndObject();
        w.WriteEndObject();

        if (r.Auth.Kind != ApiAuthKind.None)
        {
            string schemeName = r.Auth.Kind switch
            {
                ApiAuthKind.Basic => "basicAuth",
                ApiAuthKind.Bearer => "bearerAuth",
                ApiAuthKind.ApiKeyQuery => "apiKeyQuery",
                _ => "apiKeyHeader"
            };
            w.WriteStartArray("security");
            w.WriteStartObject();
            w.WriteStartArray(schemeName);
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteEndArray();
        }

        w.WriteEndObject();
    }

    private static void WriteOpenApiParam(Utf8JsonWriter w, ApiKeyValue kv, string location)
    {
        w.WriteStartObject();
        w.WriteString("name", kv.Name);
        w.WriteString("in", location);
        // Enabled in a collection means "sent by default", which is the closest honest
        // analogue of required. It is a guess, and it is the only signal available.
        w.WriteBoolean("required", kv.Enabled);
        if (kv.Description.Length > 0) w.WriteString("description", kv.Description);
        w.WriteStartObject("schema");
        w.WriteString("type", "string");
        w.WriteEndObject();
        string example = RedactByName(kv.Name, kv.Value);
        if (example.Length > 0) w.WriteString("example", example);
        w.WriteEndObject();
    }

    private static void WriteOpenApiRequestBody(Utf8JsonWriter w, ApiBody body)
    {
        if (body.Kind == ApiBodyKind.None) return;
        string contentType = body.EffectiveContentType();
        if (contentType.Length == 0) return;

        w.WriteStartObject("requestBody");
        w.WriteStartObject("content");
        w.WriteStartObject(contentType);

        if (body.Kind is ApiBodyKind.UrlEncoded or ApiBodyKind.Multipart)
        {
            w.WriteStartObject("schema");
            w.WriteString("type", "object");
            w.WriteStartObject("properties");
            foreach (var f in body.Form)
            {
                w.WriteStartObject(f.Name);
                w.WriteString("type", "string");
                w.WriteEndObject();
            }
            w.WriteEndObject();
            w.WriteEndObject();
        }
        else
        {
            w.WriteStartObject("schema");
            w.WriteString("type", body.Kind == ApiBodyKind.Json ? "object" : "string");
            w.WriteEndObject();
            if (body.Kind == ApiBodyKind.Json && body.Text.Trim().Length > 0)
            {
                // Echo the body as an example only when it really is JSON; writing
                // malformed text into an "example" would produce an invalid document.
                try
                {
                    using var parsed = JsonDocument.Parse(body.Text);
                    w.WritePropertyName("example");
                    parsed.RootElement.WriteTo(w);
                }
                catch (JsonException) { /* not JSON after all: no example */ }
            }
            else if (body.Text.Length > 0)
            {
                w.WriteString("example", body.Text);
            }
        }

        w.WriteEndObject();
        w.WriteEndObject();
        w.WriteEndObject();
    }

    private static IEnumerable<(string Tag, ApiRequest Request)> WalkTagged(ApiFolder folder, string tag)
    {
        foreach (var r in folder.Requests) yield return (tag, r);
        foreach (var f in folder.Folders)
        {
            string child = string.IsNullOrWhiteSpace(f.Name) ? tag : f.Name;
            foreach (var pair in WalkTagged(f, child)) yield return pair;
        }
    }

    private static string MostCommonServer(IReadOnlyList<ApiRequest> requests)
    {
        var counts = new List<(string Prefix, int Count)>();
        foreach (var r in requests)
        {
            string prefix = ServerPrefix(r.Url);
            if (prefix.Length == 0) continue;
            int i = counts.FindIndex(c => string.Equals(c.Prefix, prefix, StringComparison.Ordinal));
            if (i < 0) counts.Add((prefix, 1)); else counts[i] = (prefix, counts[i].Count + 1);
        }
        if (counts.Count == 0) return "";
        // Ties break towards the first URL seen, so the output stays deterministic.
        int best = 0;
        for (int i = 1; i < counts.Count; i++)
            if (counts[i].Count > counts[best].Count) best = i;
        return counts[best].Prefix;
    }

    private static string ServerPrefix(string url)
    {
        if (url.StartsWith("{{", StringComparison.Ordinal))
        {
            int close = url.IndexOf("}}", StringComparison.Ordinal);
            if (close > 2) return url[..(close + 2)];
        }
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            return uri.GetLeftPart(UriPartial.Authority);
        return "";
    }

    private static string OpenApiPath(string url, string server)
    {
        string path = url;
        if (server.Length > 0 && path.StartsWith(server, StringComparison.Ordinal))
            path = path[server.Length..];
        int q = path.IndexOf('?');
        if (q >= 0) path = path[..q];
        path = TemplateToOpenApi(path);
        if (path.Length == 0) path = "/";
        if (!path.StartsWith("/", StringComparison.Ordinal)) path = "/" + path;
        return path;
    }

    /// <summary>Converts {{var}} template syntax into OpenAPI's single-brace {var}.</summary>
    private static string TemplateToOpenApi(string s) => s.Replace("{{", "{").Replace("}}", "}");

    private static IEnumerable<string> TemplateNames(string s)
    {
        int i = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            int open = s.IndexOf("{{", i, StringComparison.Ordinal);
            if (open < 0) yield break;
            int close = s.IndexOf("}}", open + 2, StringComparison.Ordinal);
            if (close < 0) yield break;
            string name = s[(open + 2)..close].Trim();
            if (name.Length > 0 && seen.Add(name)) yield return name;
            i = close + 2;
        }
    }

    /// <summary>Distinct single-brace {name} placeholders, in order of first appearance.</summary>
    private static IEnumerable<string> BracedNames(string s)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int i = 0;
        while (true)
        {
            int open = s.IndexOf('{', i);
            if (open < 0) yield break;
            int close = s.IndexOf('}', open + 1);
            if (close < 0) yield break;
            string name = s[(open + 1)..close].Trim();
            if (name.Length > 0 && seen.Add(name)) yield return name;
            i = close + 1;
        }
    }

    private static string UniqueOperationId(string method, string path, string name, HashSet<string> used)
    {
        var sb = new StringBuilder();
        string source = name.Length > 0 ? name : method + " " + path;
        foreach (char c in source)
            sb.Append(char.IsLetterOrDigit(c) ? c : '_');
        string candidate = method + "_" + sb.ToString().Trim('_');
        if (candidate.Length == 0) candidate = method;
        string unique = candidate;
        for (int n = 2; !used.Add(unique); n++) unique = candidate + "_" + n;
        return unique;
    }

    // -------------------------------------------------------------- .http file

    /// <summary>
    /// Writes the .http / REST Client format understood by the VS Code REST Client
    /// extension and by JetBrains IDEs. It shares BruceEDR's {{variable}} syntax,
    /// so collection variables become @name assignments and the requests need no rewriting.
    /// </summary>
    public static string ToHttpFile(ApiCollection collection)
    {
        var sb = new StringBuilder();
        void Line(string s = "") => sb.Append(s).Append('\n');

        Line("# " + collection.Name);
        if (collection.Description.Length > 0)
            foreach (var l in SplitLines(collection.Description)) Line("# " + l);
        Line("# Exported by BruceEDR API Studio. Credentials are replaced with " + RedactedPlaceholder + ".");
        Line("# Request bodies are exported verbatim and may still contain sensitive data.");
        Line();

        foreach (var kv in collection.Variables.OrderBy(k => k.Key, StringComparer.Ordinal))
            Line("@" + kv.Key + " = " + (IsSecretName(kv.Key) && kv.Value.Length > 0 ? RedactedPlaceholder : kv.Value));
        if (collection.Variables.Count > 0) Line();

        foreach (var (tag, r) in WalkTagged(collection.Root, ""))
        {
            string prefix = r.Disabled ? "# " : "";
            Line("### " + (tag.Length > 0 ? tag + " / " : "") + r.DisplayName + (r.Disabled ? "  (disabled)" : ""));
            if (r.Description.Length > 0)
                foreach (var l in SplitLines(r.Description)) Line("# " + l);

            string url = r.Url;
            var enabled = r.Query.Where(q => q.Enabled).ToList();
            if (r.Auth.Kind == ApiAuthKind.ApiKeyQuery && r.Auth.KeyName.Length > 0)
                enabled.Add(new ApiKeyValue { Name = r.Auth.KeyName, Value = RedactedPlaceholder });
            if (enabled.Count > 0)
                url += (url.Contains('?') ? "&" : "?") +
                       string.Join("&", enabled.Select(q => q.Name + "=" + RedactByName(q.Name, q.Value)));

            Line(prefix + r.Method + " " + url);

            foreach (var h in r.Headers)
                Line((h.Enabled ? prefix : "# ") + h.Name + ": " + RedactByName(h.Name, h.Value));

            string? authHeader = r.Auth.Redacted().AuthorizationHeader();
            if (authHeader is not null) Line(prefix + "Authorization: " + authHeader);
            else if (r.Auth.Kind == ApiAuthKind.ApiKeyHeader && r.Auth.KeyName.Length > 0)
                Line(prefix + r.Auth.KeyName + ": " + RedactedPlaceholder);

            string body = HttpBodyText(r.Body, out string? contentType);
            if (contentType is not null &&
                !r.Headers.Any(h => h.Enabled && string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase)))
                Line(prefix + "Content-Type: " + contentType);

            if (body.Length > 0)
            {
                Line();
                foreach (var l in SplitLines(body)) Line(prefix + l);
            }

            // A disabled request is commented out rather than dropped so the operator can
            // see it exists; the query parameters of a disabled request are still redacted.
            Line();
        }

        return sb.ToString();
    }

    private static string HttpBodyText(ApiBody body, out string? contentType)
    {
        contentType = body.Kind == ApiBodyKind.None ? null : body.EffectiveContentType();
        switch (body.Kind)
        {
            case ApiBodyKind.None:
                return "";
            case ApiBodyKind.Json:
            case ApiBodyKind.Raw:
                return body.Text;
            case ApiBodyKind.UrlEncoded:
                return string.Join("&", body.Form.Where(f => f.Enabled)
                    .Select(f => f.Name + "=" + RedactByName(f.Name, f.Value)));
            case ApiBodyKind.Multipart:
                // Multipart needs an explicit boundary the exporter cannot know; listing
                // the fields is more useful than emitting a body that will not parse.
                contentType = null;
                return "# multipart fields (add a boundary by hand): " +
                       string.Join(", ", body.Form.Select(f => f.Name + "=" + RedactByName(f.Name, f.Value)));
            case ApiBodyKind.File:
                return "< " + body.FilePath;
            default:
                return "";
        }
    }

    // -------------------------------------------------------------- markdown

    /// <summary>
    /// Renders the collection as human-readable Markdown for a report or a wiki page.
    /// Everything the name-based redaction considers a credential is masked, including
    /// collection variables, because these documents get pasted into tickets.
    /// </summary>
    public static string ToMarkdown(ApiCollection collection)
    {
        var sb = new StringBuilder();
        void Line(string s = "") => sb.Append(s).Append('\n');

        Line("# " + collection.Name);
        Line();
        if (collection.Description.Length > 0) { Line(collection.Description); Line(); }
        Line($"{collection.RequestCount} request(s). Credential values are shown as `{RedactedPlaceholder}`; " +
             "request bodies are reproduced verbatim and may still contain sensitive data.");
        Line();

        if (collection.Variables.Count > 0)
        {
            Line("## Variables");
            Line();
            Line("| Name | Value |");
            Line("| --- | --- |");
            foreach (var kv in collection.Variables.OrderBy(k => k.Key, StringComparer.Ordinal))
                Line("| `" + kv.Key + "` | " +
                     Cell(IsSecretName(kv.Key) && kv.Value.Length > 0 ? RedactedPlaceholder : kv.Value) + " |");
            Line();
        }

        foreach (var (tag, r) in WalkTagged(collection.Root, ""))
        {
            Line("## " + (tag.Length > 0 ? tag + " / " : "") + r.DisplayName + (r.Disabled ? " (disabled)" : ""));
            Line();
            Line("`" + r.Method + " " + r.Url + "`");
            Line();
            if (r.Description.Length > 0) { Line(r.Description); Line(); }

            if (r.Auth.Kind != ApiAuthKind.None)
            {
                var a = r.Auth.Redacted();
                string detail = a.Kind switch
                {
                    ApiAuthKind.Basic => "user `" + Cell(a.Username) + "`",
                    ApiAuthKind.ApiKeyHeader => "header `" + Cell(a.KeyName) + "`",
                    ApiAuthKind.ApiKeyQuery => "query parameter `" + Cell(a.KeyName) + "`",
                    _ => ""
                };
                Line("Auth: **" + a.Kind + "**" + (detail.Length > 0 ? " (" + detail + ")" : "") +
                     " -- the secret is not included in this document.");
                Line();
            }

            WriteMarkdownTable(Line, "Headers", r.Headers);
            WriteMarkdownTable(Line, "Query", r.Query);

            if (r.Body.Kind != ApiBodyKind.None)
            {
                Line("Body (" + r.Body.Kind + ", `" + r.Body.EffectiveContentType() + "`):");
                Line();
                if (r.Body.Kind is ApiBodyKind.UrlEncoded or ApiBodyKind.Multipart)
                {
                    WriteMarkdownTable(Line, "", r.Body.Form);
                }
                else if (r.Body.Kind == ApiBodyKind.File)
                {
                    Line("File: `" + r.Body.FilePath + "`");
                    Line();
                }
                else
                {
                    Line("```");
                    foreach (var l in SplitLines(r.Body.Text)) Line(l);
                    Line("```");
                    Line();
                }
            }

            if (r.Assertions.Count > 0)
            {
                Line("Assertions:");
                Line();
                foreach (var a in r.Assertions) Line("- " + a.DisplayName);
                Line();
            }
        }

        return sb.ToString();
    }

    private static void WriteMarkdownTable(Action<string> line, string heading, IReadOnlyList<ApiKeyValue> items)
    {
        if (items.Count == 0) return;
        if (heading.Length > 0) { line(heading + ":"); line(""); }
        line("| Name | Value | Enabled |");
        line("| --- | --- | --- |");
        foreach (var kv in items)
            line("| `" + Cell(kv.Name) + "` | " + Cell(RedactByName(kv.Name, kv.Value)) + " | " +
                 (kv.Enabled ? "yes" : "no") + " |");
        line("");
    }

    // Pipes and newlines would break out of a Markdown table cell.
    private static string Cell(string value) =>
        value.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");

    private static IEnumerable<string> SplitLines(string text) =>
        text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
}

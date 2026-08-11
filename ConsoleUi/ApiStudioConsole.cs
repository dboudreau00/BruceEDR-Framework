using System.Text;
using ProcessShield.Api;
using ProcessShield.Core;
using ProcessShield.Hosting;

namespace ProcessShield.ConsoleUi;

/// <summary>
/// The analyst-facing half of API Studio: import a collection (Postman / OpenAPI / HAR /
/// curl), or build one straight from the endpoints ProcessShield actually observed this
/// machine talking to, then send, assert, grade and export.
///
/// Everything here is gated by <see cref="ApiSafetyPolicy"/>. Out of the box that policy
/// allows loopback only and refuses state-changing verbs, because an EDR shipping an
/// unrestricted HTTP client that anyone with console access can point anywhere would be a
/// liability rather than a feature. Widening it is a deliberate edit to shield.config.json.
/// </summary>
public sealed class ApiStudioConsole
{
    private readonly Composition _composition;
    private readonly Logger _log;

    private ApiCollection _collection = new();
    private readonly Dictionary<string, string> _variables = new(StringComparer.OrdinalIgnoreCase);
    private ApiRunResult? _lastRun;
    private ApiResponse? _lastResponse;
    private ApiRequest? _lastRequest;

    public ApiStudioConsole(Composition composition, Logger log)
    {
        _composition = composition;
        _log = log;
    }

    private ApiSafetyPolicy Policy => _composition.ApiPolicy;
    private IReadOnlyList<ApiRequest> Requests => _collection.Requests().ToArray();

    /// <summary>Dispatches an <c>api ...</c> console command. Returns false for unknown verbs.</summary>
    public bool Handle(string argument)
    {
        var parts = Split(argument, 2);
        string verb = parts.Length > 0 ? parts[0].ToLowerInvariant() : "help";
        string rest = parts.Length > 1 ? parts[1] : "";

        switch (verb)
        {
            case "" or "help": PrintHelp(); return true;
            case "policy": PrintPolicy(); return true;
            case "import": Import(rest); return true;
            case "curl": ImportCurl(rest); return true;
            case "surface": FromSurface(rest); return true;
            case "list" or "ls": ListRequests(); return true;
            case "show": Show(rest); return true;
            case "send": Send(rest); return true;
            case "run": Run(rest); return true;
            case "report": Report(rest); return true;
            case "export": Export(rest); return true;
            case "env": Env(rest); return true;
            case "analyze": AnalyzeLast(); return true;
            default:
                Write($"unknown api command '{verb}'. try 'api help'.");
                return true;
        }
    }

    // ------------------------------------------------------------------ import

    private void Import(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) { Write("usage: api import <file>"); return; }
        string full = Path.GetFullPath(path.Trim('"'));
        if (!File.Exists(full)) { Write($"no such file: {full}"); return; }

        string content;
        try { content = File.ReadAllText(full); }
        catch (Exception ex) { Write("read failed: " + ex.Message); return; }

        var result = ApiImporters.Auto(content, Path.GetFileName(full));
        if (!result.Ok || result.Collection is null)
        {
            Write("import failed: " + (result.Error ?? "unrecognised format"));
            return;
        }

        _collection = result.Collection;
        foreach (var kv in _collection.Variables) _variables[kv.Key] = kv.Value;

        Write($"imported '{_collection.Name}': {_collection.RequestCount} request(s), " +
              $"{_collection.Variables.Count} variable(s)");
        foreach (var w in result.Warnings.Take(10)) Write("  warning: " + w);
        if (result.Warnings.Count > 10) Write($"  ... and {result.Warnings.Count - 10} more warnings");
        ListRequests();
    }

    private void ImportCurl(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) { Write("usage: api curl <curl command line>"); return; }
        var request = ApiImporters.FromCurl(command);
        if (request is null) { Write("could not parse that curl command"); return; }

        var folder = _collection.Root;
        _collection = _collection with
        {
            Root = folder with { Requests = folder.Requests.Append(request).ToArray() }
        };
        Write($"added: {request.Method} {request.Url}");
    }

    /// <summary>
    /// Turns what the agent has actually watched processes connect to into a collection.
    /// This is the bridge that makes API Studio an EDR feature: the analyst does not have
    /// to know an endpoint exists to inspect it.
    /// </summary>
    private void FromSurface(string filter)
    {
        var endpoints = _composition.Host.SurfaceEndpoints();
        if (endpoints.Count == 0)
        {
            Write("no endpoints observed yet (needs the ETW network/DNS monitors and some traffic)");
            return;
        }

        var http = endpoints
            .Where(e => e.Scheme is "http" or "https")
            .Where(e => string.IsNullOrWhiteSpace(filter) ||
                        e.Host.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                        e.ProcessName.Contains(filter, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (http.Length == 0) { Write("no HTTP(S) endpoints matched"); return; }

        _collection = _composition.Surface.ToCollection("Observed API surface", http);
        Write($"built a collection from {http.Length} observed endpoint(s)");
        ListRequests();
    }

    // -------------------------------------------------------------------- view

    private void ListRequests()
    {
        var reqs = Requests;
        if (reqs.Count == 0) { Write("no requests loaded. try 'api import <file>' or 'api surface'."); return; }

        Write($"collection: {_collection.Name}  ({reqs.Count} request(s))");
        Write($"  {"#",-4} {"METHOD",-7} {"ASSERTS",-8} NAME / URL");
        for (int i = 0; i < reqs.Count; i++)
        {
            var r = reqs[i];
            string flag = r.Disabled ? " (disabled)" : "";
            Write($"  {i + 1,-4} {r.Method,-7} {r.Assertions.Count,-8} {Truncate(r.DisplayName, 90)}{flag}");
        }
        Write("  (api show N | api send N | api run)");
    }

    private void Show(string arg)
    {
        var r = Pick(arg);
        if (r is null) return;

        Write($"{r.Method} {r.Url}");
        if (!string.IsNullOrWhiteSpace(r.Description)) Write("  " + Truncate(r.Description, 200));
        foreach (var h in r.Headers.Where(h => h.Enabled))
            Write($"  header  {h.Name}: {Redact(h.Name, h.Value)}");
        foreach (var q in r.Query.Where(q => q.Enabled))
            Write($"  query   {q.Name}={Redact(q.Name, q.Value)}");
        if (r.Auth.Kind != ApiAuthKind.None) Write($"  auth    {r.Auth.Kind}");
        if (r.Body.Kind != ApiBodyKind.None)
            Write($"  body    {r.Body.Kind} ({r.Body.EffectiveContentType()}), {r.Body.Text.Length} char(s)");
        foreach (var a in r.Assertions) Write($"  assert  {a.DisplayName}");
        foreach (var c in r.Captures) Write($"  capture {c.Variable}");

        var unresolved = Templating.UnresolvedPlaceholders(r.Url, Variables());
        if (unresolved.Count > 0)
            Write("  unresolved variables: " + string.Join(", ", unresolved) + "  (set with 'api env set NAME VALUE')");
    }

    // -------------------------------------------------------------------- send

    private void Send(string arg)
    {
        var r = Pick(arg);
        if (r is null) return;

        using var client = new ApiClient(Policy);
        ApiResponse response;
        try { response = client.SendAsync(r, Variables()).GetAwaiter().GetResult(); }
        catch (Exception ex) { Write("send failed: " + ex.Message); return; }

        _lastRequest = r;
        _lastResponse = response;

        if (!response.Completed)
        {
            Write($"  ERROR  {response.Error}");
            return;
        }

        Write($"  {response.StatusCode} {response.ReasonPhrase}   {response.Elapsed.TotalMilliseconds:F0} ms   " +
              $"{response.BodyBytes} byte(s)");
        if (response.RedirectChain.Count > 0)
            Write("  redirects: " + string.Join(" -> ", response.RedirectChain));
        if (response.Tls is { } tls)
            Write($"  tls: {tls.Subject} issued by {tls.Issuer}, expires {tls.NotAfterUtc:yyyy-MM-dd} " +
                  $"({tls.DaysUntilExpiry(DateTime.UtcNow)}d), chain {(tls.ChainValid ? "valid" : "INVALID")}");

        foreach (var h in response.Headers.Take(20))
            Write($"  < {h.Name}: {Truncate(Redact(h.Name, h.Value), 120)}");

        string body = response.ContentType.Contains("json", StringComparison.OrdinalIgnoreCase)
            ? JsonQuery.Pretty(response.BodyText)
            : response.BodyText;
        Write("  --- body ---");
        foreach (var line in Truncate(body, 4000).Split('\n').Take(60)) Write("  " + line.TrimEnd());
        if (response.BodyTruncated) Write("  [body truncated by the response size cap]");

        var outcomes = AssertionEvaluator.Evaluate(r.Assertions, response);
        foreach (var o in outcomes)
            Write($"  {(o.Passed ? "PASS" : "FAIL")}  {o.Name}{(o.Passed ? "" : " -- " + o.Detail)}");

        AnalyzeLast();
    }

    private void AnalyzeLast()
    {
        if (_lastRequest is null || _lastResponse is null)
        {
            Write("nothing to analyze yet; run 'api send N' first");
            return;
        }

        var findings = EndpointAnalyzer.Analyze(_lastRequest, _lastResponse, DateTime.UtcNow);
        var (grade, score) = EndpointAnalyzer.Grade(findings);
        Write($"  --- endpoint analysis: grade {grade} ({score}/100), {findings.Count} finding(s) ---");
        foreach (var f in findings)
        {
            Write($"  [{f.Severity,-8}] {f.Title}");
            if (!string.IsNullOrWhiteSpace(f.Detail)) Write("             " + Truncate(f.Detail, 160));
            if (!string.IsNullOrWhiteSpace(f.Owasp)) Write("             " + f.Owasp);
        }
        if (findings.Count == 0) Write("  no issues found in this response");
    }

    // --------------------------------------------------------------------- run

    private void Run(string arg)
    {
        var reqs = Requests;
        if (reqs.Count == 0) { Write("no requests loaded"); return; }

        bool analyze = !arg.Contains("--no-analyze", StringComparison.OrdinalIgnoreCase);
        var env = new ApiEnvironment { Name = "console", Variables = new Dictionary<string, string>(_variables) };

        using var client = new ApiClient(Policy);
        var runner = new CollectionRunner(client);

        Write($"running {reqs.Count} request(s) at up to {Policy.MaxRequestsPerSecond:F1} req/s...");
        ApiRunResult result;
        try
        {
            result = runner.RunAsync(_collection, env, Policy, analyzeSecurity: analyze)
                           .GetAwaiter().GetResult();
        }
        catch (Exception ex) { Write("run failed: " + ex.Message); return; }

        _lastRun = result;
        foreach (var line in ApiReports.ToConsoleText(result).Split('\n')) Write(line.TrimEnd());
    }

    private void Report(string arg)
    {
        if (_lastRun is null) { Write("no run to report; use 'api run' first"); return; }
        var parts = Split(arg, 2);
        if (parts.Length < 2)
        {
            Write("usage: api report <json|junit|md|html> <path>");
            return;
        }

        string format = parts[0].ToLowerInvariant();
        string path = Path.GetFullPath(parts[1].Trim('"'));
        string content = format switch
        {
            "json" => ApiReports.ToJson(_lastRun),
            "junit" or "xml" => ApiReports.ToJUnitXml(_lastRun),
            "md" or "markdown" => ApiReports.ToMarkdown(_lastRun),
            "html" => ApiReports.ToHtml(_lastRun),
            _ => ""
        };
        if (content.Length == 0) { Write($"unknown report format '{format}'"); return; }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
            File.WriteAllText(path, content);
            Write($"wrote {format} report: {path} ({content.Length} bytes)");
        }
        catch (Exception ex) { Write("write failed: " + ex.Message); }
    }

    private void Export(string arg)
    {
        var parts = Split(arg, 3);
        if (parts.Length < 2)
        {
            Write("usage: api export <postman|openapi|http|md> <path>");
            Write("       api export curl <N>");
            return;
        }

        string format = parts[0].ToLowerInvariant();
        if (format == "curl")
        {
            var r = Pick(parts[1]);
            if (r is not null) Write(ApiExporters.ToCurl(r, Variables()));
            return;
        }

        string path = Path.GetFullPath(parts[1].Trim('"'));
        string content = format switch
        {
            "postman" => ApiExporters.ToPostman(_collection),
            "openapi" => ApiExporters.ToOpenApi(_collection, _collection.Name, "1.0.0"),
            "http" => ApiExporters.ToHttpFile(_collection),
            "md" or "markdown" => ApiExporters.ToMarkdown(_collection),
            _ => ""
        };
        if (content.Length == 0) { Write($"unknown export format '{format}'"); return; }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
            File.WriteAllText(path, content);
            Write($"exported {format}: {path} ({content.Length} bytes; secrets redacted)");
        }
        catch (Exception ex) { Write("write failed: " + ex.Message); }
    }

    // ---------------------------------------------------------------- env vars

    private void Env(string arg)
    {
        var parts = Split(arg, 3);
        string sub = parts.Length > 0 ? parts[0].ToLowerInvariant() : "list";

        switch (sub)
        {
            case "set" when parts.Length >= 3:
                _variables[parts[1]] = parts[2];
                Write($"{parts[1]} = {Redact(parts[1], parts[2])}");
                return;
            case "unset" when parts.Length >= 2:
                Write(_variables.Remove(parts[1]) ? $"removed {parts[1]}" : $"{parts[1]} was not set");
                return;
            case "clear":
                _variables.Clear();
                Write("cleared all variables");
                return;
            default:
                if (_variables.Count == 0) { Write("no variables set"); return; }
                foreach (var kv in _variables.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
                    Write($"  {kv.Key} = {Redact(kv.Key, kv.Value)}");
                return;
        }
    }

    private IReadOnlyDictionary<string, string> Variables()
        => Templating.Merge(
            Templating.BuiltIns(SystemClock.Instance),
            _collection.Variables,
            _variables);

    // ----------------------------------------------------------------- helpers

    private void PrintPolicy()
    {
        var p = Policy;
        Write("API Studio safety policy (edit api.studio in shield.config.json):");
        Write("  allowed hosts        : " + (p.AllowedHosts.Count == 0 ? "(none -- nothing can be sent)" : string.Join(", ", p.AllowedHosts)));
        Write("  mutating methods     : " + (p.AllowMutatingMethods ? "allowed" : "blocked (POST/PUT/PATCH/DELETE)"));
        Write("  plain http           : " + (p.AllowInsecureHttp ? "allowed" : "blocked outside loopback"));
        Write($"  rate limit           : {p.MaxRequestsPerSecond:F1} request(s)/second");
        Write($"  max response         : {p.MaxResponseBytes / 1024} KiB");
    }

    private ApiRequest? Pick(string arg)
    {
        var reqs = Requests;
        if (reqs.Count == 0) { Write("no requests loaded"); return null; }
        if (!int.TryParse(arg.Trim(), out int n) || n < 1 || n > reqs.Count)
        {
            Write($"give a request number between 1 and {reqs.Count} (see 'api list')");
            return null;
        }
        return reqs[n - 1];
    }

    private static string[] Split(string s, int max)
        => s.Split(' ', max, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// Masks anything whose name suggests a credential. The console is frequently
    /// screen-shared during an investigation; a bearer token scrolling past is a real
    /// leak, so redaction is the default and there is deliberately no flag to disable it.
    /// </summary>
    private static string Redact(string name, string value)
    {
        if (value.Length == 0) return value;
        bool secret = name.Contains("auth", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("token", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("key", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("secret", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("password", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("cookie", StringComparison.OrdinalIgnoreCase);
        if (!secret) return value;
        return value.Length <= 6 ? "***" : value[..4] + "***" + value[^2..];
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + $"... [{s.Length} chars total]";

    private void Write(string line) => _log.Raw("  " + line);

    private void PrintHelp() => _log.Raw(new StringBuilder()
        .AppendLine()
        .AppendLine("  API Studio -- inspect and test HTTP APIs from inside the agent")
        .AppendLine("  ---------------------------------------------------------------")
        .AppendLine("  api surface [filter]      build a collection from endpoints this host was seen using")
        .AppendLine("  api import <file>         load a Postman v2.1 / OpenAPI / Swagger / HAR file")
        .AppendLine("  api curl <command>        add one request from a curl command line")
        .AppendLine("  api list                  list loaded requests")
        .AppendLine("  api show N                show request N in full")
        .AppendLine("  api send N                send request N, then grade the response")
        .AppendLine("  api run [--no-analyze]    run the whole collection with assertions")
        .AppendLine("  api analyze               re-grade the last response")
        .AppendLine("  api report <fmt> <path>   write json | junit | md | html")
        .AppendLine("  api export <fmt> <path>   write postman | openapi | http | md")
        .AppendLine("  api export curl N         print request N as a curl command")
        .AppendLine("  api env [set K V|unset K|clear]   manage template variables")
        .AppendLine("  api policy                show what the safety policy currently permits")
        .ToString());
}

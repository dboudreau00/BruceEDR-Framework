using ProcessShield.Core;

namespace ProcessShield.Api;

// ---------------------------------------------------------------------------
// Runs a whole collection: resolve variables, send, assert, capture, analyze.
//
// Design notes:
//  * The run is a pipeline of failures-that-do-not-stop-the-run. A bad URL, a
//    refused host, a client that throws, an assertion evaluator that throws, a
//    progress handler that throws -- each is recorded and the run continues.
//    Anything else and one broken request in a 200-request regression suite
//    destroys the whole report.
//  * Captures deliberately feed the NEXT request, never the current one. That
//    keeps a run a straight line with no re-entrancy: login -> token -> call.
//  * The runner re-checks ApiSafetyPolicy itself rather than trusting the client
//    to do it. IApiClient has no policy in its signature, so a stub, a replay
//    client or a future implementation could quietly skip the check; a safety
//    control that only one implementation enforces is not a control.
// ---------------------------------------------------------------------------

/// <summary>
/// Executes every enabled request in an <see cref="ApiCollection"/> in order and
/// accumulates an <see cref="ApiRunResult"/>.
/// </summary>
public sealed class CollectionRunner
{
    private readonly IApiClient _client;
    private readonly IClock _clock;

    public CollectionRunner(IApiClient client, IClock? clock = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _clock = clock ?? SystemClock.Instance;
    }

    /// <summary>
    /// Seam for the rate limiter. Tests replace it so throttling is asserted without
    /// spending real wall-clock time; production uses <see cref="Task.Delay(TimeSpan, CancellationToken)"/>.
    /// </summary>
    internal Func<TimeSpan, CancellationToken, Task> Sleep { get; set; } =
        static (delay, ct) => Task.Delay(delay, ct);

    /// <summary>
    /// Runs the collection. Never throws for a request-level failure; the only way out
    /// other than a complete result is a caller cancelling, which still returns the
    /// partial result gathered so far.
    /// </summary>
    /// <param name="analyzeSecurity">
    /// When false the endpoint analyzer is skipped entirely. Worth turning off for a
    /// large functional regression run where only the assertions matter.
    /// </param>
    public async Task<ApiRunResult> RunAsync(ApiCollection collection, ApiEnvironment environment,
                                             ApiSafetyPolicy policy, IProgress<ApiExecution>? progress = null,
                                             bool analyzeSecurity = true, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(collection);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(policy);

        DateTime startedUtc = _clock.UtcNow;
        var executions = new List<ApiExecution>();

        // Runtime captures accumulate across the run and outrank every static source.
        var captures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        IReadOnlyDictionary<string, string> builtIns = SafeBuiltIns();

        TimeSpan interval = policy.MaxRequestsPerSecond > 0
            ? TimeSpan.FromSeconds(1.0 / policy.MaxRequestsPerSecond)
            : TimeSpan.Zero;
        DateTime? lastStart = null;

        foreach (var request in collection.Requests())
        {
            if (ct.IsCancellationRequested) break;
            if (request.Disabled) continue;

            if (interval > TimeSpan.Zero && lastStart is not null)
            {
                TimeSpan wait = interval - (_clock.UtcNow - lastStart.Value);
                if (wait > TimeSpan.Zero)
                {
                    try { await Sleep(wait, ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                }
            }
            if (ct.IsCancellationRequested) break;
            lastStart = _clock.UtcNow;

            ApiRequest effective = ApplyCollectionDefaults(request, collection);
            IReadOnlyDictionary<string, string> variables =
                SafeMerge(builtIns, collection.Variables, environment.Variables, captures);

            ApiExecution execution = await RunOneAsync(effective, variables, policy, analyzeSecurity, ct)
                                            .ConfigureAwait(false);

            // A cancellation that landed mid-send produces a response we do not want in the
            // report: it says more about the operator hitting stop than about the endpoint.
            if (ct.IsCancellationRequested && !execution.Response.Completed) break;

            executions.Add(execution);

            foreach (var kv in execution.Captured) captures[kv.Key] = kv.Value;

            try { progress?.Report(execution); }
            catch { /* a UI callback must not be able to abort a run */ }
        }

        return new ApiRunResult
        {
            CollectionName = collection.Name,
            EnvironmentName = environment.Name,
            StartedUtc = startedUtc,
            Duration = _clock.UtcNow - startedUtc,
            Executions = executions
        };
    }

    // ---------------------------------------------------------------- one request

    private async Task<ApiExecution> RunOneAsync(ApiRequest request, IReadOnlyDictionary<string, string> variables,
                                                 ApiSafetyPolicy policy, bool analyzeSecurity, CancellationToken ct)
    {
        DateTime started = _clock.UtcNow;

        // Resolve once here purely to fill ResolvedUrl and to run the policy check. The
        // client resolves again internally; that duplication is deliberate, because the
        // client is an interface and this class must not depend on any implementation
        // exposing what it resolved.
        ApiRequest resolved = request;
        string resolvedUrl = request.Url;
        string? preflightError = null;

        try
        {
            resolved = Templating.Resolve(request, variables);
            if (ApiClient.TryBuildRequestUri(resolved, out Uri? uri, out string urlError) && uri is not null)
            {
                resolvedUrl = uri.AbsoluteUri;
                ApiClient.TryNormalizeMethod(resolved.Method, out string method, out _);
                string? refusal = policy.Refuse(method, uri);
                if (refusal is not null) preflightError = "blocked by API safety policy: " + refusal;
            }
            else
            {
                resolvedUrl = resolved.Url;
                preflightError = urlError;
            }
        }
        catch (Exception ex)
        {
            preflightError = "variable substitution failed: " + ex.Message;
        }

        ApiResponse response;
        if (preflightError is not null)
        {
            response = new ApiResponse
            {
                Error = preflightError,
                StartedUtc = started,
                FinalUrl = resolvedUrl,
                Elapsed = TimeSpan.Zero
            };
        }
        else
        {
            try
            {
                response = await _client.SendAsync(request, variables, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                response = new ApiResponse { Error = "canceled", StartedUtc = started, FinalUrl = resolvedUrl };
            }
            catch (Exception ex)
            {
                // An IApiClient is allowed to be badly behaved; the run is not.
                response = new ApiResponse
                {
                    Error = "client failed: " + ex.Message,
                    StartedUtc = started,
                    FinalUrl = resolvedUrl
                };
            }
        }

        return new ApiExecution
        {
            Request = request,
            ResolvedUrl = resolvedUrl,
            Response = response,
            Assertions = EvaluateAssertions(resolved, response),
            Captured = response.Completed ? ApplyCaptures(resolved, response) : Empty(),
            Findings = analyzeSecurity && response.Completed ? Analyze(resolved, response) : Array.Empty<ApiFinding>()
        };
    }

    // Assertions run even for a failed request: "the endpoint was unreachable" has to
    // show up as a red test, not as an empty one that quietly passes.
    private static IReadOnlyList<AssertionOutcome> EvaluateAssertions(ApiRequest request, ApiResponse response)
    {
        if (request.Assertions.Count == 0) return Array.Empty<AssertionOutcome>();
        try
        {
            return AssertionEvaluator.Evaluate(request.Assertions, response);
        }
        catch (Exception ex)
        {
            return new[]
            {
                new AssertionOutcome
                {
                    Name = "assertion evaluation",
                    Passed = false,
                    Detail = "the assertion evaluator threw: " + ex.Message
                }
            };
        }
    }

    private static IReadOnlyDictionary<string, string> ApplyCaptures(ApiRequest request, ApiResponse response)
    {
        if (request.Captures.Count == 0) return Empty();
        try { return CaptureEngine.Apply(request.Captures, response); }
        catch { return Empty(); }   // a capture that cannot be extracted is not a run failure
    }

    private IReadOnlyList<ApiFinding> Analyze(ApiRequest request, ApiResponse response)
    {
        try { return EndpointAnalyzer.Analyze(request, response, _clock.UtcNow); }
        catch { return Array.Empty<ApiFinding>(); }
    }

    // --------------------------------------------------------------- inheritance

    /// <summary>
    /// Folds collection-level defaults into one request. Request-level settings always
    /// win: a default is a convenience, never an override of something explicit.
    /// </summary>
    internal static ApiRequest ApplyCollectionDefaults(ApiRequest request, ApiCollection collection)
    {
        var headers = request.Headers;
        if (collection.DefaultHeaders.Count > 0)
        {
            var merged = new List<ApiKeyValue>(request.Headers);
            foreach (var d in collection.DefaultHeaders)
            {
                if (!d.Enabled || string.IsNullOrWhiteSpace(d.Name)) continue;
                bool present = merged.Any(h => string.Equals(h.Name, d.Name, StringComparison.OrdinalIgnoreCase));
                if (!present) merged.Add(d);
            }
            headers = merged;
        }

        ApiAuth auth = request.Auth.Kind == ApiAuthKind.None ? collection.Auth : request.Auth;

        return request with { Headers = headers, Auth = auth };
    }

    // ------------------------------------------------------------------- helpers

    private IReadOnlyDictionary<string, string> SafeBuiltIns()
    {
        try { return Templating.BuiltIns(_clock); }
        catch { return Empty(); }
    }

    private static IReadOnlyDictionary<string, string> SafeMerge(params IReadOnlyDictionary<string, string>?[] sources)
    {
        try { return Templating.Merge(sources); }
        catch
        {
            // Merge is pure, so this should be unreachable; falling back keeps a broken
            // resolver from taking the whole run with it.
            var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in sources)
            {
                if (s is null) continue;
                foreach (var kv in s) merged[kv.Key] = kv.Value;
            }
            return merged;
        }
    }

    private static IReadOnlyDictionary<string, string> Empty() =>
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

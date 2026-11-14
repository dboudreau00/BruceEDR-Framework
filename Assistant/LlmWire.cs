using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using BruceEDR.Api;

namespace BruceEDR.Assistant;

public enum LlmProvider { Claude, Gemini, Grok, OpenAI }

/// <summary>One parsed piece of a streamed answer.</summary>
public sealed record LlmChunk
{
    public string Text { get; init; } = "";
    public bool Done { get; init; }
    public bool Refused { get; init; }
    public string Error { get; init; } = "";
    public string StopReason { get; init; } = "";

    public static readonly LlmChunk None = new();
}

/// <summary>A fully built provider request. <see cref="Headers"/> carries the key: never log it.</summary>
public sealed record LlmRequest(Uri Uri, IReadOnlyList<ApiKeyValue> Headers, string Body);

/// <summary>
/// Request shapes and streamed-response parsing for the four providers, written against their
/// own REST documentation (no SDKs: one HTTP client for the whole agent). Endpoints are fixed
/// here and nowhere else, so a configured key can only ever be sent to its own provider.
/// </summary>
public static class LlmWire
{
    public const int MaxOutputTokens = 8000;

    // No '/', ':' or '?': Gemini puts the model in the URL path, and those would change the call.
    private static readonly Regex ModelPattern = new("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", RegexOptions.CultureInvariant);

    public static string DisplayName(LlmProvider p) => p switch
    {
        LlmProvider.Claude => "Claude",
        LlmProvider.Gemini => "Gemini",
        LlmProvider.Grok => "Grok",
        _ => "OpenAI",
    };

    public static string Vendor(LlmProvider p) => p switch
    {
        LlmProvider.Claude => "Anthropic",
        LlmProvider.Gemini => "Google",
        LlmProvider.Grok => "xAI",
        _ => "OpenAI",
    };

    public static string DefaultModel(LlmProvider p) => p switch
    {
        LlmProvider.Claude => "claude-opus-5-5",
        // Fastest stable Gemini: a full answer in a few seconds (3.8 Flash took over a minute).
        LlmProvider.Gemini => "gemini-3.5-flash-lite",
        LlmProvider.Grok => "grok-4.7",
        _ => "gpt-6.1-sol",
    };

    public static string Host(LlmProvider p) => p switch
    {
        LlmProvider.Claude => "api.anthropic.com",
        LlmProvider.Gemini => "generativelanguage.googleapis.com",
        LlmProvider.Grok => "api.x.ai",
        _ => "api.openai.com",
    };

    /// <summary>The only hosts the assistant may reach: the four providers, https, POST.</summary>
    public static ApiSafetyPolicy Policy { get; } = new()
    {
        AllowedHosts = Enum.GetValues<LlmProvider>().Select(Host).ToArray(),
        AllowMutatingMethods = true,
        AllowInsecureHttp = false,
        MaxRequestsPerSecond = 2,
        MaxResponseBytes = 4L * 1024 * 1024,
    };

    public static bool IsValidModel(string? model) => model is not null && ModelPattern.IsMatch(model);

    /// <param name="baseOverride">Tests only: points the request at a loopback server.</param>
    public static LlmRequest Build(LlmProvider provider, string model, string apiKey, string system, string user,
        Uri? baseOverride = null)
    {
        if (!IsValidModel(model)) throw new ArgumentException("the model name has characters a model id cannot contain", nameof(model));
        if (string.IsNullOrWhiteSpace(apiKey) || apiKey.Any(char.IsControl))
            throw new ArgumentException("the API key is empty or malformed", nameof(apiKey));
        string root = (baseOverride?.ToString() ?? "https://" + Host(provider) + "/").TrimEnd('/');
        apiKey = apiKey.Trim();

        switch (provider)
        {
            case LlmProvider.Claude:
            {
                var body = new JsonObject
                {
                    ["model"] = model,
                    ["max_tokens"] = MaxOutputTokens,
                    ["stream"] = true,
                    ["system"] = system,
                    ["messages"] = new JsonArray(new JsonObject { ["role"] = "user", ["content"] = user }),
                };
                var headers = new List<ApiKeyValue>
                {
                    ApiKeyValue.Of("x-api-key", apiKey),
                    ApiKeyValue.Of("anthropic-version", "2026-10-21"),
                };
                // Short plain-English answers: low effort keeps them quick on current models.
                if (Regex.IsMatch(model, "^claude-(opus|fable|mythos|sonnet|haiku)-5", RegexOptions.CultureInvariant))
                    body["output_config"] = new JsonObject { ["effort"] = "low" };
                // Security logs can trip a safety classifier; let the API re-run a decline on a fallback model.
                if (Regex.IsMatch(model, "^claude-(fable-5-[12]|opus-5-5|opus-5|sonnet-5-5)$", RegexOptions.CultureInvariant))
                {
                    body["fallbacks"] = "default";
                    headers.Add(ApiKeyValue.Of("anthropic-beta", "server-side-fallback-2026-07-01"));
                }
                return new LlmRequest(new Uri(root + "/v1/messages"), headers, body.ToJsonString());
            }
            case LlmProvider.Gemini:
            {
                var body = new JsonObject
                {
                    ["systemInstruction"] = new JsonObject { ["parts"] = new JsonArray(new JsonObject { ["text"] = system }) },
                    ["contents"] = new JsonArray(new JsonObject
                    {
                        ["role"] = "user",
                        ["parts"] = new JsonArray(new JsonObject { ["text"] = user }),
                    }),
                    ["generationConfig"] = new JsonObject { ["maxOutputTokens"] = MaxOutputTokens },
                };
                // Gemini 3 Flash and Pro think at length by default and can stay silent for minutes;
                // "low" is the lowest level they accept ("minimal" is a 400 on 3.8 Flash).
                if (Regex.IsMatch(model, @"^gemini-3(\.\d+)?-(flash|pro)(-preview)?$", RegexOptions.CultureInvariant))
                    ((JsonObject)body["generationConfig"]!)["thinkingConfig"] = new JsonObject { ["thinkingLevel"] = "low" };
                return new LlmRequest(new Uri($"{root}/v1beta/models/{model}:streamGenerateContent?alt=sse"),
                    new[] { ApiKeyValue.Of("x-goog-api-key", apiKey) }, body.ToJsonString());
            }
            case LlmProvider.Grok:
            {
                var body = new JsonObject
                {
                    ["model"] = model,
                    ["stream"] = true,
                    ["messages"] = new JsonArray(
                        new JsonObject { ["role"] = "system", ["content"] = system },
                        new JsonObject { ["role"] = "user", ["content"] = user }),
                };
                return new LlmRequest(new Uri(root + "/v1/chat/completions"),
                    new[] { ApiKeyValue.Of("Authorization", "Bearer " + apiKey) }, body.ToJsonString());
            }
            default:
            {
                var body = new JsonObject
                {
                    ["model"] = model,
                    ["instructions"] = system,
                    ["input"] = user,
                    ["stream"] = true,
                    ["max_output_tokens"] = MaxOutputTokens,
                };
                return new LlmRequest(new Uri(root + "/v1/responses"),
                    new[] { ApiKeyValue.Of("Authorization", "Bearer " + apiKey) }, body.ToJsonString());
            }
        }
    }

    /// <summary>Parses one line of a server-sent event stream. Non-data lines yield <see cref="LlmChunk.None"/>.</summary>
    public static LlmChunk ParseLine(LlmProvider provider, string line)
    {
        if (!line.StartsWith("data:", StringComparison.Ordinal)) return LlmChunk.None;
        string data = line[5..].Trim();
        if (data.Length == 0) return LlmChunk.None;
        if (data == "[DONE]") return new LlmChunk { Done = true };

        JsonNode? node;
        try { node = JsonNode.Parse(data); }
        catch (JsonException) { return LlmChunk.None; }
        if (node is not JsonObject o) return LlmChunk.None;

        return provider switch
        {
            LlmProvider.Claude => ParseClaude(o),
            LlmProvider.Gemini => ParseGemini(o),
            LlmProvider.Grok => ParseChatCompletions(o),
            _ => ParseResponses(o),
        };
    }

    private static string Str(JsonNode? n) => n is JsonValue v && v.TryGetValue(out string? s) ? s ?? "" : "";

    private static LlmChunk ParseClaude(JsonObject o)
    {
        switch (Str(o["type"]))
        {
            case "content_block_delta":
                var delta = o["delta"] as JsonObject;
                return Str(delta?["type"]) == "text_delta" ? new LlmChunk { Text = Str(delta?["text"]) } : LlmChunk.None;
            case "message_delta":
                string stop = Str((o["delta"] as JsonObject)?["stop_reason"]);
                return stop.Length == 0 ? LlmChunk.None : new LlmChunk { StopReason = stop, Refused = stop == "refusal" };
            case "message_stop":
                return new LlmChunk { Done = true };
            case "error":
                return new LlmChunk { Error = Str((o["error"] as JsonObject)?["message"]) is { Length: > 0 } m ? m : "the provider reported an error" };
            default:
                return LlmChunk.None;
        }
    }

    private static LlmChunk ParseGemini(JsonObject o)
    {
        string block = Str((o["promptFeedback"] as JsonObject)?["blockReason"]);
        if (block.Length > 0) return new LlmChunk { Refused = true, StopReason = block, Done = true };
        if (o["error"] is JsonObject err) return new LlmChunk { Error = Str(err["message"]) };

        var candidate = (o["candidates"] as JsonArray)?.FirstOrDefault() as JsonObject;
        if (candidate is null) return LlmChunk.None;
        var text = string.Concat(((candidate["content"] as JsonObject)?["parts"] as JsonArray ?? new JsonArray())
            .OfType<JsonObject>()
            .Where(p => p["thought"] is not JsonValue t || !t.TryGetValue(out bool b) || !b)
            .Select(p => Str(p["text"])));
        string finish = Str(candidate["finishReason"]);
        bool refused = finish is "SAFETY" or "PROHIBITED_CONTENT" or "BLOCKLIST" or "SPII" or "RECITATION";
        return new LlmChunk { Text = text, StopReason = finish, Refused = refused };
    }

    private static LlmChunk ParseChatCompletions(JsonObject o)
    {
        if (o["error"] is JsonObject err) return new LlmChunk { Error = Str(err["message"]) };
        var choice = (o["choices"] as JsonArray)?.FirstOrDefault() as JsonObject;
        if (choice is null) return LlmChunk.None;
        string text = Str((choice["delta"] as JsonObject)?["content"]);
        string finish = Str(choice["finish_reason"]);
        return new LlmChunk { Text = text, StopReason = finish, Refused = finish == "content_filter" };
    }

    private static LlmChunk ParseResponses(JsonObject o)
    {
        switch (Str(o["type"]))
        {
            case "response.output_text.delta":
                return new LlmChunk { Text = Str(o["delta"]) };
            case "response.refusal.delta":
            case "response.refusal.done":
                return new LlmChunk { Refused = true, StopReason = "refusal" };
            case "response.completed":
                return new LlmChunk { Done = true, StopReason = "completed" };
            case "response.incomplete":
                return new LlmChunk { Done = true, StopReason = "incomplete" };
            case "response.failed":
                return new LlmChunk { Error = Str(((o["response"] as JsonObject)?["error"] as JsonObject)?["message"]) is { Length: > 0 } m ? m : "the response failed" };
            case "error":
                return new LlmChunk { Error = Str(o["message"]) is { Length: > 0 } e ? e : "the provider reported an error" };
            default:
                return LlmChunk.None;
        }
    }

    /// <summary>The provider's own error message from a non-2xx body, without echoing anything we sent.</summary>
    public static string ErrorMessage(string body)
    {
        try
        {
            // Gemini wraps some errors in an array; indexing an array by name would throw.
            var node = JsonNode.Parse(body);
            var err = node switch
            {
                JsonObject o => o["error"],
                JsonArray a when a.FirstOrDefault() is JsonObject first => first["error"],
                _ => null,
            };
            string msg = err is JsonObject eo ? Str(eo["message"]) : Str(err);
            if (msg.Length > 0) return msg.Length > 300 ? msg[..300] : msg;
        }
        catch (JsonException) { }
        return "";
    }
}

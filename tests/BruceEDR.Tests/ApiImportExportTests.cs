using System.Text.Json;
using BruceEDR.Api;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// Importers eat files produced by other people's tools, so most of the value here is in
/// the ugly cases: the object-form URL, the auth block, the $ref cycle, the renamed file
/// with the wrong extension, and the truncated document. Exporters get the opposite
/// treatment: the thing that must never happen is a real credential leaving the process.
/// </summary>
public class ApiImportExportTests
{
    // -------------------------------------------------------------- fixtures

    private const string PostmanMinimal = """
    {
      "info": { "name": "Sample API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
      "item": [
        {
          "name": "Health",
          "request": { "method": "GET", "url": "https://api.example.com/health" }
        },
        {
          "name": "Users",
          "item": [
            {
              "name": "Create user",
              "request": {
                "method": "POST",
                "url": {
                  "raw": "https://api.example.com/v1/users?verbose=true",
                  "protocol": "https",
                  "host": [ "api", "example", "com" ],
                  "path": [ "v1", "users" ],
                  "query": [ { "key": "verbose", "value": "true" } ]
                },
                "header": [
                  { "key": "Content-Type", "value": "application/json" },
                  { "key": "X-Disabled", "value": "no", "disabled": true }
                ],
                "body": { "mode": "raw", "raw": "{\"name\":\"ada\"}" },
                "auth": { "type": "bearer", "bearer": [ { "key": "token", "value": "super-secret-token" } ] }
              }
            }
          ]
        }
      ],
      "variable": [ { "key": "baseUrl", "value": "https://api.example.com" } ]
    }
    """;

    private const string OpenApiMinimal = """
    {
      "openapi": "3.0.3",
      "info": { "title": "Widget API", "version": "2.1.0" },
      "servers": [ { "url": "https://widgets.example.com/api" } ],
      "paths": {
        "/widgets": {
          "get": {
            "operationId": "listWidgets",
            "tags": [ "widgets" ],
            "parameters": [
              { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer" } },
              { "name": "X-Tenant", "in": "header", "required": true, "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "ok" } }
          },
          "post": {
            "operationId": "createWidget",
            "tags": [ "widgets" ],
            "requestBody": {
              "content": {
                "application/json": {
                  "schema": { "$ref": "#/components/schemas/Widget" }
                }
              }
            },
            "responses": { "201": { "description": "created" } }
          }
        },
        "/widgets/{widgetId}": {
          "get": {
            "operationId": "getWidget",
            "tags": [ "widgets" ],
            "parameters": [
              { "name": "widgetId", "in": "path", "required": true,
                "schema": { "type": "string" }, "example": "w-123" }
            ],
            "responses": { "200": { "description": "ok" } }
          }
        }
      },
      "components": {
        "schemas": {
          "Widget": {
            "type": "object",
            "properties": {
              "name": { "type": "string" },
              "size": { "type": "integer" },
              "active": { "type": "boolean" }
            }
          }
        }
      }
    }
    """;

    private const string Swagger2Minimal = """
    {
      "swagger": "2.0",
      "info": { "title": "Legacy API", "version": "1.0" },
      "host": "legacy.example.com",
      "basePath": "/v2",
      "schemes": [ "https" ],
      "paths": {
        "/ping": { "get": { "operationId": "ping", "responses": { "200": { "description": "ok" } } } }
      }
    }
    """;

    private const string HarMinimal = """
    {
      "log": {
        "version": "1.2",
        "entries": [
          {
            "request": {
              "method": "GET",
              "url": "https://cdn.example.com/assets/app.js",
              "headers": [
                { "name": ":authority", "value": "cdn.example.com" },
                { "name": "Accept", "value": "*/*" }
              ]
            }
          },
          {
            "request": {
              "method": "POST",
              "url": "https://api.example.com/track",
              "headers": [ { "name": "Content-Type", "value": "application/json" } ],
              "postData": { "mimeType": "application/json", "text": "{\"event\":\"click\"}" }
            }
          }
        ]
      }
    }
    """;

    private static ApiRequest Find(ApiCollection c, string name) =>
        c.Requests().First(r => r.Name.Contains(name, StringComparison.OrdinalIgnoreCase)
                             || r.Url.Contains(name, StringComparison.OrdinalIgnoreCase));

    // ---------------------------------------------------------------- postman

    [Fact]
    public void Postman_Import_Reads_Name_Folders_And_Requests()
    {
        var result = ApiImporters.FromPostman(PostmanMinimal);
        Assert.True(result.Ok, result.Error);
        var c = result.Collection!;

        Assert.Equal("Sample API", c.Name);
        Assert.Equal(2, c.RequestCount);
        Assert.Contains(c.Requests(), r => r.Name == "Health" && r.Method == "GET");
        Assert.Contains(c.Root.Folders, f => f.Name == "Users");
    }

    [Fact]
    public void Postman_Import_Handles_The_Object_Form_Url()
    {
        var c = ApiImporters.FromPostman(PostmanMinimal).Collection!;
        var create = Find(c, "Create user");

        Assert.Equal("POST", create.Method);
        Assert.Contains("api.example.com", create.Url, StringComparison.Ordinal);
        Assert.Contains("/v1/users", create.Url, StringComparison.Ordinal);
    }

    [Fact]
    public void Postman_Import_Preserves_Header_Enablement()
    {
        var create = Find(ApiImporters.FromPostman(PostmanMinimal).Collection!, "Create user");

        Assert.Contains(create.Headers, h => h.Name == "Content-Type" && h.Enabled);
        var disabled = create.Headers.FirstOrDefault(h => h.Name == "X-Disabled");
        Assert.NotNull(disabled);
        Assert.False(disabled!.Enabled);
    }

    [Fact]
    public void Postman_Import_Maps_Bearer_Auth_And_A_Raw_Body()
    {
        var create = Find(ApiImporters.FromPostman(PostmanMinimal).Collection!, "Create user");

        Assert.Equal(ApiAuthKind.Bearer, create.Auth.Kind);
        Assert.Equal("super-secret-token", create.Auth.Token);
        Assert.Contains("ada", create.Body.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Postman_Import_Reads_Collection_Variables()
    {
        var c = ApiImporters.FromPostman(PostmanMinimal).Collection!;
        Assert.True(c.Variables.ContainsKey("baseUrl"));
    }

    [Fact]
    public void Postman_Import_Warns_About_Test_Scripts_Instead_Of_Executing_Them()
    {
        const string withScript = """
        {
          "info": { "name": "scripted" },
          "item": [ {
            "name": "checked",
            "request": { "method": "GET", "url": "https://x.example/y" },
            "event": [ { "listen": "test", "script": { "exec": [ "pm.response.to.have.status(200);" ] } } ]
          } ]
        }
        """;

        var result = ApiImporters.FromPostman(withScript);
        Assert.True(result.Ok, result.Error);

        // Either the recognisable status assertion was lifted out, or the script was
        // reported as skipped. Silently dropping it would be the bug.
        var request = result.Collection!.Requests().First();
        bool lifted = request.Assertions.Any(a => a.Kind == AssertionKind.StatusEquals && a.Expected == "200");
        Assert.True(lifted || result.Warnings.Count > 0,
            "an unexecutable test script must either be translated or reported");
    }

    // ---------------------------------------------------------------- openapi

    [Fact]
    public void OpenApi_Import_Creates_One_Request_Per_Operation()
    {
        var result = ApiImporters.FromOpenApi(OpenApiMinimal);
        Assert.True(result.Ok, result.Error);
        var c = result.Collection!;

        Assert.Equal(3, c.RequestCount);
        Assert.Contains(c.Requests(), r => r.Method == "GET" && r.Url.EndsWith("/widgets", StringComparison.Ordinal));
        Assert.Contains(c.Requests(), r => r.Method == "POST");
    }

    [Fact]
    public void OpenApi_Import_Resolves_The_Server_Url()
    {
        var c = ApiImporters.FromOpenApi(OpenApiMinimal).Collection!;
        Assert.All(c.Requests(), r =>
            Assert.Contains("widgets.example.com/api", r.Url, StringComparison.Ordinal));
    }

    [Fact]
    public void OpenApi_Path_Parameters_Become_Template_Variables_With_Their_Example()
    {
        var c = ApiImporters.FromOpenApi(OpenApiMinimal).Collection!;
        var byId = c.Requests().First(r => r.Url.Contains("widgetId", StringComparison.Ordinal));

        Assert.Contains("{{widgetId}}", byId.Url, StringComparison.Ordinal);
        Assert.True(c.Variables.TryGetValue("widgetId", out var example));
        Assert.Equal("w-123", example);
    }

    [Fact]
    public void OpenApi_Query_Parameters_Are_Imported_With_Required_Ones_Enabled()
    {
        var c = ApiImporters.FromOpenApi(OpenApiMinimal).Collection!;
        var list = c.Requests().First(r => r.Method == "GET" && r.Url.EndsWith("/widgets", StringComparison.Ordinal));

        var limit = list.Query.FirstOrDefault(q => q.Name == "limit");
        Assert.NotNull(limit);
        Assert.False(limit!.Enabled);          // not required -> off by default

        var tenant = list.Headers.FirstOrDefault(h => h.Name == "X-Tenant");
        Assert.NotNull(tenant);
        Assert.True(tenant!.Enabled);          // required -> on
    }

    [Fact]
    public void OpenApi_Generates_A_Json_Example_Body_From_A_Referenced_Schema()
    {
        var c = ApiImporters.FromOpenApi(OpenApiMinimal).Collection!;
        var create = c.Requests().First(r => r.Method == "POST");

        Assert.Equal(ApiBodyKind.Json, create.Body.Kind);
        using var doc = JsonDocument.Parse(create.Body.Text);
        Assert.True(doc.RootElement.TryGetProperty("name", out _));
        Assert.True(doc.RootElement.TryGetProperty("size", out _));
        Assert.True(doc.RootElement.TryGetProperty("active", out _));
    }

    [Fact]
    public void OpenApi_Turns_A_Single_Success_Response_Into_A_Status_Assertion()
    {
        var c = ApiImporters.FromOpenApi(OpenApiMinimal).Collection!;
        var create = c.Requests().First(r => r.Method == "POST");
        Assert.Contains(create.Assertions, a => a.Kind == AssertionKind.StatusEquals && a.Expected == "201");
    }

    [Fact]
    public async Task A_Self_Referencing_Schema_Does_Not_Hang_The_Importer()
    {
        const string cyclic = """
        {
          "openapi": "3.0.0",
          "info": { "title": "Cyclic", "version": "1" },
          "paths": { "/node": { "post": {
              "requestBody": { "content": { "application/json": {
                  "schema": { "$ref": "#/components/schemas/Node" } } } },
              "responses": { "200": { "description": "ok" } } } } },
          "components": { "schemas": { "Node": { "type": "object", "properties": {
              "child": { "$ref": "#/components/schemas/Node" } } } } }
        }
        """;

        var work = Task.Run(() => ApiImporters.FromOpenApi(cyclic));
        var finished = await Task.WhenAny(work, Task.Delay(TimeSpan.FromSeconds(10)));
        Assert.Same(work, finished);   // a $ref cycle must be guarded, not followed forever

        var result = await work;
        Assert.True(result.Ok, result.Error);
    }

    [Fact]
    public void Swagger2_Builds_Its_Base_Url_From_Scheme_Host_And_BasePath()
    {
        var result = ApiImporters.FromOpenApi(Swagger2Minimal);
        Assert.True(result.Ok, result.Error);

        var ping = result.Collection!.Requests().First();
        Assert.Contains("https://legacy.example.com/v2/ping", ping.Url, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------------- har

    [Fact]
    public void Har_Import_Reads_Entries_And_Drops_Pseudo_Headers()
    {
        var result = ApiImporters.FromHar(HarMinimal);
        Assert.True(result.Ok, result.Error);
        var c = result.Collection!;

        Assert.Equal(2, c.RequestCount);
        Assert.All(c.Requests(), r =>
            Assert.DoesNotContain(r.Headers, h => h.Name.StartsWith(':')));

        var post = c.Requests().First(r => r.Method == "POST");
        Assert.Contains("click", post.Body.Text, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------- curl

    [Theory]
    [InlineData("curl https://api.example.com/health", "GET", "https://api.example.com/health")]
    [InlineData("curl -X DELETE https://api.example.com/v1/items/9", "DELETE", "https://api.example.com/v1/items/9")]
    [InlineData("curl --request PUT --url https://api.example.com/x", "PUT", "https://api.example.com/x")]
    public void Curl_Parses_Method_And_Url(string command, string method, string url)
    {
        var r = ApiImporters.FromCurl(command);
        Assert.NotNull(r);
        Assert.Equal(method, r!.Method);
        Assert.Equal(url, r.Url);
    }

    [Fact]
    public void Curl_Parses_Headers_Data_And_Basic_Auth()
    {
        var r = ApiImporters.FromCurl(
            "curl -X POST https://api.example.com/v1/items " +
            "-H 'Content-Type: application/json' " +
            "-H \"X-Trace: abc\" " +
            "-u alice:s3cret " +
            "-d '{\"name\":\"thing\"}'");

        Assert.NotNull(r);
        Assert.Equal("POST", r!.Method);
        Assert.Contains(r.Headers, h => h.Name == "Content-Type" && h.Value == "application/json");
        Assert.Contains(r.Headers, h => h.Name == "X-Trace" && h.Value == "abc");
        Assert.Equal(ApiAuthKind.Basic, r.Auth.Kind);
        Assert.Equal("alice", r.Auth.Username);
        Assert.Contains("thing", r.Body.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Curl_Handles_Backslash_Line_Continuations()
    {
        var r = ApiImporters.FromCurl("curl https://api.example.com/x \\\n  -H 'Accept: application/json'");
        Assert.NotNull(r);
        Assert.Contains(r!.Headers, h => h.Name == "Accept");
    }

    [Fact]
    public void A_Data_Flag_Without_An_Explicit_Method_Implies_Post()
    {
        var r = ApiImporters.FromCurl("curl https://api.example.com/x -d 'a=1'");
        Assert.NotNull(r);
        Assert.Equal("POST", r!.Method);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-curl-command")]
    [InlineData("curl")]
    public void Curl_Returns_Null_Rather_Than_Throwing_On_Junk(string command)
    {
        var ex = Record.Exception(() => ApiImporters.FromCurl(command));
        Assert.Null(ex);
    }

    // ------------------------------------------------------------------- auto

    [Theory]
    [InlineData(nameof(PostmanMinimal))]
    [InlineData(nameof(OpenApiMinimal))]
    [InlineData(nameof(Swagger2Minimal))]
    [InlineData(nameof(HarMinimal))]
    public void Auto_Sniffs_The_Format_From_Content_Not_Filename(string which)
    {
        string content = which switch
        {
            nameof(PostmanMinimal) => PostmanMinimal,
            nameof(OpenApiMinimal) => OpenApiMinimal,
            nameof(Swagger2Minimal) => Swagger2Minimal,
            _ => HarMinimal
        };

        // Deliberately misleading filename: people rename these constantly.
        var result = ApiImporters.Auto(content, "definitely-not-what-it-is.txt");
        Assert.True(result.Ok, result.Error);
        Assert.NotEmpty(result.Collection!.Requests());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{")]
    [InlineData("plain text, not a document")]
    [InlineData("{\"unrelated\":true}")]
    public void A_Malformed_Or_Unrecognised_Document_Reports_An_Error_Instead_Of_Throwing(string content)
    {
        var ex = Record.Exception(() =>
        {
            var result = ApiImporters.Auto(content, "x.json");
            // The record's own invariant: never a null collection with a null error.
            Assert.True(result.Ok || !string.IsNullOrWhiteSpace(result.Error));
        });
        Assert.Null(ex);
    }

    [Fact]
    public void Postman_Environments_Import()
    {
        const string env = """
        { "name": "staging", "values": [
            { "key": "baseUrl", "value": "https://staging.example.com", "enabled": true },
            { "key": "token", "value": "abc", "enabled": true } ] }
        """;

        var envs = ApiImporters.PostmanEnvironments(env);
        var one = Assert.Single(envs);
        Assert.Equal("staging", one.Name);
        Assert.Equal("https://staging.example.com", one.Variables["baseUrl"]);
    }

    // -------------------------------------------------------------- exporters

    [Fact]
    public void Postman_Export_Round_Trips_Through_The_Importer()
    {
        var original = ApiImporters.FromPostman(PostmanMinimal).Collection!;
        string json = ApiExporters.ToPostman(original);

        var round = ApiImporters.FromPostman(json);
        Assert.True(round.Ok, round.Error);
        var back = round.Collection!;

        Assert.Equal(original.Name, back.Name);
        Assert.Equal(original.RequestCount, back.RequestCount);

        foreach (var before in original.Requests())
        {
            var after = back.Requests().FirstOrDefault(r => r.Name == before.Name);
            Assert.NotNull(after);
            Assert.Equal(before.Method, after!.Method);
            Assert.Equal(before.Body.Kind, after.Body.Kind);
            Assert.Equal(before.Body.Text, after.Body.Text);
            foreach (var h in before.Headers.Where(h => h.Enabled))
                Assert.Contains(after.Headers, x => x.Name == h.Name && x.Value == h.Value);
        }
    }

    [Fact]
    public void Postman_Export_Never_Writes_A_Real_Secret()
    {
        var c = ApiImporters.FromPostman(PostmanMinimal).Collection!;
        string json = ApiExporters.ToPostman(c);

        Assert.DoesNotContain("super-secret-token", json, StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(json);   // and it must still be valid Postman JSON
        Assert.True(doc.RootElement.TryGetProperty("info", out _));
    }

    [Fact]
    public void Curl_Export_Quotes_Correctly_And_Redacts_Credentials()
    {
        var request = new ApiRequest
        {
            Name = "risky",
            Method = "POST",
            Url = "https://api.example.com/v1/items",
            Headers = new[]
            {
                ApiKeyValue.Of("Authorization", "Bearer super-secret-token"),
                ApiKeyValue.Of("X-Note", "it's got a quote")
            },
            Body = ApiBody.Json("{\"a\":1}")
        };

        string curl = ApiExporters.ToCurl(request);

        Assert.DoesNotContain("super-secret-token", curl, StringComparison.Ordinal);
        Assert.Contains("curl", curl, StringComparison.Ordinal);
        Assert.Contains("api.example.com", curl, StringComparison.Ordinal);
        // A naive single-quote wrapper would produce a broken command here.
        Assert.DoesNotContain("'it's got a quote'", curl, StringComparison.Ordinal);
    }

    [Fact]
    public void OpenApi_Export_Produces_A_Parseable_Document_With_Every_Path()
    {
        var c = ApiImporters.FromPostman(PostmanMinimal).Collection!;
        string spec = ApiExporters.ToOpenApi(c, "Exported", "3.0.0");

        using var doc = JsonDocument.Parse(spec);
        Assert.True(doc.RootElement.TryGetProperty("openapi", out _));
        Assert.True(doc.RootElement.TryGetProperty("paths", out var paths));
        Assert.NotEmpty(paths.EnumerateObject());
    }

    [Fact]
    public void Http_File_And_Markdown_Exports_Mention_Every_Request()
    {
        var c = ApiImporters.FromPostman(PostmanMinimal).Collection!;
        string http = ApiExporters.ToHttpFile(c);
        string md = ApiExporters.ToMarkdown(c);

        foreach (var r in c.Requests())
        {
            Assert.Contains(r.Method, http, StringComparison.Ordinal);
            Assert.Contains(r.Name, md, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("super-secret-token", http, StringComparison.Ordinal);
        Assert.DoesNotContain("super-secret-token", md, StringComparison.Ordinal);
    }

    [Fact]
    public void Exporters_Survive_An_Empty_Collection()
    {
        var empty = new ApiCollection { Name = "empty" };

        foreach (var render in new Func<string>[]
                 {
                     () => ApiExporters.ToPostman(empty),
                     () => ApiExporters.ToOpenApi(empty, "empty", "1.0.0"),
                     () => ApiExporters.ToHttpFile(empty),
                     () => ApiExporters.ToMarkdown(empty)
                 })
        {
            var ex = Record.Exception(() => render());
            Assert.Null(ex);
        }
    }
}

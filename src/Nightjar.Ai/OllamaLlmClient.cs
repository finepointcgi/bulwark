using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nightjar.Core.Ai;

namespace Nightjar.Ai;

/// <summary>
/// A local model served by Ollama. No source code leaves the machine, so this is the option for
/// air-gapped or confidential codebases. Uses /api/chat with a JSON-schema `format`.
/// </summary>
public sealed class OllamaLlmClient(HttpClient http, string model, Uri? baseUrl = null) : ILlmClient
{
    public const string DefaultModel = "qwen3-coder";

    private readonly Uri _baseUrl = baseUrl
        ?? (Environment.GetEnvironmentVariable("OLLAMA_HOST") is { Length: > 0 } host
            ? new Uri(host.Contains("://") ? host : "http://" + host)
            : new Uri("http://localhost:11434"));

    public string Name => $"ollama:{model}";

    public bool IsRemote => !_baseUrl.IsLoopback;

    public async Task<string> CompleteJsonAsync(string system, string user, string jsonSchema, CancellationToken cancellationToken)
    {
        var request = new JsonObject
        {
            ["model"] = model,
            ["stream"] = false,
            ["format"] = JsonNode.Parse(jsonSchema),
            ["options"] = new JsonObject { ["temperature"] = 0 },
            ["messages"] = new JsonArray
            {
                new JsonObject { ["role"] = "system", ["content"] = system },
                new JsonObject { ["role"] = "user", ["content"] = user },
            },
        };

        using var response = await http.PostAsJsonAsync(new Uri(_baseUrl, "/api/chat"), request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException($"Ollama returned {(int)response.StatusCode}: {body.Trim()}");
        }

        using var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        return json.RootElement.GetProperty("message").GetProperty("content").GetString()
               ?? throw new InvalidDataException("Ollama returned no content");
    }
}

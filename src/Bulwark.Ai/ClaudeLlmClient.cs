using System.Text.Json;
using Anthropic;
using Anthropic.Models.Beta;
using Anthropic.Models.Beta.Messages;
using Bulwark.Core.Ai;

namespace Bulwark.Ai;

/// <summary>
/// Claude via the Anthropic API. Credentials resolve the SDK's usual way (ANTHROPIC_API_KEY,
/// ANTHROPIC_AUTH_TOKEN, or an `ant auth login` profile).
/// </summary>
public sealed class ClaudeLlmClient : ILlmClient
{
    public const string DefaultModel = "claude-opus-5-5";

    private readonly AnthropicClient _client;
    private readonly string _model;

    public ClaudeLlmClient(string? model = null, AnthropicClient? client = null)
    {
        _model = model ?? DefaultModel;
        _client = client ?? new AnthropicClient();
    }

    public string Name => $"claude:{_model}";

    public bool IsRemote => true;

    public async Task<string> CompleteJsonAsync(string system, string user, string jsonSchema, CancellationToken cancellationToken)
    {
        var schema = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(jsonSchema)
                     ?? throw new ArgumentException("invalid JSON schema", nameof(jsonSchema));

        var response = await _client.Beta.Messages.Create(new MessageCreateParams
        {
            Model = _model,
            MaxTokens = 16000,
            // Security analysis can trip the cyber safety classifier on legitimate triage;
            // server-side fallback re-serves a declined request on a suitable model.
            Betas = [AnthropicBeta.ServerSideFallback2026_07_01],
            Fallbacks = new Default(),
            System = system,
            OutputConfig = new BetaOutputConfig
            {
                Effort = Effort.High,
                Format = new BetaJsonOutputFormat { Schema = schema },
            },
            Messages = [new BetaUserMessageParam { Content = user }],
        }, cancellationToken);

        if (response.StopReason == "refusal")
        {
            throw new InvalidOperationException($"model declined to assess this finding ({response.StopDetails?.Category})");
        }

        if (response.StopReason == "max_tokens")
        {
            throw new InvalidOperationException("model response was cut off (max_tokens)");
        }

        return string.Concat(response.Content
            .Select(b => b.TryPickText(out var text) ? text.Text : null)
            .Where(t => t is not null));
    }
}

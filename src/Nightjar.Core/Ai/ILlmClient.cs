namespace Nightjar.Core.Ai;

/// <summary>
/// The one thing the AI reviewer needs from a model: send a system prompt and a user prompt,
/// get back a JSON object that matches <paramref name="jsonSchema"/>.
/// Implementations live in Nightjar.Ai (Claude, Ollama) so Core stays provider-neutral.
/// </summary>
public interface ILlmClient
{
    /// <summary>Provider and model, e.g. "claude:claude-opus-5-5" or "ollama:qwen3-coder". Stored on each assessment.</summary>
    string Name { get; }

    /// <summary>True when prompts (which contain source code) leave this machine.</summary>
    bool IsRemote { get; }

    Task<string> CompleteJsonAsync(string system, string user, string jsonSchema, CancellationToken cancellationToken);
}

using System.Diagnostics;
using System.Text.Json;
using Bulwark.Core.Ai;

namespace Bulwark.Ai;

/// <summary>
/// Claude through the local Claude Code CLI (`claude -p`), using whatever login Claude Code
/// already has, so no API key is needed. The CLI runs with every tool, MCP server and settings
/// file disabled, from an empty directory: prompts contain untrusted repository content, so the
/// model must not be able to do anything but answer.
/// </summary>
public sealed class ClaudeCodeLlmClient(string? model = null, string executable = "claude") : ILlmClient
{
    public const string DefaultModel = "claude-opus-5-5";

    private readonly string _model = model ?? DefaultModel;

    public string Name => $"claude-code:{_model}";

    public bool IsRemote => true;

    public async Task<string> CompleteJsonAsync(string system, string user, string jsonSchema, CancellationToken cancellationToken)
    {
        var sandbox = Directory.CreateTempSubdirectory("bulwark-claude-").FullName;
        try
        {
            var startInfo = new ProcessStartInfo(executable)
            {
                WorkingDirectory = sandbox,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };

            foreach (var argument in (string[])
            [
                "-p",
                "--output-format", "json",
                "--model", _model,
                "--tools", "",
                "--strict-mcp-config",
                "--setting-sources", "",
                "--no-session-persistence",
                "--system-prompt", system,
                "--json-schema", jsonSchema,
            ])
            {
                startInfo.ArgumentList.Add(argument);
            }

            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException($"could not start '{executable}'");

            // The prompt goes over stdin: excerpts can exceed command-line length limits.
            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.StandardInput.WriteAsync(user.AsMemory(), cancellationToken);
            process.StandardInput.Close();

            try
            {
                await process.WaitForExitAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                throw;
            }

            var stdout = await stdoutTask;
            if (string.IsNullOrWhiteSpace(stdout))
            {
                throw new InvalidOperationException($"claude exited {process.ExitCode}: {(await stderrTask).Trim()}");
            }

            using var json = JsonDocument.Parse(stdout);
            var root = json.RootElement;
            if (root.TryGetProperty("is_error", out var isError) && isError.GetBoolean())
            {
                var message = root.TryGetProperty("result", out var result) ? result.GetString() : "unknown error";
                throw new InvalidOperationException($"claude reported an error: {message}");
            }

            if (root.TryGetProperty("structured_output", out var structured) && structured.ValueKind == JsonValueKind.Object)
            {
                return structured.GetRawText();
            }

            return root.TryGetProperty("result", out var text) ? text.GetString() ?? "" : "";
        }
        catch (System.ComponentModel.Win32Exception)
        {
            throw new InvalidOperationException($"'{executable}' not found. Install Claude Code, or use --ai claude with an API key.");
        }
        finally
        {
            try { Directory.Delete(sandbox, recursive: true); } catch (IOException) { }
        }
    }
}

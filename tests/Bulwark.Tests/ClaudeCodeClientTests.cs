using Bulwark.Ai;

namespace Bulwark.Tests;

/// <summary>Runs the client against a stub `claude` script, so no real CLI or account is needed.</summary>
public sealed class ClaudeCodeClientTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("bulwark-claude-stub-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Stub(string body)
    {
        var path = Path.Combine(_dir, "claude");
        File.WriteAllText(path, "#!/bin/sh\n" + body + "\n");
        File.SetUnixFileMode(path, (UnixFileMode)0b111_101_101);
        return path;
    }

    [Fact]
    public async Task ReturnsStructuredOutputAndDisablesTools()
    {
        if (OperatingSystem.IsWindows()) { return; }

        var argsFile = Path.Combine(_dir, "args");
        var stdinFile = Path.Combine(_dir, "stdin");
        var claude = Stub($$$"""
            printf '%s\n' "$@" > '{{{argsFile}}}'
            cat > '{{{stdinFile}}}'
            echo '{"type":"result","is_error":false,"result":"x","structured_output":{"verdict":"likely"}}'
            """);

        var json = await new ClaudeCodeLlmClient(executable: claude).CompleteJsonAsync("sys", "the prompt", "{}", CancellationToken.None);

        Assert.Equal("""{"verdict":"likely"}""", json);
        Assert.Equal("the prompt", File.ReadAllText(stdinFile));
        var args = File.ReadAllLines(argsFile);
        Assert.Equal("", args[Array.IndexOf(args, "--tools") + 1]);
        Assert.Contains("--strict-mcp-config", args);
        Assert.Equal("", args[Array.IndexOf(args, "--setting-sources") + 1]);
        Assert.Equal("claude-opus-5-5", args[Array.IndexOf(args, "--model") + 1]);
    }

    [Fact]
    public async Task SurfacesCliErrors()
    {
        if (OperatingSystem.IsWindows()) { return; }

        var claude = Stub("""cat >/dev/null; echo '{"type":"result","is_error":true,"result":"Not logged in"}'""");
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new ClaudeCodeLlmClient(executable: claude).CompleteJsonAsync("s", "u", "{}", CancellationToken.None));
        Assert.Contains("Not logged in", error.Message);
    }
}

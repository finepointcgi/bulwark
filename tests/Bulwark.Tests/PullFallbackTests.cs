using Bulwark.Core.Updates;
using Bulwark.Engines.Execution;

namespace Bulwark.Tests;

[Collection("PATH")]
public sealed class PullFallbackTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("bulwark-fakedocker-").FullName;
    private readonly string? _path = Environment.GetEnvironmentVariable("PATH");

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("PATH", _path);
        Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task Docker_hub_429_falls_back_to_the_mirror_with_the_same_digest()
    {
        if (OperatingSystem.IsWindows()) { return; }

        var log = Path.Combine(_dir, "log");
        var script = Path.Combine(_dir, "docker");
        File.WriteAllText(script, $$"""
            #!/bin/sh
            echo "$@" >> '{{log}}'
            [ "$1 $2" = "image inspect" ] && exit 1
            if [ "$1" = pull ]; then
              case "$3" in mirror.gcr.io/*) exit 0;; *) echo "toomanyrequests: rate limit" >&2; exit 1;; esac
            fi
            exit 0
            """);
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Environment.SetEnvironmentVariable("PATH", _dir + Path.PathSeparator + _path);

        var digest = "sha256:" + new string('c', 64);
        var spec = new EngineSpec { Name = "fallback-test", Version = "1", Image = "docker.io/example/fallback-test", Digest = digest, Binary = "fallback-test" };

        var image = await EngineImages.ResolveAsync(spec, CancellationToken.None);

        Assert.Equal($"mirror.gcr.io/example/fallback-test:1@{digest}".Replace(":1@", "@"), image.Replace(":1@", "@"));
        Assert.Contains("pull -q mirror.gcr.io/example/fallback-test", File.ReadAllText(log));
    }
}

[CollectionDefinition("PATH", DisableParallelization = true)]
public sealed class PathCollection;

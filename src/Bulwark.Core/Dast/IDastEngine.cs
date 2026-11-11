using Bulwark.Core.Engines;

namespace Bulwark.Core.Dast;

/// <summary>An active-testing engine (ZAP, nuclei). All of its traffic goes through the scope proxy.</summary>
public interface IDastEngine
{
    string Name { get; }

    /// <summary>Lower runs first; discovery (spidering) runs before targeted checks.</summary>
    int Order => 100;

    Task<EngineResult> RunAsync(DastContext context, CancellationToken cancellationToken);
}

/// <summary>Shared state for one active test.</summary>
public sealed class DastContext
{
    public required Uri Target { get; init; }
    public required PentestScope Scope { get; init; }
    public required string WorkDirectory { get; init; }

    /// <summary>Proxy URL as seen from a local process and from inside an engine container.</summary>
    public required string LocalProxyUrl { get; init; }
    public required string ContainerProxyUrl { get; init; }

    /// <summary>
    /// When engines must stop: a little before the overall time budget, so an engine that is cut
    /// off still has time to hand back the results it wrote so far.
    /// </summary>
    public DateTimeOffset Deadline { get; init; } = DateTimeOffset.MaxValue;

    /// <summary>Time an engine may still use, never less than a minute.</summary>
    public TimeSpan Remaining => Deadline == DateTimeOffset.MaxValue
        ? TimeSpan.FromHours(24)
        : TimeSpan.FromTicks(Math.Max(TimeSpan.FromMinutes(1).Ticks, (Deadline - DateTimeOffset.UtcNow).Ticks));

    /// <summary>Credentials for an authenticated scan, if the scope configures them.</summary>
    public AuthHeader? Auth { get; init; }

    /// <summary>OpenAPI spec (local file path or in-scope URL) for an API scan.</summary>
    public string? OpenApi { get; init; }

    /// <summary>URLs the discovery engine found; read by the planner.</summary>
    public List<string> DiscoveredUrls { get; } = [];

    /// <summary>Set before targeted engines run.</summary>
    public PentestPlan Plan { get; set; } = PentestPlanner.Default;
}

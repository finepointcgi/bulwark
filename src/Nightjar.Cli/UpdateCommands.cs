using System.Globalization;
using System.Reflection;
using Nightjar.Core.Updates;
using Nightjar.Engines.Canary;

namespace Nightjar.Cli;

/// <summary>
/// Everything that keeps Nightjar current: `update` (signed manifest + canary + rollback),
/// automatic daily checks during `scan`, `canary`, `self-update`, and the maintainer tools the
/// release workflows use (`manifest generate`, `engines watch`).
/// </summary>
internal static class UpdateCommands
{
    private const int Passed = 0;
    private const int Failed = 1;
    private const int Error = 2;

    private static string Version =>
        typeof(UpdateCommands).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "dev";

    public static async Task<int> UpdateAsync(Options options)
    {
        var publicKey = TrustedKeys.PublicKey(options);
        if (publicKey is null)
        {
            Console.Error.WriteLine("error: no trusted public key. Pass --key <public.pem> or set NIGHTJAR_TRUSTED_KEY.");
            return Error;
        }

        var store = ManifestStore.Default();
        using var http = Http();
        var updater = new ManifestUpdater(http, store, publicKey);

        UpdateResult result;
        if (options.Value("from-file") is { } file)
        {
            var signature = await File.ReadAllTextAsync(options.Value("signature") ?? file + ".sig");
            result = updater.Install(await File.ReadAllBytesAsync(file), signature);
        }
        else if (TrustedKeys.ManifestUrl(options) is { } url)
        {
            result = await updater.UpdateAsync(new Uri(url), CancellationToken.None);
        }
        else
        {
            Console.Error.WriteLine("error: no manifest URL. Pass --url or set NIGHTJAR_MANIFEST_URL.");
            return Error;
        }

        store.MarkUpdateChecked();
        Console.WriteLine(result.Message);
        if (result.Status == UpdateStatus.Rejected)
        {
            return Error;
        }

        if (result.Status == UpdateStatus.Updated && !options.Has("skip-canary"))
        {
            return await VerifyOrRollBackAsync(store, result.Manifest!, options, quiet: false) ? Passed : Failed;
        }

        return Passed;
    }

    /// <summary>
    /// Called at the start of every scan. At most once a day, and only when a manifest URL and key
    /// are configured (release builds have both). Never fails the scan: problems become warnings.
    /// Opt out with NIGHTJAR_AUTO_UPDATE=0 or --no-update.
    /// </summary>
    public static async Task AutoUpdateAsync(Options options)
    {
        if (options.Has("no-update") || Environment.GetEnvironmentVariable("NIGHTJAR_AUTO_UPDATE") is "0" or "false")
        {
            return;
        }

        var store = ManifestStore.Default();
        if (TrustedKeys.ManifestUrl(options) is not { } url || TrustedKeys.PublicKey(options) is not { } key
            || !store.IsUpdateCheckDue(TimeSpan.FromHours(24)))
        {
            return;
        }

        try
        {
            using var http = Http();
            var result = await new ManifestUpdater(http, store, key).UpdateAsync(new Uri(url), CancellationToken.None);
            store.MarkUpdateChecked();
            if (result.Status == UpdateStatus.Updated)
            {
                Console.Error.WriteLine($"» {result.Message} Running canary check...");
                await VerifyOrRollBackAsync(store, result.Manifest!, options, quiet: true);
            }
            else if (result.Status == UpdateStatus.Rejected)
            {
                Console.Error.WriteLine($"warning: automatic update rejected: {result.Message}");
            }
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
        {
            store.MarkUpdateChecked(); // Offline: try again tomorrow rather than on every scan.
            Console.Error.WriteLine($"warning: automatic update check failed ({e.Message}); continuing with installed engines.");
        }
    }

    public static async Task<int> CanaryAsync(Options options)
    {
        var manifest = options.Value("manifest") is { } path
            ? EngineManifest.Parse(await File.ReadAllBytesAsync(path))
            : ManifestStore.Default().Load().Manifest;

        var result = await RunCanaryAsync(manifest, options, quiet: false);
        Print(result);
        return result.Passed ? Passed : Failed;
    }

    public static async Task<int> SelfUpdateAsync(Options options)
    {
        var (manifest, isBuiltIn) = ManifestStore.Default().Load();
        if (isBuiltIn)
        {
            Console.Error.WriteLine("error: no signed manifest installed. Run `nightjar update` first.");
            return Error;
        }

        using var http = Http();
        var result = await new SelfUpdater(http).UpdateAsync(manifest, Version, Environment.ProcessPath!, CancellationToken.None);
        Console.WriteLine(result.Message);
        return Passed;
    }

    /// <summary>
    /// nightjar manifest generate --engines engines/engines.json --digests digests.txt
    ///     [--image-prefix ghcr.io/org/nightjar-engines] [--channel stable] [--sequence N]
    ///     [--nightjar-version 1.2.0 --nightjar-assets assets.txt] --out manifest.json
    /// digests.txt: "name sha256:..." per line. assets.txt: "rid url sha256" per line.
    /// </summary>
    public static int Generate(Options options)
    {
        var catalog = EngineCatalog.Load(options.Value("engines") ?? "engines/engines.json");
        var digests = ReadPairs(options.Value("digests") ?? throw new ArgumentException("--digests is required"));
        var missing = catalog.Engines.Where(e => !digests.ContainsKey(e.Name)).Select(e => e.Name).ToList();
        if (missing.Count > 0)
        {
            throw new ArgumentException($"no digest for: {string.Join(", ", missing)}");
        }

        NightjarRelease? release = null;
        if (options.Value("nightjar-version") is { } version && options.Value("nightjar-assets") is { } assetsFile)
        {
            var assets = File.ReadAllLines(assetsFile)
                .Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                .Where(p => p.Length == 3)
                .Select(p => new NightjarAsset(p[0], p[1], p[2]))
                .ToList();
            release = new NightjarRelease { Version = version, Assets = assets };
        }

        var sequence = options.Value("sequence") is { } s
            ? long.Parse(s, CultureInfo.InvariantCulture)
            : long.Parse(DateTimeOffset.UtcNow.ToString("yyyyMMddHHmm", CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);

        var manifest = catalog.ToManifest(sequence, options.Value("channel") ?? "stable", DateTimeOffset.UtcNow,
            digests, options.Value("image-prefix"), release);
        var json = System.Text.Json.JsonSerializer.Serialize(manifest, EngineManifest.JsonOptions);
        var output = options.Value("out") ?? "manifest.json";
        File.WriteAllText(output, json);
        Console.WriteLine($"Wrote {output} (sequence {sequence}, {manifest.Engines.Count} engines)");
        return Passed;
    }

    /// <summary>
    /// nightjar engines watch [--engines engines/engines.json] [--min-age-days 14] [--write]
    /// Prints pending bumps as markdown (used as the PR body). Exit 0 = changes, 3 = nothing new.
    /// </summary>
    public static async Task<int> WatchAsync(Options options)
    {
        var catalogPath = options.Value("engines") ?? "engines/engines.json";
        var root = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(catalogPath)))!;
        var minAge = TimeSpan.FromDays(double.Parse(options.Value("min-age-days") ?? "14", CultureInfo.InvariantCulture));

        using var http = Http();
        if (Environment.GetEnvironmentVariable("GITHUB_TOKEN") is { Length: > 0 } token)
        {
            http.DefaultRequestHeaders.Authorization = new("Bearer", token);
        }

        var write = options.Has("write");
        var only = options.Value("only"); // "engines" or "base"; default both
        var catalog = EngineCatalog.Load(catalogPath);
        IReadOnlyList<PinChange> changes = [];
        if (only != "base")
        {
            (catalog, changes) = await new EngineWatcher(http, minAge).CheckAsync(catalog, root, write, CancellationToken.None);
        }
        if (write && changes.Count > 0)
        {
            catalog.Save(catalogPath);
        }

        // Base images of self-built engines. A separate client: the GitHub token must never be
        // sent to Docker Hub or the mirror.
        var baseMinAge = TimeSpan.FromDays(double.Parse(options.Value("base-min-age-days") ?? "2", CultureInfo.InvariantCulture));
        using var registry = Http();
        var baseWatcher = new BaseImageWatcher(registry, baseMinAge);
        var baseChanges = new List<PinChange>();
        foreach (var engine in catalog.Engines.Where(e => e.Build is not null && only != "engines"))
        {
            var dockerfile = Path.Combine(root, engine.Build!, "Dockerfile");
            if (File.Exists(dockerfile))
            {
                baseChanges.AddRange(await baseWatcher.CheckAsync(engine.Name, dockerfile, write, CancellationToken.None));
            }
        }

        if (changes.Count == 0 && baseChanges.Count == 0)
        {
            Console.Error.WriteLine($"All engines are on their newest release older than {minAge.TotalDays:0} days, and base images are current.");
            return 3;
        }

        if (changes.Count > 0)
        {
            Console.WriteLine($"Engine updates (releases at least {minAge.TotalDays:0} days old):\n");
            Console.WriteLine("| Engine | Upstream | From | To | Released |\n|---|---|---|---|---|");
            foreach (var c in changes)
            {
                Console.WriteLine($"| {c.Engine} | [{c.Repo}](https://github.com/{c.Repo}/releases/tag/{c.To}) | {c.From} | {c.To} | {c.Published:yyyy-MM-dd} |");
            }

            Console.WriteLine();
        }

        if (baseChanges.Count > 0)
        {
            Console.WriteLine($"Base image updates (newest patch release, pinned by digest, pulled via {BaseImageWatcher.Mirror}):\n");
            Console.WriteLine("| Engine | Image | From | To |\n|---|---|---|---|");
            foreach (var c in baseChanges)
            {
                Console.WriteLine($"| {c.Engine} | {c.Repo["base image ".Length..]} | `{c.From}` | `{c.To}` |");
            }
        }

        return Passed;
    }

    private static async Task<bool> VerifyOrRollBackAsync(ManifestStore store, EngineManifest manifest, Options options, bool quiet)
    {
        CanaryResult result;
        try
        {
            result = await RunCanaryAsync(manifest, options, quiet);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // Docker unavailable etc.: keep the verified manifest, but say the canary did not run.
            Console.Error.WriteLine($"warning: canary check could not run ({e.Message}); keeping manifest {manifest.Sequence}.");
            return true;
        }

        if (result.Passed)
        {
            Console.Error.WriteLine($"Canary passed: all engines in manifest {manifest.Sequence} still find the known issues.");
            return true;
        }

        store.RollBack(manifest.Sequence);
        Print(result);
        Console.Error.WriteLine($"Rolled back: manifest {manifest.Sequence} failed the canary check and will be skipped.");
        return false;
    }

    private static Task<CanaryResult> RunCanaryAsync(EngineManifest manifest, Options options, bool quiet)
    {
        var engines = EngineFactory.Create(EngineFactory.Runner(manifest, options), options);
        var progress = quiet ? null : new Progress<string>(m => Console.Error.WriteLine($"» canary: {m}"));
        return CanaryCheck.RunAsync(engines, manifest, progress, CancellationToken.None);
    }

    private static void Print(CanaryResult result)
    {
        foreach (var failed in result.FailedEngines)
        {
            Console.Error.WriteLine($"  engine failed: {failed.Engine} {failed.Version}: {failed.Error}");
        }

        foreach (var missing in result.Missing)
        {
            Console.Error.WriteLine($"  missing: {missing.Engine} no longer reports {missing.RuleId}");
        }

        Console.Error.WriteLine(result.Passed ? "Canary passed." : "Canary FAILED.");
    }

    private static Dictionary<string, string> ReadPairs(string path) =>
        File.ReadAllLines(path)
            .Select(l => l.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(p => p.Length == 2)
            .ToDictionary(p => p[0], p => p[1], StringComparer.OrdinalIgnoreCase);

    private static HttpClient Http()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"nightjar/{Version}");
        return http;
    }
}

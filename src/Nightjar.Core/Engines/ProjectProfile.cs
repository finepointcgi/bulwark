namespace Nightjar.Core.Engines;

/// <summary>What the detector found in a project. Engines use this to decide whether they apply.</summary>
public sealed record ProjectProfile(
    IReadOnlySet<string> Ecosystems,
    IReadOnlySet<string> Languages,
    IReadOnlyList<string> Manifests,
    bool HasContainers,
    bool HasInfrastructureAsCode)
{
    public bool HasDependencies => Manifests.Count > 0;
}

/// <summary>Zero-config detection: walk the tree once and infer the stack from file names.</summary>
public static class ProjectDetector
{
    private static readonly Dictionary<string, string> ManifestEcosystems = new(StringComparer.OrdinalIgnoreCase)
    {
        ["package.json"] = "npm",
        ["package-lock.json"] = "npm",
        ["yarn.lock"] = "npm",
        ["pnpm-lock.yaml"] = "npm",
        ["requirements.txt"] = "PyPI",
        ["poetry.lock"] = "PyPI",
        ["Pipfile.lock"] = "PyPI",
        ["uv.lock"] = "PyPI",
        ["go.mod"] = "Go",
        ["Cargo.lock"] = "crates.io",
        ["pom.xml"] = "Maven",
        ["build.gradle"] = "Maven",
        ["build.gradle.kts"] = "Maven",
        ["gradle.lockfile"] = "Maven",
        ["packages.lock.json"] = "NuGet",
        ["Gemfile.lock"] = "RubyGems",
        ["composer.lock"] = "Packagist",
        ["pubspec.lock"] = "Pub",
    };

    internal static readonly Dictionary<string, string> ExtensionLanguages = new(StringComparer.OrdinalIgnoreCase)
    {
        [".cs"] = "csharp", [".js"] = "javascript", [".ts"] = "typescript", [".tsx"] = "typescript",
        [".py"] = "python", [".go"] = "go", [".java"] = "java", [".kt"] = "kotlin", [".rb"] = "ruby",
        [".php"] = "php", [".rs"] = "rust", [".c"] = "c", [".cpp"] = "cpp", [".h"] = "c", [".hpp"] = "cpp",
        [".swift"] = "swift", [".scala"] = "scala",
    };

    private static readonly HashSet<string> SkippedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", "node_modules", "bin", "obj", ".venv", "venv", "__pycache__", "target", "dist", "build", ".nightjar",
    };

    public static ProjectProfile Detect(string rootPath)
    {
        var ecosystems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var languages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var manifests = new List<string>();
        var containers = false;
        var iac = false;

        foreach (var file in EnumerateFiles(rootPath))
        {
            var name = System.IO.Path.GetFileName(file);
            var extension = System.IO.Path.GetExtension(file);

            if (ManifestEcosystems.TryGetValue(name, out var ecosystem) || extension.Equals(".csproj", StringComparison.OrdinalIgnoreCase))
            {
                ecosystems.Add(ecosystem ?? "NuGet");
                manifests.Add(System.IO.Path.GetRelativePath(rootPath, file));
            }

            if (ExtensionLanguages.TryGetValue(extension, out var language))
            {
                languages.Add(language);
            }

            if (name.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".dockerfile", StringComparison.OrdinalIgnoreCase))
            {
                containers = true;
            }

            if (extension.Equals(".tf", StringComparison.OrdinalIgnoreCase) || extension.Equals(".bicep", StringComparison.OrdinalIgnoreCase))
            {
                iac = true;
            }
        }

        return new ProjectProfile(ecosystems, languages, manifests, containers, iac);
    }

    /// <summary>Every file under <paramref name="root"/>, skipping dependency, build and VCS directories.</summary>
    public static IEnumerable<string> EnumerateFiles(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            IEnumerable<string> files, subdirectories;
            try
            {
                files = Directory.EnumerateFiles(directory);
                subdirectories = Directory.EnumerateDirectories(directory);
            }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException)
            {
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }

            foreach (var subdirectory in subdirectories)
            {
                if (!SkippedDirectories.Contains(System.IO.Path.GetFileName(subdirectory)))
                {
                    pending.Push(subdirectory);
                }
            }
        }
    }
}

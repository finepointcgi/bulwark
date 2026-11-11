using System.Text.RegularExpressions;
using Nightjar.Core.Findings;

namespace Nightjar.Core.Dependencies;

/// <summary>
/// Cheap, honest reachability: is a vulnerable package imported anywhere in first-party code?
/// <see cref="Findings.Reachability.NotImported"/> does NOT prove safety (the package may be pulled in by another
/// dependency); it means no first-party file imports it directly, which usually lowers urgency.
/// Symbol-level call analysis is deliberately out of scope here.
/// </summary>
public static partial class ReachabilityAnalyzer
{
    private static readonly string[] SkipDirectories = ["node_modules", ".git", "bin", "obj", "vendor", "dist", "build", ".venv", "venv", "__pycache__", "target", "packages"];
    private const long MaxFileBytes = 1_000_000;

    private static readonly Dictionary<string, string[]> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ["npm"] = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"],
        ["PyPI"] = [".py"],
        ["Go"] = [".go"],
        ["NuGet"] = [".cs", ".vb", ".fs"],
    };

    /// <summary>PyPI distribution names whose import name differs.</summary>
    private static readonly Dictionary<string, string> PyModuleAliases = new(StringComparer.Ordinal)
    {
        ["pyyaml"] = "yaml", ["pillow"] = "pil", ["beautifulsoup4"] = "bs4", ["scikit_learn"] = "sklearn", ["opencv_python"] = "cv2",
        ["python_dateutil"] = "dateutil", ["protobuf"] = "google", ["attrs"] = "attr", ["pycryptodome"] = "crypto", ["pyjwt"] = "jwt",
        ["msgpack_python"] = "msgpack", ["python_jose"] = "jose", ["pymysql"] = "pymysql", ["psycopg2_binary"] = "psycopg2",
    };

    public static IReadOnlyList<Finding> Annotate(string root, IReadOnlyList<Finding> findings)
    {
        var wanted = findings
            .Where(f => f.Category == FindingCategory.Vulnerability && f.Package is not null && Extensions.ContainsKey(f.Package.Ecosystem))
            .Select(f => f.Package!.Ecosystem)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (wanted.Count == 0)
        {
            return findings;
        }

        var imports = wanted.ToDictionary(e => e, e => CollectImports(root, e), StringComparer.OrdinalIgnoreCase);

        return findings.Select(f =>
        {
            if (f.Category != FindingCategory.Vulnerability || f.Package is not { } package || !imports.TryGetValue(package.Ecosystem, out var used))
            {
                return f;
            }

            return f with { Reachability = IsImported(package, used) ? Findings.Reachability.Imported : Findings.Reachability.NotImported };
        }).ToList();
    }

    public static bool IsImported(PackageRef package, IReadOnlyCollection<string> imports)
    {
        switch (package.Ecosystem.ToLowerInvariant())
        {
            case "npm":
                return imports.Any(i => i == package.Name || i.StartsWith(package.Name + "/", StringComparison.Ordinal));
            case "pypi":
                var module = package.Name.ToLowerInvariant().Replace('-', '_').Replace('.', '_');
                if (PyModuleAliases.TryGetValue(module, out var alias)) { module = alias; }
                return imports.Any(i => { var top = i.Split('.')[0].ToLowerInvariant(); return top == module || top == module.Replace("python_", ""); });
            case "go":
                return imports.Any(i => i == package.Name || i.StartsWith(package.Name + "/", StringComparison.Ordinal));
            case "nuget":
                // Namespaces conventionally start with the package id (Newtonsoft.Json → Newtonsoft.Json).
                return imports.Any(i => i == package.Name || i.StartsWith(package.Name + ".", StringComparison.OrdinalIgnoreCase)
                    || i.StartsWith(package.Name.Split('.')[0] + ".", StringComparison.OrdinalIgnoreCase) && package.Name.Split('.').Length == 1);
            default:
                return true;
        }
    }

    internal static HashSet<string> CollectImports(string root, string ecosystem)
    {
        var results = new HashSet<string>(StringComparer.Ordinal);
        var extensions = Extensions[ecosystem];
        foreach (var file in Walk(root, extensions))
        {
            string text;
            try { text = File.ReadAllText(file); } catch (IOException) { continue; }
            foreach (var import in Extract(ecosystem, text))
            {
                results.Add(import);
            }
        }

        return results;
    }

    private static IEnumerable<string> Extract(string ecosystem, string text)
    {
        switch (ecosystem.ToLowerInvariant())
        {
            case "npm":
                foreach (Match m in NpmImport().Matches(text)) { yield return PackageOf(m.Groups[1].Value); }
                break;
            case "pypi":
                foreach (Match m in PyImport().Matches(text)) { yield return m.Groups[1].Value; }
                break;
            case "go":
                foreach (Match m in GoImport().Matches(text)) { yield return m.Groups[1].Value; }
                break;
            case "nuget":
                foreach (Match m in CsUsing().Matches(text)) { yield return m.Groups[1].Value; }
                break;
        }
    }

    /// <summary>"lodash/fp" → "lodash"-style prefixes are matched later; relative paths are dropped.</summary>
    private static string PackageOf(string specifier) => specifier;

    private static IEnumerable<string> Walk(string root, string[] extensions)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            IEnumerable<string> subdirectories, files;
            try
            {
                subdirectories = Directory.EnumerateDirectories(directory);
                files = Directory.EnumerateFiles(directory);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var sub in subdirectories)
            {
                if (!SkipDirectories.Contains(Path.GetFileName(sub), StringComparer.OrdinalIgnoreCase))
                {
                    pending.Push(sub);
                }
            }

            foreach (var file in files)
            {
                if (extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase) && new FileInfo(file).Length <= MaxFileBytes)
                {
                    yield return file;
                }
            }
        }
    }

    [GeneratedRegex("""(?:from\s+|import\s+|require\(\s*|import\(\s*)['"]([^./'"][^'"]*)['"]""")]
    private static partial Regex NpmImport();

    [GeneratedRegex(@"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", RegexOptions.Multiline)]
    private static partial Regex PyImport();

    [GeneratedRegex("""^\s*(?:import\s+)?(?:[\w.]+\s+)?"([\w.\-]+(?:/[\w.\-~]+)+)"\s*$""", RegexOptions.Multiline)]
    private static partial Regex GoImport();

    [GeneratedRegex(@"^\s*(?:global\s+)?using\s+(?:static\s+)?(?:\w+\s*=\s*)?([A-Za-z_][\w.]*)\s*;", RegexOptions.Multiline)]
    private static partial Regex CsUsing();
}

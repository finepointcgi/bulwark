using System.Security.Cryptography;
using System.Text;

namespace Bulwark.Core.Reports;

/// <summary>
/// Keeps the latest report for each scanned project under BULWARK_HOME/reports, outside
/// the scanned repo, so scanning never dirties a working tree. The dashboard reads from here.
/// </summary>
public sealed class ReportArchive(string homeDirectory)
{
    public string Directory { get; } = Path.Combine(homeDirectory, "reports");

    public string Save(ScanReport report)
    {
        System.IO.Directory.CreateDirectory(Directory);
        var path = Path.Combine(Directory, $"{KeyFor(report.Project)}.json");
        File.WriteAllText(path, report.ToJson());
        return path;
    }

    /// <summary>The last saved report for a project, or null.</summary>
    public ScanReport? Load(string project)
    {
        var path = Path.Combine(Directory, $"{KeyFor(project)}.json");
        try { return File.Exists(path) ? ScanReport.FromJson(File.ReadAllText(path)) : null; }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidDataException or IOException) { return null; }
    }

    /// <summary>Keeps the project's CycloneDX SBOM next to its report so `bulwark monitor` can re-check it.</summary>
    public void SaveSbom(string project, Sbom.SoftwareBillOfMaterials sbom)
    {
        System.IO.Directory.CreateDirectory(Directory);
        File.WriteAllText(SbomPath(project), sbom.CycloneDxJson);
    }

    public string SbomPath(string project) => Path.Combine(Directory, $"{KeyFor(project)}.cdx.json");

    /// <summary>Short stable id for a project path, used for file names and dashboard URLs.</summary>
    public static string KeyFor(string project) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(project)))[..16];

    public IReadOnlyList<ScanReport> LoadAll()
    {
        if (!System.IO.Directory.Exists(Directory))
        {
            return [];
        }

        var reports = new List<ScanReport>();
        foreach (var file in System.IO.Directory.EnumerateFiles(Directory, "*.json").Where(f => !f.EndsWith(".cdx.json", StringComparison.Ordinal)))
        {
            try
            {
                reports.Add(ScanReport.FromJson(File.ReadAllText(file)));
            }
            catch (Exception e) when (e is System.Text.Json.JsonException or InvalidDataException or IOException)
            {
                // Skip unreadable or partially written reports instead of breaking the dashboard.
            }
        }

        return reports.OrderByDescending(r => r.StartedAt).ToList();
    }
}

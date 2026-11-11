using System.Globalization;
using Bulwark.Core.Findings;
using Bulwark.Core.Gates;
using Bulwark.Core.Reports;
using Bulwark.Core.Triage;
using Bulwark.Core.Updates;

namespace Bulwark.Cli;

/// <summary>`bulwark triage` plus the triage / new-code steps that run after every scan.</summary>
internal static class TriageCommand
{
    /// <summary>
    /// bulwark triage &lt;finding-id or prefix&gt; false-positive|accepted-risk|confirmed|fixed|reset
    ///     [--reason text] [--expires 2027-01-31] [--project path] [--shared]
    /// </summary>
    public static int Run(Options options)
    {
        var idPrefix = options.Positional.ElementAtOrDefault(0);
        var stateText = options.Positional.ElementAtOrDefault(1);
        if (idPrefix is null || stateText is null)
        {
            Console.Error.WriteLine("usage: bulwark triage <finding-id> false-positive|accepted-risk|confirmed|fixed|reset [--reason text] [--expires yyyy-mm-dd] [--project path] [--shared]");
            return 2;
        }

        var project = Path.GetFullPath(options.Value("project") ?? ".");
        var home = ManifestStore.Default().HomeDirectory;
        var report = new ReportArchive(home).LoadAll().FirstOrDefault(r => r.Project == project)
            ?? throw new ArgumentException($"no scan report for {project}. Run `bulwark scan` there first, or pass --project.");

        var matches = report.Findings.Where(f => f.Id.StartsWith(idPrefix, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count != 1)
        {
            throw new ArgumentException(matches.Count == 0
                ? $"no finding with id starting '{idPrefix}' in the last scan of {project}"
                : $"'{idPrefix}' matches {matches.Count} findings; use more characters of the id");
        }

        var state = TriageStore.ParseState(stateText);
        if (state is TriageState.FalsePositive or TriageState.AcceptedRisk && string.IsNullOrWhiteSpace(options.Value("reason")))
        {
            throw new ArgumentException("--reason is required for false-positive and accepted-risk, so the decision can be reviewed later");
        }

        var finding = matches[0];
        var path = new TriageStore(home).Save(project, new TriageDecision
        {
            FindingId = finding.Id,
            State = state,
            Reason = options.Value("reason"),
            By = Environment.UserName,
            At = DateTimeOffset.UtcNow,
            Expires = options.Value("expires") is { } e ? DateTimeOffset.Parse(e, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal) : null,
            Title = finding.Title,
        }, shared: options.Has("shared"));

        Console.WriteLine($"{finding.Id[..12]} {finding.Title}\n  → {state} (saved to {path})");
        if (options.Has("shared"))
        {
            Console.WriteLine("  Commit .bulwark/triage.json so CI and teammates get the same decision.");
        }

        return 0;
    }

    /// <summary>
    /// After a scan: apply saved triage, then work out which findings are new for --new-only.
    /// Returns null when the gate should consider every finding.
    /// </summary>
    public static (ScanReport Report, IReadOnlySet<string>? NewIds) AfterScan(ScanReport report, Options options, string home)
    {
        var ignore = IgnoreRules.Load(report.Project);
        if (ignore.HasRules)
        {
            var kept = report.Findings.Where(f => !ignore.IsIgnored(f)).ToList();
            if (kept.Count < report.Findings.Count)
            {
                Console.Error.WriteLine($"» {report.Findings.Count - kept.Count} finding(s) in paths listed in {IgnoreRules.FileName}");
            }

            report = report with { Findings = kept };
        }

        report = report with { Findings = new TriageStore(home).Apply(report.Project, report.Findings, DateTimeOffset.UtcNow) };

        var triaged = report.Findings.Count(f => f.Triage is not (TriageState.New or TriageState.Confirmed));
        if (triaged > 0)
        {
            Console.Error.WriteLine($"» {triaged} finding(s) skipped by saved triage (false positive / accepted risk / fixed)");
        }

        IReadOnlySet<string>? newIds = null;
        string? against = null;
        if (options.Value("since") is { } gitRef)
        {
            newIds = NewCodeDetector.SinceGitRef(report.Findings, report.Project, gitRef);
            against = $"changes since {gitRef}";
        }
        else if (options.Value("baseline") is { } baseline)
        {
            var previous = baseline == "last"
                ? new ReportArchive(home).LoadAll().FirstOrDefault(r => r.Project == report.Project)
                : ScanReport.FromJson(File.ReadAllText(baseline));
            if (previous is null)
            {
                Console.Error.WriteLine("» no earlier scan of this project; every finding counts as new");
            }
            else
            {
                newIds = NewCodeDetector.AgainstBaseline(report.Findings, previous);
                against = $"baseline from {previous.StartedAt.ToLocalTime():g}";
            }
        }
        else if (options.Has("new-only"))
        {
            throw new ArgumentException("--new-only needs --since <git-ref> or --baseline <report.json|last>");
        }

        if (newIds is not null)
        {
            Console.Error.WriteLine($"» {newIds.Count} of {report.Findings.Count} finding(s) are new ({against})");
        }

        return (report, newIds);
    }
}

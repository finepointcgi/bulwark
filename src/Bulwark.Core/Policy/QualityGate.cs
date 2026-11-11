using Bulwark.Core.Findings;

namespace Bulwark.Core.Policy;

/// <summary>Pass/fail decision for CI. Fails on any untriaged or confirmed finding at or above the threshold.</summary>
public sealed record QualityGate(Severity FailOn)
{
    public GateResult Evaluate(IEnumerable<Finding> findings)
    {
        var blocking = findings
            .Where(f => f.Severity >= FailOn && f.Triage is TriageState.New or TriageState.Confirmed)
            .ToList();
        return new GateResult(blocking.Count == 0, blocking);
    }
}

public sealed record GateResult(bool Passed, IReadOnlyList<Finding> Blocking);

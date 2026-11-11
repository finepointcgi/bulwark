using Nightjar.Core.Dast;

namespace Nightjar.Engines.Zap;

/// <summary>
/// ZAP's built-in header authentication: it adds the header to every request whose host matches
/// ZAP_AUTH_HEADER_SITE. Passed as environment variables, which ToolRunner hands to docker by
/// name only, so the value never appears on a command line.
/// </summary>
internal static class ZapAuth
{
    public static IReadOnlyDictionary<string, string>? Environment(DastContext context) =>
        context.Auth is not { } auth ? null : new Dictionary<string, string>
        {
            ["ZAP_AUTH_HEADER"] = auth.Name,
            ["ZAP_AUTH_HEADER_VALUE"] = auth.Value,
            ["ZAP_AUTH_HEADER_SITE"] = context.Target.Host,
        };
}

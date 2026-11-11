namespace Bulwark.Cli;

/// <summary>Tiny argument parser: a command, positional args, and --name value / --flag options.</summary>
internal sealed class Options
{
    private readonly Dictionary<string, string?> _named = new(StringComparer.OrdinalIgnoreCase);

    public string Command { get; private init; } = "help";
    public List<string> Positional { get; } = [];

    public string? Value(string name) => _named.GetValueOrDefault(name);
    public bool Has(string name) => _named.ContainsKey(name);

    public static Options Parse(string[] args)
    {
        var options = new Options { Command = args.Length > 0 ? args[0].ToLowerInvariant() : "help" };
        for (var i = 1; i < args.Length; i++)
        {
            var arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                options.Positional.Add(arg);
                continue;
            }

            var name = arg[2..];
            var equals = name.IndexOf('=');
            if (equals >= 0)
            {
                options._named[name[..equals]] = name[(equals + 1)..];
            }
            else if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) && !IsFlag(name))
            {
                options._named[name] = args[++i];
            }
            else
            {
                options._named[name] = null;
            }
        }

        return options;
    }

    private static bool IsFlag(string name) => name is "container";
}

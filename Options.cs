using System.Globalization;

namespace WinCertWatch;

public sealed record Options(string? Input, string Scope, int Days, bool Json, bool Help)
{
    public static Options Parse(string[] args)
    {
        string? input = null;
        string scope = "both";
        int days = 30;
        bool json = false, help = false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < args.Length; i++)
        {
            string flag = args[i];
            if (!seen.Add(flag)) throw new ArgumentException("Duplicate option.");
            string Value()
            {
                if (++i >= args.Length || string.IsNullOrWhiteSpace(args[i]) || args[i].StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException("Missing option value.");
                return args[i];
            }
            switch (flag)
            {
                case "--input": input = Value(); break;
                case "--scope":
                    scope = Value();
                    if (scope is not ("user" or "machine" or "both")) throw new ArgumentException("Scope must be user, machine or both.");
                    break;
                case "--days":
                    if (!int.TryParse(Value(), NumberStyles.None, CultureInfo.InvariantCulture, out days) || days is < 0 or > 3650)
                        throw new ArgumentException("Days must be an integer from 0 to 3650.");
                    break;
                case "--json": json = true; break;
                case "--help": help = true; break;
                default: throw new ArgumentException("Unknown option; use --help.");
            }
        }
        if (input != null && seen.Contains("--scope")) throw new ArgumentException("--scope cannot be used with --input.");
        if (help && args.Length != 1) throw new ArgumentException("Use --help alone.");
        return new(input, scope, days, json, help);
    }
}

using System.Text.Json;
using WinCertWatch;

return Cli.Run(args);

public static class Cli
{
    public const string Help = """
    win-cert-watch 1.0.0 - read-only Windows personal certificate validity inventory
    Usage: win-cert-watch [--scope user|machine|both] [--days 0..3650] [--json]
           win-cert-watch --input REPORT.json [--days 0..3650] [--json]
           win-cert-watch --help
    Default: both CurrentUser\My and LocalMachine\My, 30-day warning window.
    JSON output can be replayed offline on .NET-supported Windows, Linux or macOS.
    Replay recalculates findings at the original capture time; --days defaults to 30.
    Exit: 0 complete report, 2 invalid arguments/input, 3 incomplete evidence,
          4 live mode outside Windows, 130 cancelled. Findings alone do not change exit 0.
    No subjects/names/keys, chain building, network probes, repairs or store writes.
    """;
    public static int Run(string[] args)
    {
        try
        {
            var options = Options.Parse(args);
            if (options.Help) { Console.WriteLine(Help); return 0; }
            using var cancel = new CancellationTokenSource();
            ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancel.Cancel(); };
            Console.CancelKeyPress += handler;
            try
            {
                Report report;
                if (options.Input != null) report = Snapshot.Read(options.Input);
                else
                {
                    if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("Live collection requires Windows; use --input for offline review."); return 4; }
                    var capturedAt = DateTimeOffset.UtcNow;
                    var stores = Collector.Collect(options.Scope, cancel.Token);
                    report = new(1, "win-cert-watch", capturedAt, stores, default, 30, "", []);
                }
                cancel.Token.ThrowIfCancellationRequested();
                report = Analyzer.Analyze(report, options.Days);
                Console.WriteLine(options.Json ? JsonSerializer.Serialize(report, Snapshot.Json) : Analyzer.Text(report));
                return report.Status == "partial" ? 3 : 0;
            }
            finally { Console.CancelKeyPress -= handler; }
        }
        catch (OperationCanceledException) { Console.Error.WriteLine("Cancelled."); return 130; }
        catch (Exception e) when (e is ArgumentException or JsonException or IOException or UnauthorizedAccessException or NotSupportedException)
        { Console.Error.WriteLine("Invalid arguments or inaccessible/invalid input. Use --help. No input content is echoed."); return 2; }
    }
}

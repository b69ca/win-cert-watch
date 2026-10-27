using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Text;

namespace WinCertWatch;

public sealed record CertificateEvidence(string Thumbprint, DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc, bool HasPrivateKey, string[] EkuOids);
public sealed record StoreEvidence(string Location, string Status, int EnumeratedCount,
    int UnreadableCount, CertificateEvidence[] Certificates);
public sealed record Finding(string Id, string Location, string? Thumbprint, string Observation, string NextCheck);
public sealed record Report(int SchemaVersion, string Tool, DateTimeOffset CapturedAtUtc,
    StoreEvidence[] Stores, DateTimeOffset AnalyzedAtUtc, int WarningDays, string Status, Finding[] Findings);

public static partial class Snapshot
{
    public const int MaxBytes = 8 * 1024 * 1024;
    public const int MaxCertificates = 4096;
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 16
    };
    [GeneratedRegex("^[0-9A-F]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex ThumbprintPattern();
    [GeneratedRegex("^[0-2](\\.[0-9]{1,10}){1,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex OidPattern();

    public static Report Read(string path)
    {
        using var input = File.OpenRead(path);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[8192];
        int n;
        while ((n = input.Read(chunk)) != 0)
        {
            if (buffer.Length + n > MaxBytes) throw new ArgumentException("Snapshot exceeds 8 MiB.");
            buffer.Write(chunk, 0, n);
        }
        return Parse(buffer.ToArray());
    }
    public static Report Parse(byte[] bytes)
    {
        if (bytes.Length > MaxBytes) throw new ArgumentException("Snapshot exceeds 8 MiB.");
        // Windows PowerShell 5.1 redirection writes UTF-16LE; PowerShell 7 writes UTF-8.
        // Accept explicit BOMs only, without guessing encodings or replacing bad bytes.
        if (bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) bytes = bytes[3..];
        else if (bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE }))
            bytes = Encoding.UTF8.GetBytes(new UnicodeEncoding(false, true, true).GetString(bytes, 2, bytes.Length - 2));
        else if (bytes.AsSpan().StartsWith(new byte[] { 0xFE, 0xFF }))
            bytes = Encoding.UTF8.GetBytes(new UnicodeEncoding(true, true, true).GetString(bytes, 2, bytes.Length - 2));
        if (bytes.Length > MaxBytes) throw new ArgumentException("Decoded snapshot exceeds 8 MiB.");
        using var doc = JsonDocument.Parse(bytes, new() { MaxDepth = 16 });
        RejectDuplicates(doc.RootElement);
        var report = doc.Deserialize<Report>(Json) ?? throw new ArgumentException("Missing report.");
        Validate(report);
        return report;
    }
    private static void RejectDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new ArgumentException("Duplicate JSON property.");
                RejectDuplicates(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var value in element.EnumerateArray()) RejectDuplicates(value);
    }
    public static void Validate(Report report)
    {
        if (report.SchemaVersion != 1 || report.Tool != "win-cert-watch" || report.CapturedAtUtc == default ||
            report.CapturedAtUtc.Offset != TimeSpan.Zero || report.Stores == null || report.Stores.Length is < 1 or > 2)
            throw new ArgumentException("Unsupported or invalid snapshot envelope.");
        var locations = new HashSet<string>(StringComparer.Ordinal);
        foreach (var store in report.Stores)
        {
            if (store == null || store.Location is not ("CurrentUser" or "LocalMachine") || !locations.Add(store.Location) ||
                store.Status is not ("complete" or "unavailable" or "truncated") ||
                store.EnumeratedCount is < 0 or > 1000000 || store.UnreadableCount < 0 || store.Certificates == null ||
                store.Certificates.Length > MaxCertificates || store.UnreadableCount > store.EnumeratedCount ||
                store.Certificates.Length + store.UnreadableCount > store.EnumeratedCount)
                throw new ArgumentException("Invalid store evidence.");
            if (store.Status == "unavailable" && (store.EnumeratedCount != 0 || store.UnreadableCount != 0 || store.Certificates.Length != 0))
                throw new ArgumentException("Unavailable store must not claim coverage.");
            if (store.Status == "complete" && store.Certificates.Length + store.UnreadableCount != store.EnumeratedCount)
                throw new ArgumentException("Complete store counts disagree.");
            if (store.Status == "truncated" && store.Certificates.Length + store.UnreadableCount >= store.EnumeratedCount)
                throw new ArgumentException("Truncation must indicate omitted certificates.");
            var fingerprints = new HashSet<string>(StringComparer.Ordinal);
            foreach (var cert in store.Certificates)
            {
                if (cert == null || cert.Thumbprint == null || !ThumbprintPattern().IsMatch(cert.Thumbprint) || !fingerprints.Add(cert.Thumbprint) ||
                    cert.NotBeforeUtc == default || cert.NotAfterUtc <= cert.NotBeforeUtc ||
                    cert.NotBeforeUtc.Offset != TimeSpan.Zero || cert.NotAfterUtc.Offset != TimeSpan.Zero ||
                    cert.EkuOids == null || cert.EkuOids.Length > 64 || cert.EkuOids.Distinct(StringComparer.Ordinal).Count() != cert.EkuOids.Length ||
                    cert.EkuOids.Any(x => x == null || !OidPattern().IsMatch(x)))
                    throw new ArgumentException("Invalid certificate evidence.");
            }
        }
    }
}

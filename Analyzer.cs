using System.Globalization;
using System.Text;

namespace WinCertWatch;

public static class Analyzer
{
    public static Report Analyze(Report evidence, int days)
    {
        Snapshot.Validate(evidence);
        if (days is < 0 or > 3650) throw new ArgumentException("Invalid warning days.");
        var findings = new List<Finding>();
        foreach (var store in evidence.Stores.OrderBy(s => s.Location, StringComparer.Ordinal))
        {
            if (store.Status != "complete" || store.UnreadableCount != 0)
                findings.Add(new("coverage-incomplete", store.Location, null,
                    $"Store coverage: {store.Status}; unreadable certificates: {store.UnreadableCount}.",
                    "Check access under the intended account and collection limits; this is not an empty/healthy-store result."));
            foreach (var cert in store.Certificates.OrderBy(c => c.NotAfterUtc).ThenBy(c => c.Thumbprint, StringComparer.Ordinal))
            {
                var at = evidence.CapturedAtUtc;
                if (cert.NotBeforeUtc > at)
                    findings.Add(new("not-yet-valid", store.Location, cert.Thumbprint,
                        "Certificate validity starts after collection time.", "Check the system clock and certificate deployment dates; usage is not established."));
                if (cert.NotAfterUtc < at)
                    findings.Add(new("expired", store.Location, cert.Thumbprint,
                        "Certificate validity ended before collection time.", "Identify consumers by thumbprint and review renewal/bindings. Presence alone does not prove an outage."));
                else if ((cert.NotAfterUtc - at).TotalDays <= days)
                    findings.Add(new("expires-soon", store.Location, cert.Thumbprint,
                        $"Certificate expires within {days.ToString(CultureInfo.InvariantCulture)} days of collection time.",
                        "Review renewal and actual bindings; unused certificates may also appear."));
            }
        }
        bool partial = evidence.Stores.Any(s => s.Status != "complete" || s.UnreadableCount != 0);
        return evidence with { AnalyzedAtUtc = DateTimeOffset.UtcNow, WarningDays = days,
            Status = partial ? "partial" : "complete", Findings = findings.ToArray() };
    }
    public static string Text(Report report)
    {
        var text = new StringBuilder();
        text.AppendLine($"win-cert-watch 1.0.0 | coverage: {report.Status}");
        text.AppendLine($"Captured UTC: {report.CapturedAtUtc:O} | warning window: {report.WarningDays} days");
        text.AppendLine("Validity is assessed at collection time, not replay time. No trust, binding or private-key access test is performed.");
        foreach (var store in report.Stores)
        {
            text.AppendLine($"{store.Location}\\My: {store.Status}, enumerated={store.EnumeratedCount}, readable={store.Certificates.Length}, unreadable={store.UnreadableCount}");
            foreach (var cert in store.Certificates.OrderBy(c => c.NotAfterUtc).ThenBy(c => c.Thumbprint, StringComparer.Ordinal))
                text.AppendLine($"  {cert.Thumbprint} | valid {cert.NotBeforeUtc:O} through {cert.NotAfterUtc:O} | private-key association={cert.HasPrivateKey} | EKU={(cert.EkuOids.Length == 0 ? "not specified" : string.Join(",", cert.EkuOids))}");
        }
        text.AppendLine($"Review findings: {report.Findings.Length}");
        foreach (var f in report.Findings)
            text.AppendLine($"[{f.Id}] {f.Location}\\My {f.Thumbprint ?? "-"}: {f.Observation} Next: {f.NextCheck}");
        text.AppendLine("No findings is not a clean bill of health. Only selected personal stores were examined.");
        return text.ToString();
    }
}

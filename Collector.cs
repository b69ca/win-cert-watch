using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;

namespace WinCertWatch;

public static class Collector
{
    [SupportedOSPlatform("windows")]
    public static StoreEvidence[] Collect(string scope, CancellationToken cancellation)
    {
        var locations = scope switch
        {
            "user" => new[] { StoreLocation.CurrentUser },
            "machine" => new[] { StoreLocation.LocalMachine },
            "both" => new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine },
            _ => throw new ArgumentException("Invalid scope.")
        };
        return locations.Select(location => ReadStore(location, cancellation)).ToArray();
    }
    [SupportedOSPlatform("windows")]
    private static StoreEvidence ReadStore(StoreLocation location, CancellationToken cancellation)
    {
        try
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var all = store.Certificates;
            try
            {
                var certificates = new List<CertificateEvidence>();
                int unreadable = 0;
                foreach (var cert in all.Cast<X509Certificate2>().Take(Snapshot.MaxCertificates))
                {
                    cancellation.ThrowIfCancellationRequested();
                    try { certificates.Add(Project(cert)); }
                    catch (Exception e) when (e is CryptographicException or ArgumentException or InvalidOperationException)
                    { unreadable++; }
                }
                return new(location.ToString(), all.Count > Snapshot.MaxCertificates ? "truncated" : "complete",
                    all.Count, unreadable, certificates.OrderBy(c => c.Thumbprint, StringComparer.Ordinal).ToArray());
            }
            finally { foreach (var cert in all) cert.Dispose(); }
        }
        catch (Exception e) when (e is CryptographicException or UnauthorizedAccessException or System.Security.SecurityException)
        { return new(location.ToString(), "unavailable", 0, 0, []); }
    }
    public static CertificateEvidence Project(X509Certificate2 cert)
    {
        // Deliberately no Subject, Issuer, FriendlyName, SAN, raw certificate or key access.
        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(x => x.EnhancedKeyUsages.Cast<Oid>()).Select(x => x.Value ?? "")
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        if (eku.Length > 64) throw new ArgumentException("Too many EKUs.");
        return new(cert.Thumbprint.ToUpperInvariant(), cert.NotBefore.ToUniversalTime(), cert.NotAfter.ToUniversalTime(), cert.HasPrivateKey, eku);
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using WinCertWatch;

int passed = 0, failed = 0;
void Check(string name, Action action)
{
    try { action(); passed++; Console.WriteLine($"PASS {name}"); }
    catch (Exception e) { failed++; Console.Error.WriteLine($"FAIL {name}: {e.GetType().Name}"); }
}
void Assert(bool value) { if (!value) throw new Exception("Assertion failed"); }
void Reject(Action action)
{
    try { action(); } catch (Exception e) when (e is ArgumentException or JsonException) { return; }
    throw new Exception("Expected rejection");
}
var at = new DateTimeOffset(2026, 10, 27, 12, 0, 0, TimeSpan.Zero);
CertificateEvidence Cert(int before = -30, int after = 60, char id = 'A') => new(new string(id, 40), at.AddDays(before), at.AddDays(after), true, ["1.3.6.1.5.5.7.3.1"]);
Report Evidence(params CertificateEvidence[] certs) => new(1, "win-cert-watch", at,
    [new("CurrentUser", "complete", certs.Length, 0, certs)], at, 30, "complete", []);
Report RoundTrip(Report report) => Snapshot.Parse(JsonSerializer.SerializeToUtf8Bytes(report, Snapshot.Json));
Check("defaults and valid options", () => { var o = Options.Parse([]); Assert(o.Scope == "both" && o.Days == 30); Assert(Options.Parse(["--input", "report.json", "--days", "0", "--json"]).Days == 0); Assert(Options.Parse(["--scope", "machine", "--days", "3650"]).Scope == "machine"); });
Check("unknown duplicate missing and conflicting arguments", () => {
    foreach (var a in new[] { new[]{"--wat"}, new[]{"--days"}, new[]{"--days","-1"}, new[]{"--days","1.1"}, new[]{"--days","3651"}, new[]{"--scope","root"}, new[]{"--json","--json"}, new[]{"--input","a","--scope","user"}, new[]{"--help","--json"} }) Reject(() => Options.Parse(a));
});
Check("healthy and empty stores are complete but no health proof", () => { Assert(Analyzer.Analyze(Evidence(Cert()), 30).Findings.Length == 0); var r = Analyzer.Analyze(Evidence(), 30); Assert(r.Status == "complete" && Analyzer.Text(r).Contains("not a clean bill of health")); });
Check("expired is distinct from soon", () => { var f = Analyzer.Analyze(Evidence(Cert(after:-1)),30).Findings; Assert(f.Length == 1 && f[0].Id == "expired"); });
Check("not yet valid is observed independently", () => { Assert(Analyzer.Analyze(Evidence(Cert(before:1,after:2)),30).Findings.Select(x=>x.Id).SequenceEqual(["not-yet-valid","expires-soon"])); });
Check("expiry boundary inclusive and threshold override", () => { Assert(Analyzer.Analyze(Evidence(Cert(after:30)),30).Findings.Length == 1); Assert(Analyzer.Analyze(Evidence(Cert(after:30)),29).Findings.Length == 0); Assert(Analyzer.Analyze(Evidence(Cert(after:0)),0).Findings.Single().Id == "expires-soon"); });
Check("replay preserves capture time and ignores saved findings", () => { var r = Evidence(Cert()) with { Findings = [new("forged","forged",null,"forged","forged")], Status="forged" }; var actual = Analyzer.Analyze(RoundTrip(r),30); Assert(actual.CapturedAtUtc == at && actual.Findings.Length == 0 && actual.Status == "complete"); });
Check("unavailable store is partial not empty success", () => { var r = Evidence() with { Stores = [new("LocalMachine","unavailable",0,0,[])] }; Assert(Analyzer.Analyze(r,30).Status == "partial"); Assert(Analyzer.Analyze(r,30).Findings.Single().Id == "coverage-incomplete"); });
Check("truncated and unreadable coverage retained", () => { var r = Evidence() with { Stores = [new("LocalMachine","truncated",5000,1,[Cert()])] }; Assert(Analyzer.Analyze(RoundTrip(r),30).Status == "partial"); r = Evidence() with { Stores = [new("CurrentUser","complete",1,1,[])] }; Assert(Analyzer.Analyze(r,30).Status == "partial"); });
Check("strict envelope ownership version null missing unknown", () => {
    var bytes = JsonSerializer.Serialize(Evidence(),Snapshot.Json);
    foreach (var json in new[]{"null","{}",bytes.Replace("win-cert-watch","other-tool"),bytes.Replace("\"schemaVersion\": 1","\"schemaVersion\": 2"),bytes.Replace("\"tool\":", "\"extra\": 1, \"tool\":")}) Reject(()=>Snapshot.Parse(Encoding.UTF8.GetBytes(json)));
    Reject(()=>Snapshot.Validate(Evidence() with { Stores=null! }));
});
Check("duplicate JSON properties rejected at every depth", () => { var json=JsonSerializer.Serialize(Evidence(Cert()),Snapshot.Json); foreach(var text in new[]{json.Replace("\"tool\":","\"tool\": \"win-cert-watch\", \"tool\":"),json.Replace("\"hasPrivateKey\": true","\"hasPrivateKey\": true, \"hasPrivateKey\": false")}) Reject(()=>Snapshot.Parse(Encoding.UTF8.GetBytes(text))); });
Check("malformed thumbprint dates OIDs and duplicates rejected", () => {
    foreach(var c in new[]{Cert() with { Thumbprint="\u001b[31m" },Cert() with{NotAfterUtc=at.AddDays(-31)},Cert() with{NotBeforeUtc=at.ToOffset(TimeSpan.FromHours(1))},Cert() with{EkuOids=["bad"]},Cert() with{EkuOids=["1.2.3","1.2.3"]}}) Reject(()=>RoundTrip(Evidence(c)));
    Reject(()=>RoundTrip(Evidence(Cert(),Cert())));
});
Check("store scope status and count consistency", () => {
    foreach(var s in new[]{new StoreEvidence("Root","complete",0,0,[]),new("CurrentUser","complete",2,0,[]),new("CurrentUser","unavailable",1,0,[Cert()]),new("CurrentUser","truncated",0,0,[]),new("CurrentUser","complete",0,-1,[])}) Reject(()=>RoundTrip(Evidence() with{Stores=[s]}));
    Reject(()=>RoundTrip(Evidence() with{Stores=[]})); Reject(()=>RoundTrip(Evidence() with{Stores=[new("CurrentUser","complete",0,0,[]),new("CurrentUser","complete",0,0,[])]}));
});
Check("size and certificate limits", () => { Reject(()=>Snapshot.Parse(new byte[Snapshot.MaxBytes+1])); Reject(()=>RoundTrip(Evidence(Enumerable.Repeat(Cert(),Snapshot.MaxCertificates+1).ToArray()))); });
Check("PowerShell UTF-8 and UTF-16 BOM snapshots replay strictly", () => {
    var text=JsonSerializer.Serialize(Evidence(Cert()),Snapshot.Json);
    foreach(var encoding in new Encoding[]{new UTF8Encoding(true,true),new UnicodeEncoding(false,true,true),new UnicodeEncoding(true,true,true)})
        Assert(Snapshot.Parse(encoding.GetPreamble().Concat(encoding.GetBytes(text)).ToArray()).Stores[0].Certificates.Length==1);
    Reject(()=>Snapshot.Parse([0xFF,0xFE,0x00]));
});
Check("ordering and cross-store same thumbprint", () => { var r=Evidence(Cert(id:'B'),Cert(after:10)); var result=Analyzer.Analyze(r,30); Assert(result.Findings.Single().Thumbprint==new string('A',40)); var s=r.Stores[0] with{Location="LocalMachine"}; Assert(RoundTrip(r with{Stores=[r.Stores[0],s]}).Stores.Length==2); });
Check("snapshot file round trip and CLI exit codes", () => {
    string dir=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
    try {
        string path=Path.Combine(dir,"report.json"); File.WriteAllBytes(path,JsonSerializer.SerializeToUtf8Bytes(Evidence(Cert()),Snapshot.Json)); Assert(Snapshot.Read(path).Tool=="win-cert-watch");
        var originalOut=Console.Out; var originalError=Console.Error;
        using var output=new StringWriter(); using var errors=new StringWriter(); Console.SetOut(output); Console.SetError(errors);
        try { Assert(Cli.Run(["--input",path,"--json"])==0); Assert(output.ToString().Contains("win-cert-watch")); File.WriteAllBytes(path,JsonSerializer.SerializeToUtf8Bytes(Evidence() with{Stores=[new("CurrentUser","unavailable",0,0,[])]},Snapshot.Json)); Assert(Cli.Run(["--input",path])==3); Assert(Cli.Run(["--days","bad"])==2); if(!OperatingSystem.IsWindows()) Assert(Cli.Run([])==4); }
        finally { Console.SetOut(originalOut); Console.SetError(originalError); }
    } finally { Directory.Delete(dir,true); }
});
Check("certificate projection uses synthetic ephemeral cert without names", () => {
    using var rsa=RSA.Create(2048);
    var request=new CertificateRequest("CN=synthetic.invalid",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new("1.3.6.1.5.5.7.3.1")},false));
    using var cert=request.CreateSelfSigned(at.AddDays(-1),at.AddDays(30));
    var projected=Collector.Project(cert); Assert(projected.HasPrivateKey && projected.Thumbprint.Length==40 && projected.EkuOids.Single()=="1.3.6.1.5.5.7.3.1");
    var json=JsonSerializer.Serialize(projected,Snapshot.Json); Assert(!json.Contains("synthetic") && !json.Contains("subject",StringComparison.OrdinalIgnoreCase) && !json.Contains("rawData"));
    using var publicOnly=X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert)); Assert(!Collector.Project(publicOnly).HasPrivateKey);
});
Check("missing EKU remains unspecified not a usability claim", () => {
    using var rsa=RSA.Create(2048); var request=new CertificateRequest("CN=synthetic.invalid",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1); using var cert=request.CreateSelfSigned(at.AddDays(-1),at.AddDays(30)); Assert(Collector.Project(cert).EkuOids.Length==0);
});
Console.WriteLine($"{passed} behavior groups passed; {failed} failed");
return failed==0 ? 0 : 1;

# win-cert-watch

Read-only Windows personal certificate inventory for renewal reviews and troubleshooting expired or not-yet-valid local certificates. Identifies certificates by thumbprint without collecting subjects, issuers, SANs, account names, friendly names or key material. No network traffic or store changes.

This is **not** an endpoint TLS checker, trust/revocation checker, certificate installer or automatic renewal tool. It complements [win-tls-doctor](https://github.com/b69ca/win-tls-doctor), which checks a remote HTTPS handshake.

## Requirements and installation

Live collection: Windows 11 or Windows Server 2022/2025, under the account whose personal store you intend to inspect. Other Windows versions are not specifically validated. Start without elevation; unavailable stores are reported explicitly. Service accounts and other users have different stores.

Download `win-cert-watch-1.0.0-win-x64.zip` and `SHA256SUMS.txt` from [Releases](https://github.com/b69ca/win-cert-watch/releases), verify the ZIP hash with `Get-FileHash -Algorithm SHA256`, then extract it. The unsigned x64 executable includes .NET 10; no separate runtime or PowerShell is required. Apply your normal unsigned-software policy. CI artifacts are also available from successful [Actions runs](https://github.com/b69ca/win-cert-watch/actions), but expire.

## Examples

```powershell
.\win-cert-watch.exe
.\win-cert-watch.exe --scope machine --days 60
.\win-cert-watch.exe --scope user --json > report.json
.\win-cert-watch.exe --input report.json --days 7
.\win-cert-watch.exe --input report.json --json
.\win-cert-watch.exe --help
```

JSON is both a report and the offline input format. Offline analysis works on Windows, Linux and macOS with .NET 10 or a suitable build. Captured evidence and capture time are preserved; saved findings/status are ignored and recalculated. Analysis is always relative to **capture time**, not today's date. Recollect to assess current state. `--days` defaults to 30 even when replaying a report created with a different window.

## Options

| Option | Meaning |
| --- | --- |
| `--scope user\|machine\|both` | Personal (`My`) stores only; default both. Not permitted with `--input`. |
| `--days N` | Inclusive expiry warning window, integer 0–3650; default 30. |
| `--json` | Versioned structured report; stdout contains only JSON. |
| `--input FILE` | Replay this tool's JSON, at most 8 MiB, with strict schema/evidence validation. |
| `--help` | Usage without collection; use alone. |

Unknown/duplicate options, missing values, duplicate JSON properties, foreign tools/schema versions, unknown properties, invalid dates/OIDs/thumbprints, contradictory counts and excessive arrays are rejected. Errors are generic: untrusted file contents, exception details and paths are not echoed. Output is plain text without ANSI escapes.

Exit codes: **0** complete report, even with expired certificates; **2** invalid arguments or inaccessible/invalid snapshot; **3** partial evidence (JSON/text report still produced); **4** live collection attempted outside Windows; **130** cancelled. Automation must inspect coverage and findings, not assume exit 0 means healthy.

## Output interpretation

Each store reports enumerated/readable/unreadable counts and `complete`, `unavailable` or `truncated` coverage. At most 4096 certificates per store are projected. `partial` includes any unavailable, omitted or unreadable evidence; it is never silently treated as an empty healthy store.

Each readable certificate includes its standard SHA-1 Windows thumbprint (an **identifier**, not a cryptographic security endorsement), UTC validity interval, private-key association flag and EKU OIDs. Missing EKU is recorded as unspecified, not interpreted as proof of an intended application. A `true` private-key flag says there is an association; the tool never opens/exports the private key and does not prove the caller or a service can use it. A public-only certificate is not automatically a fault.

Stable finding IDs:

- `expired`: NotAfter is before capture time.
- `not-yet-valid`: NotBefore is after capture time; review system clock/deployment dates.
- `expires-soon`: NotAfter is at/after capture time and within the requested window (exact equality is included).
- `coverage-incomplete`: store access, projection failures or a collection bound prevented full coverage.

Findings describe observations and next checks, not root causes. Old unused certificates may be expired. No IIS/HTTP.sys/RDP/VPN bindings, service identity, consumers, chain trust, revocation, hostname suitability or private-key permissions are established. Root, intermediate, WebHosting, smart-card/service-specific and remote stores are excluded; archived certificates are not requested. No findings is not a clean bill of health.

To identify a certificate locally, use the reported location/thumbprint in your normal certificate-management console (`certmgr.msc` for current user, `certlm.msc` for machine). Example of a separate, read-only administrator command:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
```

That separate command may display identifying metadata; do not paste its output into public issues.

## Privacy and safety

Store access uses `.NET X509Store` with `ReadOnly | OpenExistingOnly`; it does not create stores. There are no imports, deletes, repairs, PFX handling, raw certificate exports, chain building, HTTP calls, telemetry or uploads. Only stdout redirection requested by the operator creates a report. Thumbprints, validity dates, EKUs and key-association flags can still fingerprint infrastructure: review before sharing. Reports do not include hostnames, usernames or raw error messages.

Collection disposes certificate/store handles. Cancellation is checked between certificates; synchronous Windows store open/enumeration cannot be interrupted by this process while inside an OS call. The native collection is materialized before the 4096-item projection cap, so this is not a strict native-memory or wall-clock limit. Enumeration is not transactional; certificates may change concurrently. Inaccessible or malformed entries are partial evidence, not a diagnosis of why access failed.

## Build, test and troubleshoot

Install the .NET 10 SDK separately; no NuGet runtime/test packages are used.

```powershell
dotnet build WinCertWatch.csproj -c Release
dotnet run --project tests/Checks.csproj -c Release
dotnet run --project WinCertWatch.csproj -c Release -- --help
dotnet run --project WinCertWatch.csproj -c Release -- --input tests/fixture.json
dotnet run --project WinCertWatch.csproj -c Release -- --input tests/fixture.json --days 7 --json
./scripts/Package-Windows.ps1
./scripts/Smoke-Windows.ps1 -Executable ./artifacts/publish/win-cert-watch.exe
```

Run the dependency-free checks with `dotnet run`, not `dotnet test`. Windows CI exercises real personal-store collection, independently compares counts/thumbprints/metadata, verifies stores were not changed, replays saved evidence and checks a packaged executable. Synthetic ephemeral certificate projection tests cover nonempty evidence without adding/removing any certificate in a live store. An empty hosted runner store is explicitly reported; fixtures cover expiry cases. CI does not establish all policy, locale, domain, certificate-provider or Windows-version combinations.

For exit 3, check the intended account/store permissions and coverage counts; elevation is not a guaranteed fix. For exit 2, use a fresh unmodified JSON report from this tool, within the size bound. For expiry findings, verify capture time, clock and actual bindings before planning changes. No repair command is suggested or executed automatically.

## License

MIT. See LICENSE. Microsoft API references: [store opening flags](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.openflags), [HasPrivateKey](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.hasprivatekey).

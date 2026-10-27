param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$exe = (Resolve-Path -LiteralPath $Executable).Path
$tempDir = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir | Out-Null
$reportPath = Join-Path $tempDir 'snapshot.json'
function Inventory {
    $result = @{}
    foreach ($location in @('CurrentUser','LocalMachine')) {
        $store = New-Object Security.Cryptography.X509Certificates.X509Store('My', $location)
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
            $certs = $store.Certificates
            try {
                $result[$location] = @($certs | ForEach-Object {
                    [PSCustomObject]@{ thumbprint=$_.Thumbprint; notBeforeUtc=$_.NotBefore.ToUniversalTime(); notAfterUtc=$_.NotAfter.ToUniversalTime(); hasPrivateKey=$_.HasPrivateKey }
                } | Sort-Object thumbprint)
            } finally { foreach($cert in $certs) { $cert.Dispose() } }
        } finally { $store.Dispose() }
    }
    return $result
}
try {
    $before = Inventory
    $raw = & $exe --json
    if ($LASTEXITCODE -ne 0) { throw 'Hosted runner live collection must have complete coverage.' }
    $rawText = $raw -join "`n"
    $report = $rawText | ConvertFrom-Json
    [IO.File]::WriteAllText($reportPath, $rawText, (New-Object Text.UTF8Encoding($false)))
    if ($report.tool -ne 'win-cert-watch' -or $report.schemaVersion -ne 1 -or $report.status -ne 'complete' -or @($report.stores).Count -ne 2) { throw 'Invalid live envelope.' }
    foreach($store in $report.stores) {
        $allowedStore = @('location','status','enumeratedCount','unreadableCount','certificates')
        if (@(Compare-Object $allowedStore @($store.PSObject.Properties.Name)).Count -ne 0) { throw 'Unexpected store metadata.' }
        $expected = @($before[$store.location])
        if ($store.status -ne 'complete' -or $store.unreadableCount -ne 0 -or $store.enumeratedCount -ne $expected.Count -or @($store.certificates).Count -ne $expected.Count) { throw 'Independent certificate count mismatch.' }
        foreach($cert in $store.certificates) {
            $allowedCert = @('thumbprint','notBeforeUtc','notAfterUtc','hasPrivateKey','ekuOids')
            if (@(Compare-Object $allowedCert @($cert.PSObject.Properties.Name)).Count -ne 0) { throw 'Unexpected identifying certificate metadata.' }
            $match = @($expected | Where-Object thumbprint -eq $cert.thumbprint)
            if ($match.Count -ne 1 -or $match[0].hasPrivateKey -ne $cert.hasPrivateKey -or [datetimeoffset]$match[0].notBeforeUtc -ne [datetimeoffset]$cert.notBeforeUtc -or [datetimeoffset]$match[0].notAfterUtc -ne [datetimeoffset]$cert.notAfterUtc) { throw 'Independent metadata mismatch.' }
        }
    }
    $replayText = & $exe --input $reportPath --json
    if ($LASTEXITCODE -ne 0) { throw 'Replay failed.' }
    $replay = ($replayText -join "`n") | ConvertFrom-Json
    if (($report.stores | ConvertTo-Json -Depth 10 -Compress) -ne ($replay.stores | ConvertTo-Json -Depth 10 -Compress) -or ($report.findings | ConvertTo-Json -Depth 10 -Compress) -ne ($replay.findings | ConvertTo-Json -Depth 10 -Compress) -or $report.capturedAtUtc -ne $replay.capturedAtUtc) { throw 'Replay changed evidence/findings.' }
    & $exe --input $reportPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Text replay failed.' }
    & $exe --input $reportPath --days 7 --json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Threshold override failed.' }
    & $exe --scope user --json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'User scope failed.' }
    & $exe --scope machine --json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Machine scope failed.' }
    $after = Inventory
    foreach ($location in @('CurrentUser','LocalMachine')) {
        if (($before[$location] | ConvertTo-Json -Depth 5 -Compress) -ne ($after[$location] | ConvertTo-Json -Depth 5 -Compress)) { throw 'Certificate-store inventory changed during smoke test.' }
    }
    $total = @($report.stores | ForEach-Object {$_.certificates}).Count
    Write-Output "Windows live collection, independent inventory, privacy whitelist, unchanged stores, offline replay and scope checks passed. Certificates=$total."
} finally {
    if (Test-Path -LiteralPath $reportPath) { Remove-Item -LiteralPath $reportPath -Force }
    Remove-Item -LiteralPath $tempDir -Force
}

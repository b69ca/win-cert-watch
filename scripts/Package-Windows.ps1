param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$project = Join-Path $PSScriptRoot '../WinCertWatch.csproj'
$publish = Join-Path $PSScriptRoot '../artifacts/publish'
$dist = Join-Path $PSScriptRoot '../artifacts/dist'
if (Test-Path $publish) { throw 'Publish directory already exists; use a clean checkout or remove only artifacts/publish before packaging.' }
if (Test-Path $dist) { throw 'Distribution directory already exists; use a clean checkout or remove only artifacts/dist before packaging.' }
New-Item -ItemType Directory -Path $dist -Force | Out-Null
dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o $publish
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
Copy-Item (Join-Path $PSScriptRoot '../README.md'),(Join-Path $PSScriptRoot '../LICENSE'),(Join-Path $PSScriptRoot '../CHANGELOG.md') -Destination $publish
$expected = @('CHANGELOG.md','LICENSE','README.md','win-cert-watch.exe')
$actual = @(Get-ChildItem -LiteralPath $publish -File | Select-Object -ExpandProperty Name | Sort-Object)
if (@(Compare-Object $expected $actual).Count -ne 0 -or @(Get-ChildItem -LiteralPath $publish -Directory).Count -ne 0) { throw 'Unexpected distribution contents.' }
$zip = Join-Path $dist 'win-cert-watch-1.0.0-win-x64.zip'
Compress-Archive -Path (Join-Path $publish '*') -DestinationPath $zip
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS.txt'), "$hash  win-cert-watch-1.0.0-win-x64.zip`n", (New-Object Text.UTF8Encoding($false)))
Write-Output 'Standalone package created with an explicit four-file manifest and SHA-256 checksum.'

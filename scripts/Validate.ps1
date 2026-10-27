$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    dotnet build WinCertWatch.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    dotnet run --project tests/Checks.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Checks failed.' }
    dotnet run --project WinCertWatch.csproj -c Release --no-build -- --help
    if ($LASTEXITCODE -ne 0) { throw 'Help failed.' }
    dotnet run --project WinCertWatch.csproj -c Release --no-build -- --input tests/fixture.json
    if ($LASTEXITCODE -ne 0) { throw 'Text fixture failed.' }
    dotnet run --project WinCertWatch.csproj -c Release --no-build -- --input tests/fixture.json --days 7 --json
    if ($LASTEXITCODE -ne 0) { throw 'JSON fixture failed.' }
} finally { Pop-Location }

$ErrorActionPreference = 'Stop'
$module = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../go-onec'))
Push-Location $module
try {
    & go test ./...
    if ($LASTEXITCODE) { throw 'Active tests failed' }
    & go vet ./...
    if ($LASTEXITCODE) { throw 'Vet failed' }
    $taskBinary = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'bin/onec.exe' } else { 'bin/onec' }
    & go build -trimpath -buildvcs=false -o $taskBinary ./cmd/onec
    if ($LASTEXITCODE) { throw 'CLI build failed' }
} finally { Pop-Location }

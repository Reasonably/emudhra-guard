# Tests only a temporary custom certificate store, never Root/CA/Disallowed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/../windows.ps1"

function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Expect-Error([scriptblock]$Code, [string]$Message) {
    $failed = $false
    try { & $Code | Out-Null } catch { $failed = $true }
    Assert $failed $Message
}

$originalOpen = ${function:Open-CertStore}
$script:testStore = 'EmudhraGuardTest-' + [Guid]::NewGuid().ToString('N')
$script:testDirectory = Join-Path $env:LOCALAPPDATA $script:testStore
$script:realLocalAppData = $env:LOCALAPPDATA
$env:LOCALAPPDATA = $script:testDirectory
$certificates = @(Read-Certificates)
$unrelatedPem = [IO.File]::ReadAllText("$PSScriptRoot/unrelated.pem")
$unrelatedDer = [Convert]::FromBase64String(($unrelatedPem -replace '-----[^\r\n]+-----', '' -replace '\s', ''))
$unrelated = [Security.Cryptography.X509Certificates.X509Certificate2]::new($unrelatedDer)

function Open-CertStore([string]$Name, [string]$Location, [bool]$Writable) {
    $null = $Name; $null = $Location
    & $originalOpen $script:testStore 'CurrentUser' $Writable
}

try {
    $seed = Open-CertStore 'Disallowed' 'CurrentUser' $true
    try { $seed.Add($certificates[0].Certificate); $seed.Add($unrelated) } finally { $seed.Dispose() }
    $before = Read-Index 'Disallowed' 'CurrentUser'
    $status = @(Get-GuardStatus $certificates 'CurrentUser')
    Assert (@($status | Where-Object Status -eq 'DENY').Count -eq 1) 'Check reported the wrong count.'
    Assert ((Read-Index 'Disallowed' 'CurrentUser').Count -eq $before.Count) 'Check mutated the store.'

    Block-Certificates $certificates 'CurrentUser'
    $blocked = Read-Index 'Disallowed' 'CurrentUser'
    Assert ($blocked.Count -eq 24) 'Block lost a certificate or did not add all targets.'
    $backupFiles = @(Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'emudhra-guard/backups') -Filter '*.json')
    Assert ($backupFiles.Count -eq 1) 'Expected one backup.'
    $backup = Read-BlockBackup $backupFiles[0].FullName $certificates
    Assert (@($backup.Added).Count -eq 22) 'Backup included a pre-existing block.'
    Block-Certificates $certificates 'CurrentUser'
    Assert (@(Get-ChildItem -LiteralPath $backupFiles[0].DirectoryName -Filter '*.json').Count -eq 1) 'Second block wrote another backup.'

    Restore-Certificates $certificates $backup
    $restored = Read-Index 'Disallowed' 'CurrentUser'
    Assert ($restored.Count -eq 2) 'Restore removed a pre-existing certificate.'
    Assert ($restored.ContainsKey($certificates[0].Sha256)) 'Restore removed a pre-existing target block.'
    Assert ($restored.ContainsKey((Get-Sha256 $unrelated.RawData))) 'Restore removed an unrelated certificate.'
    Restore-Certificates $certificates $backup

    $badBackupPath = Join-Path $script:testDirectory 'bad-backup.json'
    $bad = $backup | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    $bad.Added = @('A' * 64)
    $bad | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $badBackupPath -Encoding UTF8
    Expect-Error { Read-BlockBackup $badBackupPath $certificates } 'Unknown restore target was accepted.'
    $bad.ComputerName = 'another-computer'
    $bad | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $badBackupPath -Encoding UTF8
    Expect-Error { Read-BlockBackup $badBackupPath $certificates } 'A foreign backup was accepted.'

    $realData = $DataPath
    $DataPath = Join-Path $script:testDirectory 'corrupt.tsv'
    [IO.File]::WriteAllText($DataPath, 'corrupt')
    Expect-Error { Read-Certificates } 'Corrupt certificate payload was accepted.'
    $DataPath = $realData
    Write-Host 'PASS: native isolated-store check, block, idempotency, selective restore, backup and payload validation.'
} finally {
    $cleanup = & $originalOpen $script:testStore 'CurrentUser' $true
    try { foreach ($cert in @($cleanup.Certificates)) { $cleanup.Remove($cert) } }
    finally { $cleanup.Dispose() }
    $env:LOCALAPPDATA = $script:realLocalAppData
    foreach ($item in $certificates) { $item.Certificate.Dispose() }
    $unrelated.Dispose()
    if (Test-Path -LiteralPath $script:testDirectory) { Remove-Item -LiteralPath $script:testDirectory -Recurse -Force }
}

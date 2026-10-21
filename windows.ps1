#requires -Version 5.1
# SPDX-License-Identifier: MIT
[CmdletBinding()]
param(
    [ValidateSet('Check', 'Block', 'Restore')][string]$Action = 'Check',
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$Scope = 'CurrentUser',
    [string]$BackupPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$DataSha256 = '55BC7E540EA13BF8614F473E4E6A475C990F596EFD3E8820B4E6CD52A8D759BA'
$DataPath = Join-Path $PSScriptRoot 'data/certificates.tsv'

function Get-Sha256([byte[]]$Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '') }
    finally { $hash.Dispose() }
}

function Read-Certificates {
    if ((Get-Sha256 ([IO.File]::ReadAllBytes($DataPath))) -ne $DataSha256) {
        throw 'Certificate data checksum mismatch.'
    }
    $result = @()
    foreach ($line in ([IO.File]::ReadAllLines($DataPath) | Select-Object -Skip 1)) {
        $fields = $line.Split("`t")
        if ($fields.Count -ne 4 -or $fields[0] -cnotmatch '^[A-F0-9]{64}$' -or $fields[1] -cnotmatch '^[A-F0-9]{40}$') {
            throw 'Invalid certificate row.'
        }
        $bytes = [Convert]::FromBase64String($fields[3])
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
        if ((Get-Sha256 $bytes) -cne $fields[0] -or $cert.Thumbprint -cne $fields[1]) {
            throw "Certificate fingerprint mismatch: $($fields[2])"
        }
        $result += [pscustomobject]@{ Sha256 = $fields[0]; Name = $fields[2]; Certificate = $cert }
    }
    if ($result.Count -ne 23 -or @($result.Sha256 | Select-Object -Unique).Count -ne 23) { throw 'Expected 23 unique certificates.' }
    return $result
}

function Open-CertStore([string]$Name, [string]$Location, [bool]$Writable) {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new($Name, $Location)
    $flags = [Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
    if ($Writable) { $flags = [Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite }
    try { $store.Open($flags); return $store }
    catch {
        $store.Dispose()
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if (-not $Writable -and $cause.HResult -eq -2146885628) { return $null }
        throw
    }
}

function Get-StoreIndex($Store) {
    $index = @{}
    if ($null -ne $Store) {
        foreach ($cert in $Store.Certificates) { $index[(Get-Sha256 $cert.RawData)] = $cert }
    }
    return $index
}

function Read-Index([string]$Name, [string]$Location) {
    $store = Open-CertStore $Name $Location $false
    try { return Get-StoreIndex $store }
    finally { if ($null -ne $store) { $store.Dispose() } }
}

function Get-GuardStatus($Certificates, [string]$Location) {
    $blocked = Read-Index 'Disallowed' $Location
    $roots = Read-Index 'Root' $Location
    $intermediates = Read-Index 'CA' $Location
    foreach ($item in $Certificates) {
        [pscustomobject]@{
            Status = $(if ($blocked.ContainsKey($item.Sha256)) { 'DENY' } else { 'NOT_CONFIGURED' })
            PresentInRootOrCA = ($roots.ContainsKey($item.Sha256) -or $intermediates.ContainsKey($item.Sha256))
            Name = $item.Name
        }
    }
}

function Save-BlockBackup([string]$Location, [string[]]$Added) {
    $base = $env:LOCALAPPDATA
    if ($Location -eq 'LocalMachine') { $base = $env:ProgramData }
    if ([string]::IsNullOrWhiteSpace($base)) { throw 'Backup location is unavailable.' }
    $directory = Join-Path $base 'emudhra-guard/backups'
    $null = [IO.Directory]::CreateDirectory($directory)
    $path = Join-Path $directory ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N') + '.json')
    $backup = [ordered]@{
        Version = 1; Scope = $Location; ComputerName = $env:COMPUTERNAME
        UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        DataSha256 = $DataSha256; Added = @($Added)
    }
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($backup | ConvertTo-Json -Depth 4))
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    return $path
}

function Block-Certificates($Certificates, [string]$Location) {
    $before = Read-Index 'Disallowed' $Location
    $added = @($Certificates | Where-Object { -not $before.ContainsKey($_.Sha256) })
    if ($added.Count -eq 0) { Write-Host 'Already blocked. No changes made.'; return }
    $path = Save-BlockBackup $Location @($added.Sha256)
    Write-Host "Backup: $path"
    $store = Open-CertStore 'Disallowed' $Location $true
    try {
        foreach ($item in $added) { $store.Add($item.Certificate) }
        $after = Get-StoreIndex $store
        foreach ($item in $Certificates) {
            if (-not $after.ContainsKey($item.Sha256)) { throw "Block verification failed: $($item.Name)" }
        }
    } finally { $store.Dispose() }
    Write-Host 'Blocked all 23 certificates. Restart browsers to refresh cached trust decisions.'
}

function Read-BlockBackup([string]$Path, $Certificates) {
    $backup = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path) | ConvertFrom-Json
    if ($backup.Version -ne 1 -or $backup.DataSha256 -cne $DataSha256 -or $backup.Scope -notin @('CurrentUser', 'LocalMachine')) {
        throw 'Invalid backup or different certificate list.'
    }
    if ($backup.ComputerName -ne $env:COMPUTERNAME) { throw 'Backup belongs to another computer.' }
    if ($backup.Scope -eq 'CurrentUser' -and $backup.UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        throw 'Backup belongs to another Windows account.'
    }
    $allowed = @($Certificates.Sha256)
    foreach ($sha256 in @($backup.Added)) {
        if ($sha256 -cnotmatch '^[A-F0-9]{64}$' -or $sha256 -cnotin $allowed) { throw 'Backup contains an unknown certificate.' }
    }
    return $backup
}

function Restore-Certificates($Certificates, $Backup) {
    $before = Read-Index 'Disallowed' $Backup.Scope
    $remove = @($Backup.Added | Where-Object { $before.ContainsKey($_) })
    if ($remove.Count -eq 0) { Write-Host 'Already restored. No changes made.'; return }
    $store = Open-CertStore 'Disallowed' $Backup.Scope $true
    try {
        foreach ($sha256 in $remove) { $store.Remove($before[$sha256]) }
        $after = Get-StoreIndex $store
        foreach ($sha256 in $remove) {
            if ($after.ContainsKey($sha256)) { throw 'Restore verification failed.' }
        }
    } finally { $store.Dispose() }
    Write-Host "Restored $($remove.Count) entries. Pre-existing blocks were retained."
}

function Invoke-Guard {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This script requires Windows.' }
    $certificates = @(Read-Certificates)
    try {
        $backup = $null
        if ($Action -eq 'Restore') {
            if ([string]::IsNullOrWhiteSpace($BackupPath)) { throw 'Restore requires -BackupPath.' }
            $backup = Read-BlockBackup $BackupPath $certificates
            $Scope = $backup.Scope
        } elseif ($BackupPath) { throw '-BackupPath is only used with Restore.' }
        if ($Scope -eq 'LocalMachine' -and $Action -ne 'Check') {
            $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
            if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'LocalMachine changes require an administrator PowerShell.' }
        }
        switch ($Action) {
            'Check' {
                $status = @(Get-GuardStatus $certificates $Scope)
                $status | Format-Table -AutoSize | Out-Host
                $count = @($status | Where-Object Status -eq 'DENY').Count
                Write-Host "Scope: $Scope | Explicit local blocks: $count/23. NOT_CONFIGURED is not a vulnerability verdict."
                if ($count -ne 23) { return 2 }
            }
            'Block' { Block-Certificates $certificates $Scope }
            'Restore' { Restore-Certificates $certificates $backup }
        }
        return 0
    } finally { foreach ($item in $certificates) { $item.Certificate.Dispose() } }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { exit (Invoke-Guard) }
    catch { Write-Error -ErrorAction Continue $_; exit 1 }
}

[CmdletBinding()]
param(
    [string]$BackupDirectory = "backups"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$fileName = "counterstrike-{0}.dump" -f (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$containerPath = "/tmp/$fileName"

if ([System.IO.Path]::IsPathRooted($BackupDirectory)) {
    $resolvedBackupDirectory = [System.IO.Path]::GetFullPath($BackupDirectory)
} else {
    $resolvedBackupDirectory = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $BackupDirectory))
}

New-Item -ItemType Directory -Path $resolvedBackupDirectory -Force | Out-Null
$backupPath = Join-Path $resolvedBackupDirectory $fileName
$checksumPath = "$backupPath.sha256"
if ((Test-Path -LiteralPath $backupPath) -or (Test-Path -LiteralPath $checksumPath)) {
    throw "Refusing to overwrite an existing backup file."
}

Push-Location $repositoryRoot
try {
    $dumpCommand = "pg_dump --format=custom --no-owner --no-acl --username=counterstrike --dbname=counterstrike --file='$containerPath'"
    & docker compose exec -T db sh -c $dumpCommand
    if ($LASTEXITCODE -ne 0) {
        throw "PostgreSQL backup failed with exit code $LASTEXITCODE."
    }

    & docker compose cp "db:$containerPath" $backupPath
    if ($LASTEXITCODE -ne 0) {
        throw "Copying the database backup from the container failed with exit code $LASTEXITCODE."
    }

    $backup = Get-Item -LiteralPath $backupPath
    if ($backup.Length -le 0) {
        Remove-Item -LiteralPath $backupPath -Force
        throw "The database backup is empty."
    }

    $checksum = Get-FileHash -LiteralPath $backupPath -Algorithm SHA256
    "{0}  {1}" -f $checksum.Hash.ToLowerInvariant(), $fileName |
        Set-Content -LiteralPath $checksumPath -Encoding ascii
    Write-Output "Database backup created: $backupPath"
    Write-Output "SHA-256 checksum: $checksumPath"
    Write-Warning "The dump is not encrypted by pg_dump. Store it only on encrypted storage with restricted access."
} finally {
    try {
        & docker compose exec -T db rm -f $containerPath 2>$null | Out-Null
    } catch {
        # The container may have stopped; the temporary file is inside its disposable layer.
    }
    Pop-Location
}

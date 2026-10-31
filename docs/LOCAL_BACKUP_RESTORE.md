# Local PostgreSQL backup and restore

This procedure backs up the Compose PostgreSQL database and verifies a restore in a separate Compose project. It does not define production retention, off-site replication, RPO/RTO, or an audit archive; those decisions remain part of PLN-04 and OPS-02.

## What the backup contains

The custom-format `pg_dump` contains the Counterstrike database, including run/job records, audit events and stream head, LLM usage metadata, and encrypted prompt/response artifacts. It does not contain the `output-data` volume or application secrets. LLM artifact decryption after restore requires the same `LLM_AUDIT_ENCRYPTION_KEY` and key version that were active when each artifact was encrypted. Keep keys in a separate approved secret store; never place them beside the dump.

`pg_dump` does not encrypt the backup file. Write the destination to encrypted storage with access restricted to authorized operators. The backup script also writes a SHA-256 checksum for transfer/integrity checks; a checksum does not provide confidentiality or prove who created the file.

## Create a backup

Start the local Compose stack and wait for the database health check. From the repository root, run:

```powershell
./scripts/backup.ps1
```

To select an encrypted external destination:

```powershell
./scripts/backup.ps1 -BackupDirectory 'D:\CounterstrikeBackups'
```

The script runs `pg_dump` inside the database container and copies the binary custom-format file to the selected directory; it never redirects binary output through PowerShell. It refuses to overwrite a same-named file and writes a `.sha256` sidecar.

## Verify a restore in an isolated Compose project

Choose a backup file and verify its checksum before restoring:

```powershell
$backup = (Resolve-Path 'D:\CounterstrikeBackups\counterstrike-YYYYMMDDTHHMMSSZ.dump').Path
$expected = (Get-Content "$backup.sha256" -Raw).Trim().Split(' ')[0]
$actual = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'Backup checksum mismatch.' }
```

Use a unique project name and a subnet that does not overlap the running stack. These commands restore into a separate named volume, not the active `counterstrike` database:

```powershell
$env:COMPOSE_SUBNET = '172.16.241.0/24'
$env:API_PORT = '18001'
docker compose -p counterstrike-restore-check up -d db
docker compose -p counterstrike-restore-check cp $backup db:/tmp/restore.dump
docker compose -p counterstrike-restore-check exec -T db pg_restore --username=counterstrike --dbname=counterstrike --no-owner --no-acl /tmp/restore.dump
```

Before starting the API, configure the restore process with the original LLM artifact encryption key and key version in the trusted local `.env`; do not pass them as command-line arguments. Set `LOCAL_DEV_ROLE=admin` for local verification so the audit integrity and privileged artifact routes are available. Then start the API and check readiness and audit integrity:

```powershell
docker compose -p counterstrike-restore-check up -d api
Invoke-RestMethod 'http://127.0.0.1:18001/health/ready'
Invoke-RestMethod 'http://127.0.0.1:18001/api/v1/audit/integrity'
```

When retained LLM artifacts exist, inspect one through the purpose-required content endpoint and confirm decryption succeeds. The read is itself appended to the restored audit trail:

```powershell
$calls = Invoke-RestMethod 'http://127.0.0.1:18001/api/v1/llm/usage?limit=1'
if ($calls.items.Count -gt 0) {
    $callId = $calls.items[0].id
    $body = @{ kind = 'request'; purpose = 'Verify restored artifact decryption' } | ConvertTo-Json
    Invoke-RestMethod -Method Post -ContentType 'application/json' -Body $body `
        "http://127.0.0.1:18001/api/v1/llm/usage/$callId/content"
}
```

Stop only the isolated verification project when finished. Check the project name before removing its volume; `down --volumes` deletes the restored verification database:

```powershell
docker compose -p counterstrike-restore-check ps
docker compose -p counterstrike-restore-check down --volumes
```

This restore exercise is not production recovery acceptance. Record elapsed restore time, data completeness, key availability, audit-chain status, and any missing external dependencies in OPS-02/OPS-05 before relying on it operationally.

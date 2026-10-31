# Database migrations

Alembic is the only supported mechanism for changing the persistent schema.
Application startup does not create or alter tables from SQLAlchemy metadata.
The migration environment loads the same `Base.metadata` as the ORM models and
compares column types during drift checks.

## Local development

Set `DATABASE_URL` to a disposable database, then run:

```powershell
alembic upgrade head
alembic current
alembic check
```

Use `alembic history` to review the revision chain. Keep each schema change in
a new, reviewed revision. If a local downgrade is needed, use only a disposable
database whose data can be lost; then upgrade back to `head` and inspect the
result. A downgrade is not the ordinary rollback path for production data.

Revision `0005_artifact_purge` refuses to downgrade if any LLM artifact has
already been purged. Removing `purged_at` in that state would hide a durable
erasure and cause content reads to treat a purged record like a decryptable
artifact.

Revision `0006_outbox_delivery_lease` refuses to downgrade while any outbox row
is actively delivering. Stop delivery workers and resolve or expire active
leases before using a disposable local downgrade.

Revision `0007_outbox_daily_digest` makes `outbox_messages.run_id` nullable so a
digest can represent a time window spanning multiple runs. It refuses to
downgrade while any run-less outbox message exists; archive or remove those
digest rows before a disposable local downgrade. Production recovery remains
forward-only regardless of whether these guards permit a local downgrade.

## Production recovery

Production schema changes are forward-only. Deploy a compatible application
version and apply reviewed migrations with the migration role. If a release
must be reversed, deploy a compatible application build or create a corrective
forward migration. Use a verified backup restore only into a separately named
recovery environment first; do not downgrade the live database as a substitute
for restoring known-good state.

Before production use, verify the backup/restore runbook, migration-role
privileges, migration lock behavior, and the expected recovery point and time.
The platform, retention, and production migration approvals remain tracked in
`PLN-04`, `DB-03`, and `OPS-02`.

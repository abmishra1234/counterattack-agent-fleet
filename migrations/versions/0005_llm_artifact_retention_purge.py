"""Allow auditable ciphertext erasure after configured artifact expiry."""

import sqlalchemy as sa
from alembic import op

revision = "0005_artifact_purge"
down_revision = "0004_llm_call_pricing_date"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "llm_exchange_artifacts",
        sa.Column("purged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute("DROP TRIGGER trg_llm_artifacts_no_update ON llm_exchange_artifacts")
    op.execute(
        """CREATE FUNCTION counterstrike_allow_llm_artifact_purge() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.purged_at IS NULL
               AND NEW.purged_at IS NOT NULL
               AND OLD.encrypted_payload <> decode('', 'hex')
               AND NEW.encrypted_payload = decode('', 'hex')
               AND (to_jsonb(OLD) - 'encrypted_payload' - 'purged_at')
                   IS NOT DISTINCT FROM
                   (to_jsonb(NEW) - 'encrypted_payload' - 'purged_at') THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'LLM artifacts are immutable except for one retention purge';
        END;
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_llm_artifacts_purge_only
        BEFORE UPDATE ON llm_exchange_artifacts
        FOR EACH ROW EXECUTE FUNCTION counterstrike_allow_llm_artifact_purge()"""
    )
    op.execute(
        """CREATE TRIGGER trg_llm_artifacts_no_delete
        BEFORE DELETE ON llm_exchange_artifacts
        FOR EACH ROW EXECUTE FUNCTION counterstrike_reject_audit_mutation()"""
    )


def downgrade() -> None:
    purged_count = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM llm_exchange_artifacts WHERE purged_at IS NOT NULL")
    )
    if purged_count:
        raise RuntimeError(
            "Cannot downgrade artifact purge after ciphertext has been purged; "
            "restore a verified pre-purge backup or roll forward"
        )
    op.execute("DROP TRIGGER trg_llm_artifacts_no_delete ON llm_exchange_artifacts")
    op.execute("DROP TRIGGER trg_llm_artifacts_purge_only ON llm_exchange_artifacts")
    op.execute("DROP FUNCTION counterstrike_allow_llm_artifact_purge()")
    op.execute(
        """CREATE TRIGGER trg_llm_artifacts_no_update
        BEFORE UPDATE ON llm_exchange_artifacts
        FOR EACH ROW EXECUTE FUNCTION counterstrike_reject_audit_mutation()"""
    )
    op.drop_column("llm_exchange_artifacts", "purged_at")

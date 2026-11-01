"""Track each advisory-asset finding once across runs.

Alert rows remain the per-run history. Existing alerts are folded into one finding per
alert_key, pointing at the most recent alert row.
"""

from alembic import op

revision = "0008_findings"
down_revision = "0007_outbox_daily_digest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE findings (
            id VARCHAR(36) PRIMARY KEY,
            finding_key VARCHAR(200) NOT NULL,
            cve_id VARCHAR(80) NOT NULL,
            asset_key VARCHAR(160) NOT NULL,
            latest_alert_id VARCHAR(36) NOT NULL REFERENCES alerts(id),
            first_run_id VARCHAR(36) NOT NULL REFERENCES runs(id),
            last_run_id VARCHAR(36) NOT NULL REFERENCES runs(id),
            priority VARCHAR(8) NOT NULL,
            risk_score NUMERIC(8, 3) NOT NULL,
            status VARCHAR(24) NOT NULL DEFAULT 'open',
            occurrences INTEGER NOT NULL DEFAULT 1,
            first_seen_at TIMESTAMPTZ NOT NULL,
            last_seen_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT uq_finding_key UNIQUE (finding_key)
        )"""
    )
    op.execute("CREATE INDEX ix_findings_status_last_seen ON findings (status, last_seen_at)")
    op.execute(
        """INSERT INTO findings (
            id, finding_key, cve_id, asset_key, latest_alert_id, first_run_id, last_run_id,
            priority, risk_score, status, occurrences, first_seen_at, last_seen_at
        )
        SELECT gen_random_uuid()::text, alert_key, cve_id, asset_key, id, first_run_id, run_id,
            priority, risk_score, 'open', occurrences, first_seen_at, created_at
        FROM (
            SELECT a.*,
                row_number() OVER (
                    PARTITION BY alert_key ORDER BY created_at DESC, id DESC
                ) AS newest,
                first_value(run_id) OVER (
                    PARTITION BY alert_key ORDER BY created_at, id
                    ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                ) AS first_run_id,
                min(created_at) OVER (PARTITION BY alert_key) AS first_seen_at,
                count(*) OVER (PARTITION BY alert_key) AS occurrences
            FROM alerts a
        ) ranked
        WHERE newest = 1"""
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS findings")

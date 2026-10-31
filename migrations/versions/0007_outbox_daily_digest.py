"""Allow outbox messages that summarize a UTC alert window."""

import sqlalchemy as sa
from alembic import op

revision = "0007_outbox_daily_digest"
down_revision = "0006_outbox_delivery_lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "outbox_messages",
        "run_id",
        existing_type=sa.String(length=36),
        nullable=True,
    )


def downgrade() -> None:
    digest_rows = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM outbox_messages WHERE run_id IS NULL")
    )
    if digest_rows:
        raise RuntimeError(
            "Cannot require run_id while daily digest outbox messages exist; "
            "archive or remove digest messages before downgrading"
        )
    op.alter_column(
        "outbox_messages",
        "run_id",
        existing_type=sa.String(length=36),
        nullable=False,
    )

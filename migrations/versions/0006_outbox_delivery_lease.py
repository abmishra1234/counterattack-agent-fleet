"""Add delivery leases for the asynchronous channel sender."""

import sqlalchemy as sa
from alembic import op

revision = "0006_outbox_delivery_lease"
down_revision = "0005_artifact_purge"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("outbox_messages", sa.Column("delivery_worker_id", sa.String(200)))
    op.add_column(
        "outbox_messages", sa.Column("delivery_started_at", sa.DateTime(timezone=True))
    )
    op.add_column(
        "outbox_messages",
        sa.Column("delivery_lease_expires_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_outbox_delivery_lease",
        "outbox_messages",
        ["status", "delivery_lease_expires_at"],
    )


def downgrade() -> None:
    active_deliveries = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM outbox_messages WHERE status = 'delivering'")
    )
    if active_deliveries:
        raise RuntimeError(
            "Cannot remove delivery lease columns while outbox messages are delivering; "
            "stop workers and resolve or expire their leases first"
        )
    op.drop_index("ix_outbox_delivery_lease", table_name="outbox_messages")
    op.drop_column("outbox_messages", "delivery_lease_expires_at")
    op.drop_column("outbox_messages", "delivery_started_at")
    op.drop_column("outbox_messages", "delivery_worker_id")

"""Link each metered attempt to the effective pricing date used."""

import sqlalchemy as sa
from alembic import op

revision = "0004_llm_call_pricing_date"
down_revision = "0003_llm_pricing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "llm_calls",
        sa.Column("pricing_effective_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("llm_calls", "pricing_effective_at")

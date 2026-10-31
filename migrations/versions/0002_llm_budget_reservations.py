"""Persist conservative per-attempt LLM budget reservations."""

import sqlalchemy as sa
from alembic import op

revision = "0002_llm_budget"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "llm_calls",
        sa.Column("budget_estimate_usd", sa.Numeric(20, 10), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("llm_calls", "budget_estimate_usd")

"""Store immutable effective-dated LLM pricing versions."""

from alembic import op

revision = "0003_llm_pricing"
down_revision = "0002_llm_budget"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE llm_pricing_rates (
            id VARCHAR(36) PRIMARY KEY,
            provider VARCHAR(80) NOT NULL,
            model VARCHAR(160) NOT NULL,
            pricing_version VARCHAR(80) NOT NULL,
            effective_from TIMESTAMPTZ NOT NULL,
            input_rate_per_million NUMERIC(18, 8) NOT NULL,
            output_rate_per_million NUMERIC(18, 8) NOT NULL,
            currency VARCHAR(8) NOT NULL DEFAULT 'USD',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_llm_pricing_provider_model_version
                UNIQUE(provider, model, pricing_version),
            CONSTRAINT uq_llm_pricing_provider_model_effective
                UNIQUE(provider, model, effective_from)
        )"""
    )
    op.execute(
        "CREATE INDEX ix_llm_pricing_effective "
        "ON llm_pricing_rates(provider, model, effective_from)"
    )
    op.execute(
        """CREATE TRIGGER trg_llm_pricing_rates_immutable
        BEFORE UPDATE OR DELETE ON llm_pricing_rates
        FOR EACH ROW EXECUTE FUNCTION counterstrike_reject_audit_mutation()"""
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS llm_pricing_rates CASCADE")

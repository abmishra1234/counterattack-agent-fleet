from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from counterstrike import llm_metering
from counterstrike.db_models import LLMCall


@pytest.mark.parametrize(
    ("usage", "input_rate", "expected"),
    [
        ({"prompt_tokens": 1000, "completion_tokens": 500}, Decimal("0.15"), Decimal("0.00045")),
        ({"prompt_tokens": 0, "completion_tokens": 0}, Decimal("0.15"), Decimal("0")),
        ({"prompt_tokens": 1000}, Decimal("0.15"), None),
        ({"prompt_tokens": 1000, "completion_tokens": 500}, None, None),
    ],
)
def test_cost_uses_separate_per_million_rates(monkeypatch, usage, input_rate, expected):
    record = LLMCall(
        id="call",
        task="summarise",
        input_rate_per_million=input_rate,
        output_rate_per_million=Decimal("0.60"),
    )
    monkeypatch.setattr(llm_metering, "_lock_pending_attempt", lambda *args: record)
    monkeypatch.setattr(llm_metering, "store_artifact", MagicMock())
    monkeypatch.setattr(llm_metering, "append_event", MagicMock())
    llm_metering.complete_attempt(
        MagicMock(),
        record,
        settings=MagicMock(),
        raw_response="{}",
        usage=usage,
        response_id="response",
        latency_ms=10,
    )
    assert record.cost_amount == expected
    assert record.cost_currency == ("USD" if expected is not None else None)
    assert record.outcome == "succeeded"

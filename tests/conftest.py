import json
from pathlib import Path

import pytest

from counterstrike.agents.extract import extract_agent
from counterstrike.agents.ingest import ingest_agent
from counterstrike.llm import FakeLLM

DATA = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture
def data_dir() -> Path:
    return DATA


@pytest.fixture
def gold() -> dict:
    return json.loads((DATA / "gold" / "expected_alerts.json").read_text())


@pytest.fixture
def base_state(data_dir) -> dict:
    state = {"data_dir": str(data_dir), "needs_human": [], "trace": []}
    state.update(ingest_agent(state))
    return state


@pytest.fixture
def extracted_state(base_state) -> dict:
    state = dict(base_state)
    out = extract_agent(state, FakeLLM())
    state["extracted"] = out["extracted"]
    state["needs_human"] = out["needs_human"]
    return state

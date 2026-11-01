import json
from pathlib import Path

import pytest

from counterstrike.agents.extract import extract_agent
from counterstrike.agents.ingest import ingest_agent
from counterstrike.llm import FakeLLM

DATA = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(autouse=True, scope="session")
def offline_environment():
    """Keep local credentials and deployment switches out of offline tests and children."""
    from counterstrike.config import Settings

    with pytest.MonkeyPatch.context() as patch:
        for name, field in Settings.model_fields.items():
            key = name.upper() if name != "environment" else "COUNTERSTRIKE_ENV"
            default = field.default
            if default is None:
                default = ""
            elif isinstance(default, bool):
                default = str(default).lower()
            patch.setenv(key, str(default))
        patch.delenv("COUNTERSTRIKE_LLM", raising=False)
        yield


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


@pytest.fixture
def db_settings(tmp_path, monkeypatch):
    from counterstrike.config import Settings
    from counterstrike.db import get_engine
    from counterstrike.db_models import Base

    url = f"sqlite:///{(tmp_path / 'service.db').as_posix()}"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    settings = Settings(database_url=url, out_dir=tmp_path / "out", local_dev_role="admin")
    engine = get_engine(settings)
    Base.metadata.create_all(engine)
    yield settings
    engine.dispose()


@pytest.fixture
def persisted_run(db_settings, data_dir):
    from counterstrike.db import session_scope
    from counterstrike.graph import run
    from counterstrike.repositories import create_run, mark_run_started, persist_run_results

    state = run(data_dir, db_settings.out_dir, FakeLLM(), settings=db_settings)
    with session_scope(db_settings) as session:
        record = create_run(
            session, trigger_type="manual", actor_id="tester", request_id="req-test"
        )
        mark_run_started(session, record.id)
        persist_run_results(session, record.id, state, settings=db_settings)
        return record.id, state

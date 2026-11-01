import json

import pytest

from counterstrike.cli import main
from counterstrike.evaluate import evaluate, gate
from counterstrike.graph import run
from counterstrike.llm import FakeLLM


def test_full_fleet_matches_gold(tmp_path, data_dir, gold):
    run(data_dir, tmp_path, FakeLLM())
    metrics = evaluate(tmp_path, data_dir / "gold" / "expected_alerts.json")
    assert gate(metrics, 1.0, 1.0, 1.0) == []
    report = json.loads((tmp_path / "run_report.json").read_text())
    assert [t["agent"] for t in report["trace"]] == [
        "fixture_feed",
        "ingest",
        "extract",
        "correlate",
        "score",
        "remediate",
        "dispatch",
    ]
    assert (tmp_path / "outbox" / "team-payments.md").exists()


def test_inputs_are_never_modified(tmp_path, data_dir):
    before = {p.name: p.read_bytes() for p in data_dir.glob("*.json")}
    run(data_dir, tmp_path, FakeLLM())
    assert before == {p.name: p.read_bytes() for p in data_dir.glob("*.json")}


def test_evaluator_accepts_recorded_cvss_but_rejects_invented_versions(tmp_path, data_dir):
    run(data_dir, tmp_path, FakeLLM())
    path = tmp_path / "alerts.json"
    alerts = json.loads(path.read_text())
    assert all(any(e.startswith("CVSS score: ") for e in a["evidence"]) for a in alerts)
    alerts[0]["summary"] += " Upgrade to 99.88.77."
    path.write_text(json.dumps(alerts))
    metrics = evaluate(tmp_path, data_dir / "gold" / "expected_alerts.json")
    assert metrics["ungrounded_summaries"] == [alerts[0]["alert_id"]]
    assert any("ungrounded" in failure for failure in gate(metrics, 1.0, 1.0, 1.0))


def test_no_match_path_short_circuits_to_dispatch(tmp_path, data_dir):
    d = tmp_path / "data"
    d.mkdir()
    for name in ("advisories.json", "kev.json", "aliases.json"):
        (d / name).write_text((data_dir / name).read_text())
    (d / "inventory.json").write_text(
        json.dumps(
            [
                {
                    "asset_id": "Z",
                    "service": "z",
                    "component": "unknown-lib",
                    "version": "1.0.0",
                    "internet_facing": False,
                    "criticality": "low",
                    "owner": "nobody",
                }
            ]
        )
    )
    out = tmp_path / "out"
    run(d, out, FakeLLM())
    report = json.loads((out / "run_report.json").read_text())
    assert report["alerts"] == 0
    assert "score" not in [t["agent"] for t in report["trace"]]


def test_cli_gate_fails_on_wrong_gold(tmp_path, data_dir, gold):
    out = tmp_path / "out"
    assert main(["run", "--data", str(data_dir), "--out", str(out)]) == 0
    gold["alerts"][0]["priority"] = "P4"
    bad = tmp_path / "bad_gold.json"
    bad.write_text(json.dumps(gold))
    assert main(["eval", "--out", str(out), "--gold", str(bad)]) == 1


def test_generalises_to_hidden_fixture_set(tmp_path, data_dir):
    hidden = data_dir.parent / "grading" / "hidden_data"
    required = (
        hidden / "advisories.json",
        hidden / "inventory.json",
        hidden / "kev.json",
        hidden / "aliases.json",
        hidden / "gold" / "expected_alerts.json",
    )
    if not all(path.is_file() for path in required):
        pytest.skip("trainer-only hidden fixtures are not present in this checkout")
    run(hidden, tmp_path, FakeLLM())
    metrics = evaluate(tmp_path, hidden / "gold" / "expected_alerts.json")
    assert gate(metrics, 1.0, 1.0, 1.0) == []

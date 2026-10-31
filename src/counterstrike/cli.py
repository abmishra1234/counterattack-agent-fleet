"""Command line: `counterstrike run` and `counterstrike eval`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from counterstrike.config import read_dotenv
from counterstrike.evaluate import evaluate, gate, scorecard_md
from counterstrike.graph import run
from counterstrike.llm import get_llm


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="counterstrike", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the agent fleet over a data folder")
    r.add_argument("--data", default="data")
    r.add_argument("--out", default="out")
    r.add_argument(
        "--llm",
        default=None,
        choices=["fake", "gateway", "openai_compatible", "azure_openai"],
    )

    e = sub.add_parser("eval", help="score a run against gold labels and enforce the gate")
    e.add_argument("--out", default="out")
    e.add_argument("--gold", default="data/gold/expected_alerts.json")
    e.add_argument("--min-precision", type=float, default=1.0)
    e.add_argument("--min-recall", type=float, default=1.0)
    e.add_argument("--min-priority-accuracy", type=float, default=1.0)

    args = p.parse_args(argv)
    if args.cmd == "run":
        dotenv = read_dotenv()
        provider = args.llm or os.environ.get(
            "LLM_PROVIDER",
            os.environ.get(
                "COUNTERSTRIKE_LLM",
                dotenv.get("LLM_PROVIDER", dotenv.get("COUNTERSTRIKE_LLM", "fake")),
            ),
        )
        if provider in {"openai_compatible", "azure_openai"}:
            provider = "gateway"
        try:
            llm = get_llm(provider)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        state = run(args.data, args.out, llm)
        report = json.loads((Path(args.out) / "run_report.json").read_text(encoding="utf-8"))
        print(
            f"alerts={report['alerts']} by_priority={report['by_priority']} "
            f"needs_human={report['needs_human']} -> {args.out}/"
        )
        return 0 if state else 1

    metrics = evaluate(args.out, args.gold)
    failures = gate(metrics, args.min_precision, args.min_recall, args.min_priority_accuracy)
    md = scorecard_md(metrics, failures)
    (Path(args.out) / "scorecard.md").write_text(md, encoding="utf-8")
    print(md)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(md)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

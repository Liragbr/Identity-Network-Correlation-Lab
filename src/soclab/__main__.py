"""CLI: run a safe lab scenario, or replay a previously generated evidence file."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detect import correlate
from .lab import run_local_experiment
from .report import write_report
from .telemetry import load_events


def main() -> None:
    parser = argparse.ArgumentParser(prog="soclab", description="SOC defensive evidence and detection lab")
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run", help="execute loopback services and generate auditable events")
    run.add_argument("--output", type=Path, default=Path("artifacts"))
    verify = sub.add_parser("verify", help="recalculate findings from server-produced JSONL")
    verify.add_argument("--events", type=Path, required=True)
    verify.add_argument("--output", type=Path, default=Path("artifacts/verified"))
    args = parser.parse_args()
    if args.action == "run":
        events = run_local_experiment(args.output / "events.jsonl")
        output = args.output
    else:
        events = load_events(args.events)
        output = args.output
    result = correlate(events)
    write_report(events, result, output)
    print(json.dumps({"action": args.action, "events": len(events), "findings": len(result["findings"]),
                      "output": str(output), "categories": sorted({f["category"] for f in result["findings"]})},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

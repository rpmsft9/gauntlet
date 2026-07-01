"""`gauntlet` command line. `run` gates the pipeline; exit code 1 == gate failed."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from gauntlet import __version__
from gauntlet.adapters.demo_agent import DemoAgent
from gauntlet.config import Config
from gauntlet.dashboard import render_dashboard
from gauntlet.engine import run_gauntlet
from gauntlet.history import append as append_history
from gauntlet.history import drift as compute_drift
from gauntlet.history import load_all, load_previous
from gauntlet.llm import make_client
from gauntlet.report import render_console, render_markdown
from gauntlet.scenarios import all_scenarios


def _select(scenarios, include, exclude):
    if include:
        scenarios = [s for s in scenarios if s.id in include]
    if exclude:
        scenarios = [s for s in scenarios if s.id not in exclude]
    return scenarios


def cmd_list(_args: argparse.Namespace) -> int:
    for s in all_scenarios():
        owasp = ", ".join(s.taxonomy.owasp) or "-"
        print(f"{s.id:28} [{s.severity.value:8}] {s.mode:8} {owasp:10} {s.title}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cfg = Config.load(args.config)
    if args.threshold is not None:
        cfg.threshold = args.threshold
    if args.model:
        cfg.model = args.model
    mock = True if args.mock else cfg.mock

    scenarios = _select(all_scenarios(), cfg.include, cfg.exclude)
    if not scenarios:
        print("No scenarios selected.", file=sys.stderr)
        return 2

    client = make_client(mock=mock, model=cfg.model)
    using_mock = client.__class__.__name__ == "MockClient"
    if using_mock and not args.quiet:
        print("! No API key found - running in MOCK mode (synthetic results).\n", file=sys.stderr)

    report = run_gauntlet(
        scenarios,
        client,
        adapter_factory=lambda c: DemoAgent(c),
        threshold=cfg.threshold,
        attacker_turns=cfg.attacker_turns,
        target_name=DemoAgent.name if isinstance(DemoAgent.name, str) else "target",
    )

    previous = load_previous()
    drift = compute_drift(report, previous)

    if not args.quiet:
        render_console(report, drift)

    if args.json:
        Path(args.json).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    if args.markdown:
        Path(args.markdown).write_text(render_markdown(report, drift), encoding="utf-8")

    # Emit a GitHub Actions job summary when running in CI.
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(render_markdown(report, drift) + "\n")

    if not args.no_history:
        append_history(report, mock=using_mock)

    if args.dashboard:
        Path(args.dashboard).write_text(render_dashboard(load_all()), encoding="utf-8")

    return 0 if report.passed else 1


def cmd_dashboard(args: argparse.Namespace) -> int:
    runs = load_all()
    out = Path(args.out)
    out.write_text(render_dashboard(runs), encoding="utf-8")
    print(f"Wrote {out} ({len(runs)} run(s)).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gauntlet", description="Continuous agentic red-teaming as a CI gate.")
    p.add_argument("--version", action="version", version=f"gauntlet {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="Run the gauntlet and gate on the resilience threshold.")
    r.add_argument("--config", default=None, help="Path to gauntlet.yaml (default: ./gauntlet.yaml).")
    r.add_argument("--threshold", type=float, default=None, help="Override resilience threshold (0-100).")
    r.add_argument("--model", default=None, help="Override the model under test.")
    r.add_argument("--mock", action="store_true", help="Force offline mock mode.")
    r.add_argument("--json", default=None, help="Write the full JSON report to this path.")
    r.add_argument("--markdown", default=None, help="Write a markdown report to this path.")
    r.add_argument("--no-history", action="store_true", help="Do not append to the drift history log.")
    r.add_argument("--dashboard", default=None, help="Write/refresh the HTML drift dashboard at this path.")
    r.add_argument("--quiet", action="store_true", help="Suppress the console report.")
    r.set_defaults(func=cmd_run)

    lst = sub.add_parser("list", help="List available scenarios.")
    lst.set_defaults(func=cmd_list)

    dash = sub.add_parser("dashboard", help="Render the HTML drift dashboard from run history.")
    dash.add_argument("--out", default="gauntlet-dashboard.html", help="Output HTML path.")
    dash.set_defaults(func=cmd_dashboard)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

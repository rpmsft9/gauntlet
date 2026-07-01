"""Self-contained HTML drift dashboard — resilience trend over time.

No external CDN or JS framework: the chart is inline SVG computed in Python, so
the file renders offline and travels cleanly as a CI artifact.
"""

from __future__ import annotations

import html

_W, _H = 820, 320
_PAD_L, _PAD_R, _PAD_T, _PAD_B = 48, 20, 20, 40


def _x(i: int, n: int) -> float:
    if n <= 1:
        return _PAD_L
    span = _W - _PAD_L - _PAD_R
    return _PAD_L + span * i / (n - 1)


def _y(score: float) -> float:
    span = _H - _PAD_T - _PAD_B
    return _PAD_T + span * (1 - max(0.0, min(100.0, score)) / 100.0)


def _svg_chart(runs: list[dict]) -> str:
    n = len(runs)
    threshold = runs[-1].get("threshold", 80) if runs else 80
    parts: list[str] = [f'<svg viewBox="0 0 {_W} {_H}" width="100%" role="img" aria-label="Resilience trend">']

    # gridlines + y labels (0,25,50,75,100)
    for val in (0, 25, 50, 75, 100):
        y = _y(val)
        parts.append(f'<line x1="{_PAD_L}" y1="{y:.1f}" x2="{_W - _PAD_R}" y2="{y:.1f}" class="grid"/>')
        parts.append(f'<text x="{_PAD_L - 8}" y="{y + 4:.1f}" class="ylab">{val}</text>')

    # threshold line
    ty = _y(threshold)
    parts.append(f'<line x1="{_PAD_L}" y1="{ty:.1f}" x2="{_W - _PAD_R}" y2="{ty:.1f}" class="threshold"/>')
    parts.append(f'<text x="{_W - _PAD_R}" y="{ty - 6:.1f}" class="tlab">threshold {threshold}</text>')

    if n:
        pts = [(_x(i, n), _y(r.get("resilience_score", 0))) for i, r in enumerate(runs)]
        poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        parts.append(f'<polyline points="{poly}" class="line"/>')
        for (x, y), r in zip(pts, runs):
            cls = "pass" if r.get("passed") else "fail"
            title = html.escape(
                f"{r.get('started_at', '')}  score {r.get('resilience_score')}  "
                f"breaches {r.get('breaches')}/{r.get('total')}"
            )
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" class="{cls}"><title>{title}</title></circle>')

    parts.append("</svg>")
    return "".join(parts)


def _rows(runs: list[dict]) -> str:
    out: list[str] = []
    for i, r in enumerate(reversed(runs), 1):
        verdict = "PASS" if r.get("passed") else "FAIL"
        cls = "ok" if r.get("passed") else "bad"
        out.append(
            "<tr>"
            f"<td>{len(runs) - i + 1}</td>"
            f"<td>{html.escape(str(r.get('started_at', '')))}</td>"
            f"<td>{html.escape(str(r.get('target_name', '')))}</td>"
            f"<td>{r.get('resilience_score')}</td>"
            f"<td>{r.get('threshold')}</td>"
            f"<td>{r.get('breaches')}/{r.get('total')}</td>"
            f'<td class="{cls}">{verdict}</td>'
            "</tr>"
        )
    return "".join(out)


def render_dashboard(runs: list[dict]) -> str:
    latest = runs[-1] if runs else {}
    score = latest.get("resilience_score", "—")
    verdict = ("PASS" if latest.get("passed") else "FAIL") if runs else "—"
    vcls = "ok" if latest.get("passed") else "bad"
    chart = _svg_chart(runs)
    rows = _rows(runs) or '<tr><td colspan="7">No runs recorded yet. Run <code>gauntlet run</code>.</td></tr>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gauntlet — Resilience Dashboard</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem;
         background: #0f1115; color: #e6e6e6; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
  .sub {{ color: #9aa4b2; margin: 0 0 1.5rem; }}
  .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .card {{ background: #171a21; border: 1px solid #262b36; border-radius: 12px; padding: 1rem 1.25rem; min-width: 150px; }}
  .card .k {{ color: #9aa4b2; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }}
  .card .v {{ font-size: 1.8rem; font-weight: 700; }}
  .panel {{ background: #171a21; border: 1px solid #262b36; border-radius: 12px; padding: 1.25rem; }}
  svg {{ display: block; }}
  .grid {{ stroke: #262b36; stroke-width: 1; }}
  .ylab, .tlab {{ fill: #9aa4b2; font-size: 11px; }}
  .ylab {{ text-anchor: end; }} .tlab {{ text-anchor: end; }}
  .threshold {{ stroke: #d9a441; stroke-width: 1.5; stroke-dasharray: 5 4; }}
  .line {{ fill: none; stroke: #4f9dff; stroke-width: 2.5; }}
  circle.pass {{ fill: #2ec16b; }} circle.fail {{ fill: #ef4d4d; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1.5rem; }}
  th, td {{ text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #262b36; }}
  th {{ color: #9aa4b2; font-weight: 600; font-size: .8rem; text-transform: uppercase; }}
  td.ok {{ color: #2ec16b; font-weight: 700; }} td.bad {{ color: #ef4d4d; font-weight: 700; }}
  .{vcls} {{ }}
  footer {{ color: #6b7280; font-size: .8rem; margin-top: 2rem; }}
</style></head>
<body>
  <h1>🛡️ Gauntlet — Resilience Dashboard</h1>
  <p class="sub">Continuous agentic red-teaming · drift across {len(runs)} run(s)</p>
  <div class="cards">
    <div class="card"><div class="k">Latest score</div><div class="v">{score}</div></div>
    <div class="card"><div class="k">Gate</div><div class="v {vcls}">{verdict}</div></div>
    <div class="card"><div class="k">Runs tracked</div><div class="v">{len(runs)}</div></div>
  </div>
  <div class="panel">{chart}</div>
  <table>
    <thead><tr><th>#</th><th>When</th><th>Target</th><th>Score</th><th>Threshold</th><th>Breaches</th><th>Gate</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <footer>Generated by Gauntlet — resilience is a severity-weighted % of attacks withstood.</footer>
</body></html>
"""

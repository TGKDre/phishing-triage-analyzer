from __future__ import annotations

import csv
import html
from datetime import datetime, timezone
from pathlib import Path

from .models import Analysis

_COLORS = {"malicious": "#b91c1c", "suspicious": "#b45309", "clean": "#15803d"}


def write_csv(results: list[Analysis], path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "file",
                "verdict",
                "score",
                "from",
                "from_domain",
                "spf",
                "dkim",
                "dmarc",
                "indicators",
                "attachments",
                "subject",
            ]
        )
        for r in results:
            writer.writerow(
                [
                    r.path.name,
                    r.verdict,
                    r.score,
                    r.from_addr,
                    r.from_domain,
                    r.auth.spf,
                    r.auth.dkim,
                    r.auth.dmarc,
                    len(r.indicators),
                    "; ".join(a.filename for a in r.attachments),
                    r.subject,
                ]
            )
    return path


def _indicator_rows(r: Analysis) -> str:
    if not r.indicators:
        return "<tr><td colspan='4'>No indicators</td></tr>"
    return "\n".join(
        f"<tr class='{html.escape(i.severity)}'><td>{html.escape(i.severity)}</td>"
        f"<td>{html.escape(i.category)}</td><td class='mono'>{html.escape(i.value)}</td>"
        f"<td>{html.escape(i.detail)}</td></tr>"
        for i in r.indicators
    )


def _attachment_rows(r: Analysis) -> str:
    if not r.attachments:
        return ""
    rows = "\n".join(
        f"<tr><td>{html.escape(a.filename)}</td><td>{html.escape(a.content_type)}</td>"
        f"<td>{a.size}</td><td class='mono'>{a.sha256}</td></tr>"
        for a in r.attachments
    )
    return (
        "<h4>Attachments</h4><table><thead><tr><th>File</th><th>Type</th><th>Bytes</th>"
        f"<th>SHA256</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _card(r: Analysis) -> str:
    color = _COLORS.get(r.verdict, "#333")
    title = html.escape(r.subject or "(no subject)")
    return f"""
    <section class="card">
      <h3><span class="verdict" style="background:{color}">{html.escape(r.verdict)}</span> {title}</h3>
      <p class="muted mono">{html.escape(str(r.path.name))}</p>
      <table class="meta">
        <tr><th>From</th><td>{html.escape(r.from_display)} &lt;{html.escape(r.from_addr)}&gt;</td></tr>
        <tr><th>Return-Path</th><td class="mono">{html.escape(r.return_path or "-")}</td></tr>
        <tr><th>Reply-To</th><td class="mono">{html.escape(r.reply_to or "-")}</td></tr>
        <tr><th>SPF</th><td>{html.escape(r.auth.spf)}</td></tr>
        <tr><th>DKIM</th><td>{html.escape(r.auth.dkim)}</td></tr>
        <tr><th>DMARC</th><td>{html.escape(r.auth.dmarc)}{(' policy ' + html.escape(r.auth.dmarc_policy)) if r.auth.dmarc_policy else ''}</td></tr>
        <tr><th>Score</th><td><strong>{r.score}</strong></td></tr>
      </table>
      <h4>Indicators</h4>
      <table><thead><tr><th>Severity</th><th>Category</th><th>Value</th><th>Detail</th></tr></thead>
      <tbody>{_indicator_rows(r)}</tbody></table>
      {_attachment_rows(r)}
    </section>"""


def write_html(results: list[Analysis], path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = {"malicious": 0, "suspicious": 0, "clean": 0}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    stamp = datetime.now(timezone.utc)

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing triage report</title>
<style>
  body {{ font-family: system-ui, -apple-system, Arial, sans-serif; margin: 2rem; color: #1b1b1b; max-width: 1100px; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .muted {{ color: #666; }}
  .mono {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; word-break: break-all; }}
  .card {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem 1.2rem; margin: 1.2rem 0; }}
  .verdict {{ color: #fff; text-transform: uppercase; font-size: 11px; letter-spacing: 0.06em; padding: 2px 8px; border-radius: 999px; vertical-align: middle; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.4rem 0 0.8rem; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 6px 8px; font-size: 13px; text-align: left; vertical-align: top; }}
  th {{ background: #f3f4f6; }}
  tr.high {{ background: #fde8e8; }}
  tr.medium {{ background: #fef3c7; }}
  tr.low {{ background: #eef2ff; }}
  .meta th {{ width: 140px; }}
</style></head>
<body>
  <h1>Phishing triage report</h1>
  <p class="muted">Generated {stamp:%Y-%m-%d %H:%M UTC} &middot; {len(results)} messages &middot;
    malicious {counts['malicious']}, suspicious {counts['suspicious']}, clean {counts['clean']}</p>
  {''.join(_card(r) for r in results) if results else '<p>No messages analysed.</p>'}
</body></html>"""
    path.write_text(doc, encoding="utf-8")
    return path

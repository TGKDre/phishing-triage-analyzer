from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyze import analyze_many, to_json
from .report import write_csv, write_html

_RANK = {"none": 0, "clean": 0, "suspicious": 1, "malicious": 2}


def collect(input_path: Path) -> list[Path]:
    if input_path.is_dir():
        return sorted(p for p in input_path.rglob("*") if p.is_file() and p.suffix.lower() in {".eml", ".msg"})
    return [input_path]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage .eml files with email authentication checks and indicator scoring.")
    parser.add_argument("--input", required=True, help="An .eml file or a directory of .eml files.")
    parser.add_argument("--out", default="reports", help="Output directory for findings.csv and report.html.")
    parser.add_argument("--dns", action="store_true", help="Also check live DNS for SPF, DMARC and DKIM records.")
    parser.add_argument("--json", action="store_true", help="Write results.json and print it.")
    parser.add_argument(
        "--fail-on",
        choices=["none", "suspicious", "malicious"],
        default="none",
        help="Exit with code 2 when any message reaches this verdict.",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input not found: {input_path}", file=sys.stderr)
        return 2

    files = collect(input_path)
    if not files:
        print(f"No .eml files found under {input_path}", file=sys.stderr)
        return 2

    results = analyze_many(files, dns=args.dns)

    for r in results:
        auth = f"spf={r.auth.spf} dkim={r.auth.dkim} dmarc={r.auth.dmarc}"
        print(f"[{r.verdict:10s} {r.score:3d}] {r.path.name}: {r.from_addr} ({auth}, {len(r.indicators)} indicators)")

    out = Path(args.out)
    csv_path = write_csv(results, out / "findings.csv")
    html_path = write_html(results, out / "report.html")

    counts = {"malicious": 0, "suspicious": 0, "clean": 0}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    print(
        f"Analysed {len(results)} messages: {counts['malicious']} malicious, "
        f"{counts['suspicious']} suspicious, {counts['clean']} clean."
    )
    print(f"Wrote {csv_path} and {html_path}")

    if args.json:
        payload = to_json(results)
        (out / "results.json").write_text(payload + "\n", encoding="utf-8")
        print(payload)

    threshold = _RANK[args.fail_on]
    if threshold and any(_RANK[r.verdict] >= threshold for r in results):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import sys
import time
import uuid
from datetime import UTC, datetime

from .analyzer import analyze
from .collector import collect
from .reports import write_reports
from .scope import TargetError, load_targets


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description="Bounded DNS and HTTP/HTTPS reconnaissance for authorized web targets.",
        epilog="This tool does not brute-force, authenticate, fuzz, follow redirects, or exploit services.",
    )
    parser.add_argument("--target", action="append", default=[], help="Target origin URL or hostname; repeatable.")
    parser.add_argument("--target-file", help="UTF-8 file with one target per line; # starts a comment.")
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="Per-request connect/read timeout, 0.5–10 seconds (default: 5)."
    )
    parser.add_argument("--output-dir", default="reports", help="Directory for JSON, Markdown, and CSV reports.")
    parser.add_argument("--skip-dns", action="store_true", help="Skip DNS record collection.")
    parser.add_argument("--skip-http", action="store_true", help="Skip HTTP and endpoint collection.")
    parser.add_argument("--authorized", action="store_true", help="Acknowledge explicit permission for every target.")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    return parser


def run(args: argparse.Namespace) -> int:
    if not args.authorized:
        print("Refusing to collect target data without --authorized.", file=sys.stderr)
        return 2
    if not 0.5 <= args.timeout <= 10:
        print("Timeout must be between 0.5 and 10 seconds.", file=sys.stderr)
        return 2
    if args.skip_dns and args.skip_http:
        print("At least one collector must remain enabled.", file=sys.stderr)
        return 2
    try:
        targets = load_targets(args.target, args.target_file)
    except TargetError as exc:
        print(f"Invalid target scope: {exc}", file=sys.stderr)
        return 2

    print(f"Collecting authorized reconnaissance for {len(targets)} origin(s).")
    print("Requests are bounded, redirects are not followed, and credentials are never sent.")
    started = time.monotonic()
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    results = collect(targets, args.timeout, args.skip_dns, args.skip_http)
    analyze(results)
    finished_at = datetime.now(UTC).isoformat(timespec="seconds")

    from .models import ScanReport

    report = ScanReport(
        scan_id=uuid.uuid4().hex[:12],
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=time.monotonic() - started,
        targets=results,
    )
    try:
        files = write_reports(report, args.output_dir)
    except OSError as exc:
        print(f"Could not write reports: {exc}", file=sys.stderr)
        return 1

    summary = report.to_dict()["summary"]
    print(
        f"Finished in {report.duration_seconds:.2f}s: {summary['http_responses']} HTTP response(s), "
        f"{summary['endpoints']} endpoint observation(s), {summary['findings']} review lead(s)."
    )
    for path in files:
        print(f"Report: {path.resolve()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("Collection interrupted by the operator.", file=sys.stderr)
        return 130

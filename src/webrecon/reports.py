from __future__ import annotations

import csv
import html
import io
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding, ScanReport


def _md(value: object) -> str:
    text = html.escape(str(value), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text)


def _safe_csv(value: object) -> str:
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _markdown(report: ScanReport) -> str:
    payload = report.to_dict()
    summary = payload["summary"]
    lines = [
        "# Web Security Reconnaissance Report",
        "",
        f"- **Scan ID:** `{_md(report.scan_id)}`",
        f"- **Started (UTC):** {_md(report.started_at)}",
        f"- **Finished (UTC):** {_md(report.finished_at)}",
        f"- **Duration:** {report.duration_seconds:.2f}s",
        f"- **Targets:** {summary['targets']}",
        f"- **HTTP responses:** {summary['http_responses']}",
        f"- **Endpoints collected:** {summary['endpoints']}",
        f"- **Heuristic findings:** {summary['findings']}",
        "",
        "> This report contains reconnaissance observations and low-confidence review leads, "
        "not proof of exploitability.",
        "",
        "## Findings",
        "",
    ]
    findings = [finding for target in report.targets for finding in target.findings]
    if not findings:
        lines.append("No heuristic findings were produced.")
    for finding in findings:
        lines.extend(
            [
                f"### [{_md(finding.severity.upper())}] {_md(finding.title)}",
                "",
                f"- **Rule:** `{_md(finding.rule_id)}`",
                f"- **Source:** {_md(finding.source)}",
                f"- **Confidence:** {_md(finding.confidence)}",
                f"- **Evidence:** {_md(finding.evidence)}",
                f"- **Recommendation:** {_md(finding.recommendation)}",
                "",
            ]
        )
    lines.extend(["## Target inventory", ""])
    for target in report.targets:
        lines.extend(
            [
                f"### `{_md(target.origin)}`",
                "",
                f"- **DNS records:** {len(target.dns)}",
                f"- **HTTP status:** {target.http.status_code if target.http else 'not collected'}",
                "- **Technologies:** "
                + (
                    ", ".join(_md(item) for item in (target.http.technologies if target.http else []))
                    or "none identified"
                ),
                f"- **Endpoints:** {len(target.endpoints)}",
                "",
            ]
        )
        if target.endpoints:
            lines.append("| Path | Source | Status | Requested |")
            lines.append("| --- | --- | ---: | :---: |")
            for endpoint in target.endpoints:
                path = html.escape(endpoint.path, quote=True).replace("|", "&#124;")
                lines.append(
                    f"| <code>{path}</code> | {_md(', '.join(endpoint.discovered_by))} | "
                    f"{endpoint.status_code if endpoint.status_code is not None else '—'} | "
                    f"{'yes' if endpoint.probed else 'no'} |"
                )
            lines.append("")
        if target.warnings:
            lines.append("**Collection warnings:**")
            lines.extend(f"- {_md(item)}" for item in target.warnings)
            lines.append("")
    return "\n".join(lines)


def _csv(findings: list[Finding]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["rule_id", "severity", "confidence", "source", "title", "evidence", "recommendation"])
    for finding in findings:
        writer.writerow(
            [
                _safe_csv(finding.rule_id),
                _safe_csv(finding.severity),
                _safe_csv(finding.confidence),
                _safe_csv(finding.source),
                _safe_csv(finding.title),
                _safe_csv(finding.evidence),
                _safe_csv(finding.recommendation),
            ]
        )
    return output.getvalue()


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8", newline="")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_reports(report: ScanReport, output_dir: str | Path) -> list[Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"recon-{stamp}-{report.scan_id}"
    findings = [finding for target in report.targets for finding in target.findings]
    outputs = {
        directory / f"{stem}.json": json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
        directory / f"{stem}.md": _markdown(report),
        directory / f"{stem}.csv": _csv(findings),
    }
    for path, content in outputs.items():
        _atomic_write(path, content)
    return list(outputs)

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from webrecon.cli import main
from webrecon.models import Finding, ScanReport, TargetResult
from webrecon.reports import write_reports


def test_cli_requires_authorization(capsys) -> None:
    assert main(["--target", "example.com"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_csv_formula_guard_and_markdown_escaping(tmp_path) -> None:
    finding = Finding(
        rule_id="TEST",
        title='=HYPERLINK("https://example.com")',
        severity="low",
        confidence="low",
        evidence="<script>alert(1)</script> `markdown`",
        recommendation="Review safely",
        source="test",
    )
    report = ScanReport(
        scan_id="abc123def456",
        started_at="2026-10-30T00:00:00+00:00",
        finished_at="2026-10-30T00:00:01+00:00",
        duration_seconds=1,
        targets=[TargetResult("https://example.com", "https://example.com", "example.com", findings=[finding])],
    )
    files = write_reports(report, tmp_path)
    payload = json.loads(next(path for path in files if path.suffix == ".json").read_text(encoding="utf-8"))
    schema_path = Path(__file__).parents[1] / "schemas" / "recon-report.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    markdown = next(path for path in files if path.suffix == ".md").read_text(encoding="utf-8")
    csv_text = next(path for path in files if path.suffix == ".csv").read_text(encoding="utf-8")
    assert payload["summary"]["findings"] == 1
    assert "<script>" not in markdown
    assert r"\`markdown\`" in markdown
    assert "'=HYPERLINK" in csv_text

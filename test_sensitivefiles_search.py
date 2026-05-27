import json
from pathlib import Path

import sensitivefiles_search as scanner


def test_dot_env_file_is_scanned_and_redacted(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("PASSWORD=123456\nSAFE=value\n", encoding="utf-8")

    findings, total_files, _ = scanner.scan(
        roots=[tmp_path],
        include_exts=scanner.DEFAULT_EXTENSIONS,
        exclude_dirs=scanner.DEFAULT_EXCLUDE_DIRS,
        exclude_globs=[],
        max_size=1024 * 1024,
        threads=2,
        context_lines=0,
        redact=True,
        keyword=None,
        quiet=True,
    )

    assert total_files == 1
    assert len(findings) == 1
    assert findings[0].rule_id == "weak_password"
    assert findings[0].severity == "high"
    assert "123456" not in findings[0].match
    assert "123456" not in findings[0].context


def test_excluded_directory_is_skipped(tmp_path: Path) -> None:
    skipped = tmp_path / "node_modules"
    skipped.mkdir()
    (skipped / "config.js").write_text("api_key='abcdefghijklmnopqrstuvwxyz'\n", encoding="utf-8")

    findings, total_files, _ = scanner.scan(
        roots=[tmp_path],
        include_exts=scanner.DEFAULT_EXTENSIONS,
        exclude_dirs=scanner.DEFAULT_EXCLUDE_DIRS,
        exclude_globs=[],
        max_size=1024 * 1024,
        threads=1,
        context_lines=0,
        redact=True,
        keyword=None,
        quiet=True,
    )

    assert total_files == 0
    assert findings == []


def test_json_report_contains_summary(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    finding = scanner.Finding(
        file="demo.env",
        line=1,
        rule_id="api_key",
        category="API Key",
        severity="high",
        match="abcd********wxyz",
        context="1: api_key=abcd********wxyz",
    )

    scanner.write_report(report, "json", [finding], total_files=1, elapsed=0.12)
    payload = json.loads(report.read_text(encoding="utf-8"))

    assert payload["summary"]["scanned_files"] == 1
    assert payload["summary"]["findings"] == 1
    assert payload["summary"]["severity"]["high"] == 1
    assert payload["findings"][0]["rule_id"] == "api_key"


def test_cli_writes_report_and_returns_one_when_findings_exist(tmp_path: Path) -> None:
    target = tmp_path / "config.ini"
    report = tmp_path / "out.txt"
    target.write_text("token=abcdefghijklmnopqrstuvwxyz123456\n", encoding="utf-8")

    exit_code = scanner.main([str(tmp_path), "-o", str(report), "--quiet"])

    assert exit_code == 1
    assert report.exists()
    assert "findings: 1" in report.read_text(encoding="utf-8")


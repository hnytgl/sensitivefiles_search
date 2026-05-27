#!/usr/bin/env python3
# coding: utf-8
"""Local sensitive file and secret scanner.

This tool is intended for authorized local security checks. By default it masks
matched secrets in reports to reduce accidental leakage.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import html
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_EXTENSIONS = {
    ".aws",
    ".bash_history",
    ".bashrc",
    ".bat",
    ".cer",
    ".cfg",
    ".conf",
    ".config",
    ".crt",
    ".dockerfile",
    ".env",
    ".ini",
    ".inc",
    ".java",
    ".js",
    ".json",
    ".jsp",
    ".jspx",
    ".key",
    ".kubeconfig",
    ".log",
    ".netrc",
    ".npmrc",
    ".pem",
    ".php",
    ".ps1",
    ".pypirc",
    ".properties",
    ".py",
    ".sh",
    ".sql",
    ".tfvars",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".asp",
    ".aspx",
}

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
}

RULES = [
    {
        "id": "weak_password",
        "category": "弱密码",
        "severity": "high",
        "pattern": r"(?i)(?:\b(?:password|passwd|pwd)\b|密码|口令)\s*[:=]\s*['\"]?(?:123456|12345678|123456789|admin|root|password|qwerty|abc123|111111|000000|passw0rd)['\"]?\b",
    },
    {
        "id": "credential_keyword",
        "category": "凭据关键词",
        "severity": "medium",
        "pattern": r"(?i)(?:\b(?:password|passwd|pwd|username|user|login)\b|账户|用户名|密码|口令)\s*[:=]\s*['\"]?[^'\"\s]{3,}",
    },
    {
        "id": "api_key",
        "category": "API Key",
        "severity": "high",
        "pattern": r"(?i)\b(api[_-]?key|access[_-]?key|secret[_-]?key|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{16,}",
    },
    {
        "id": "github_token",
        "category": "GitHub Token",
        "severity": "critical",
        "pattern": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b",
    },
    {
        "id": "slack_token",
        "category": "Slack Token",
        "severity": "critical",
        "pattern": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    },
    {
        "id": "aws_access_key",
        "category": "AWS Access Key",
        "severity": "critical",
        "pattern": r"\b(AKIA|ASIA)[A-Z0-9]{16}\b",
    },
    {
        "id": "private_key",
        "category": "私钥",
        "severity": "critical",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    },
    {
        "id": "jwt",
        "category": "JWT",
        "severity": "high",
        "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    },
    {
        "id": "database_url",
        "category": "数据库连接",
        "severity": "high",
        "pattern": r"(?i)\b(mysql|postgres|postgresql|mongodb|redis|sqlserver)://[^:\s]+:[^@\s]+@[^/\s]+",
    },
    {
        "id": "jdbc_url",
        "category": "JDBC 连接",
        "severity": "medium",
        "pattern": r"(?i)jdbc:[a-z0-9]+://[^\s\"']+",
    },
    {
        "id": "ip_address",
        "category": "IP 地址",
        "severity": "low",
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    },
    {
        "id": "email",
        "category": "邮箱",
        "severity": "low",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    },
    {
        "id": "id_card_cn",
        "category": "身份证号",
        "severity": "medium",
        "pattern": r"\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b",
    },
    {
        "id": "phone_cn",
        "category": "手机号",
        "severity": "low",
        "pattern": r"\b1[3-9]\d{9}\b",
    },
]

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_LABEL = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "严重",
}


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    category: str
    severity: str
    match: str
    context: str


def color(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def parse_csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def normalize_extensions(values: Iterable[str]) -> set[str]:
    normalized = set()
    for value in values:
        value = value.strip().lower()
        if not value:
            continue
        normalized.add(value if value.startswith(".") else f".{value}")
    return normalized


def compile_rules(keyword: str | None = None) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = [dict(rule, regex=re.compile(str(rule["pattern"]))) for rule in RULES]
    if keyword:
        rules.append(
            {
                "id": "custom_keyword",
                "category": "自定义关键词",
                "severity": "medium",
                "pattern": re.escape(keyword),
                "regex": re.compile(re.escape(keyword), re.IGNORECASE),
            }
        )
    return rules


def should_skip_dir(path: Path, exclude_dirs: set[str]) -> bool:
    return any(part.lower() in exclude_dirs for part in path.parts)


def file_type_key(path: Path) -> str:
    name = path.name.lower()
    if name in DEFAULT_EXTENSIONS:
        return name
    return path.suffix.lower()


def should_skip_file(path: Path, include_exts: set[str], exclude_globs: list[str]) -> bool:
    if include_exts and file_type_key(path) not in include_exts:
        return True
    return any(fnmatch.fnmatch(path.name, pattern) or fnmatch.fnmatch(str(path), pattern) for pattern in exclude_globs)


def iter_files(
    roots: list[Path],
    include_exts: set[str],
    exclude_dirs: set[str],
    exclude_globs: list[str],
    max_size: int,
) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            candidates = [root]
        else:
            candidates = []
            for current, dirs, names in os.walk(root):
                current_path = Path(current)
                dirs[:] = [d for d in dirs if d.lower() not in exclude_dirs]
                if should_skip_dir(current_path, exclude_dirs):
                    continue
                candidates.extend(current_path / name for name in names)

        for path in candidates:
            try:
                if should_skip_file(path, include_exts, exclude_globs):
                    continue
                if path.stat().st_size > max_size:
                    continue
                files.append(path)
            except OSError:
                continue
    return files


def mask_secret(text: str) -> str:
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}{'*' * min(len(text) - 8, 24)}{text[-4:]}"


def redact_line(line: str, match_text: str) -> str:
    return line.replace(match_text, mask_secret(match_text))


def scan_file(path: Path, rules: list[dict[str, object]], context_lines: int, redact: bool) -> list[Finding]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    findings: list[Finding] = []
    for index, line in enumerate(lines):
        for rule in rules:
            regex = rule["regex"]
            assert isinstance(regex, re.Pattern)
            match = regex.search(line)
            if not match:
                continue

            match_text = match.group(0)
            start = max(0, index - context_lines)
            end = min(len(lines), index + context_lines + 1)
            context = []
            for line_no in range(start, end):
                line_text = lines[line_no]
                if redact and line_no == index:
                    line_text = redact_line(line_text, match_text)
                context.append(f"{line_no + 1}: {line_text}")

            findings.append(
                Finding(
                    file=str(path),
                    line=index + 1,
                    rule_id=str(rule["id"]),
                    category=str(rule["category"]),
                    severity=str(rule["severity"]),
                    match=mask_secret(match_text) if redact else match_text,
                    context="\n".join(context),
                )
            )
            break
    return findings


def scan(
    roots: list[Path],
    include_exts: set[str],
    exclude_dirs: set[str],
    exclude_globs: list[str],
    max_size: int,
    threads: int,
    context_lines: int,
    redact: bool,
    keyword: str | None,
    quiet: bool = False,
) -> tuple[list[Finding], int, float]:
    start = time.perf_counter()
    rules = compile_rules(keyword)
    files = iter_files(roots, include_exts, exclude_dirs, exclude_globs, max_size)

    findings: list[Finding] = []
    completed = 0
    total = len(files)
    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = [executor.submit(scan_file, path, rules, context_lines, redact) for path in files]
        for future in as_completed(futures):
            completed += 1
            findings.extend(future.result())
            if not quiet and (completed == total or completed % 100 == 0):
                print(f"\r扫描进度：{completed}/{total} 文件，发现 {len(findings)} 条", end="", flush=True)
    if not quiet:
        print()
    return findings, total, time.perf_counter() - start


def summarize(findings: list[Finding]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


def write_txt(path: Path, findings: list[Finding], total_files: int, elapsed: float) -> None:
    lines = [
        "Sensitive Files Search Report",
        f"scanned_files: {total_files}",
        f"findings: {len(findings)}",
        f"elapsed_seconds: {elapsed:.2f}",
        "",
    ]
    for finding in findings:
        lines.extend(
            [
                f"[{finding.severity}] {finding.category} {finding.file}:{finding.line}",
                f"rule: {finding.rule_id}",
                f"match: {finding.match}",
                finding.context,
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_json(path: Path, findings: list[Finding], total_files: int, elapsed: float) -> None:
    payload = {
        "summary": {
            "scanned_files": total_files,
            "findings": len(findings),
            "elapsed_seconds": round(elapsed, 2),
            "severity": summarize(findings),
        },
        "findings": [asdict(finding) for finding in findings],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(path: Path, findings: list[Finding]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(Finding.__annotations__.keys()))
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def write_html(path: Path, findings: list[Finding], total_files: int, elapsed: float) -> None:
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.severity)}</td>"
            f"<td>{html.escape(finding.category)}</td>"
            f"<td>{html.escape(finding.file)}:{finding.line}</td>"
            f"<td><code>{html.escape(finding.match)}</code></td>"
            f"<td><pre>{html.escape(finding.context)}</pre></td>"
            "</tr>"
        )
    document = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>Sensitive Files Search Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; color: #1f2937; }}
    h1 {{ margin-bottom: 8px; }}
    .summary {{ margin: 12px 0 20px; padding: 12px; background: #f3f4f6; border-radius: 8px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 8px; vertical-align: top; }}
    th {{ background: #f9fafb; text-align: left; }}
    pre {{ white-space: pre-wrap; margin: 0; }}
    code {{ color: #b91c1c; }}
  </style>
</head>
<body>
  <h1>Sensitive Files Search Report</h1>
  <div class="summary">扫描文件：{total_files}，发现结果：{len(findings)}，耗时：{elapsed:.2f}s</div>
  <table>
    <thead><tr><th>严重性</th><th>分类</th><th>位置</th><th>命中</th><th>上下文</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>"""
    path.write_text(document, encoding="utf-8")


def write_report(path: Path, fmt: str, findings: list[Finding], total_files: int, elapsed: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        write_json(path, findings, total_files, elapsed)
    elif fmt == "csv":
        write_csv(path, findings)
    elif fmt == "html":
        write_html(path, findings, total_files, elapsed)
    else:
        write_txt(path, findings, total_files, elapsed)


def print_summary(findings: list[Finding], total_files: int, elapsed: float, color_enabled: bool) -> None:
    summary = summarize(findings)
    print(color("扫描完成", "1;32", color_enabled))
    print(f"  扫描文件：{total_files}")
    print(f"  发现结果：{len(findings)}")
    print(f"  耗时：{elapsed:.2f}s")
    print(
        "  风险分布："
        f"严重 {summary['critical']} / 高 {summary['high']} / 中 {summary['medium']} / 低 {summary['low']}"
    )
    for finding in sorted(findings, key=lambda item: -SEVERITY_RANK[item.severity])[:10]:
        label = SEVERITY_LABEL.get(finding.severity, finding.severity)
        sev_color = {"critical": "1;31", "high": "31", "medium": "33", "low": "36"}.get(finding.severity, "0")
        print(
            f"  {color('[' + label + ']', sev_color, color_enabled)} "
            f"{finding.category} {finding.file}:{finding.line} -> {finding.match}"
        )
    if len(findings) > 10:
        print(f"  仅展示前 10 条，其余请查看报告。")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="本机敏感文件和敏感信息排查工具，支持脱敏报告、多线程和多格式输出。",
    )
    parser.add_argument("paths", nargs="*", help="要扫描的目录或文件，未提供时进入交互输入。")
    parser.add_argument("-o", "--output", default="sensitive_info_results.txt", help="报告输出路径。")
    parser.add_argument("--format", choices=["txt", "json", "csv", "html"], default="txt", help="报告格式。")
    parser.add_argument("--ext", help="要扫描的扩展名，逗号分隔，例如 .php,.env,.txt；默认使用内置集合。")
    parser.add_argument("--all-files", action="store_true", help="扫描所有文件类型。")
    parser.add_argument("--exclude-dir", help="排除目录名，逗号分隔。")
    parser.add_argument("--exclude-glob", action="append", default=[], help="排除文件通配符，可重复。")
    parser.add_argument("--max-size-mb", type=float, default=5, help="单文件最大大小，默认 5MB。")
    parser.add_argument("-t", "--threads", type=int, default=os.cpu_count() or 4, help="线程数。")
    parser.add_argument("-C", "--context", type=int, default=2, help="命中位置上下文行数。")
    parser.add_argument("-k", "--keyword", help="额外自定义关键词。")
    parser.add_argument("--no-redact", action="store_true", help="不脱敏输出命中内容。")
    parser.add_argument("--quiet", action="store_true", help="减少控制台输出。")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出。")
    return parser


def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)

    paths = args.paths
    if not paths:
        user_path = input("请输入要扫描的目录或文件路径：").strip()
        if user_path:
            paths = [user_path]
    if not paths:
        parser.error("请提供要扫描的路径。")

    roots = [Path(path).expanduser().resolve() for path in paths]
    missing = [str(path) for path in roots if not path.exists()]
    if missing:
        parser.error(f"路径不存在：{', '.join(missing)}")

    include_exts = set() if args.all_files else (normalize_extensions(parse_csv_set(args.ext)) or DEFAULT_EXTENSIONS)
    exclude_dirs = DEFAULT_EXCLUDE_DIRS | parse_csv_set(args.exclude_dir)
    max_size = int(args.max_size_mb * 1024 * 1024)
    findings, total_files, elapsed = scan(
        roots=roots,
        include_exts=include_exts,
        exclude_dirs=exclude_dirs,
        exclude_globs=args.exclude_glob,
        max_size=max_size,
        threads=args.threads,
        context_lines=max(0, args.context),
        redact=not args.no_redact,
        keyword=args.keyword,
        quiet=args.quiet,
    )

    output = Path(args.output)
    write_report(output, args.format, findings, total_files, elapsed)

    if not args.quiet:
        print_summary(findings, total_files, elapsed, color_enabled=sys.stdout.isatty() and not args.no_color)
        print(f"报告已保存：{output}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

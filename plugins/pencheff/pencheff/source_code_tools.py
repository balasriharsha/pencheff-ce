"""Source-code SAST scanner wrappers (feature 001-multi-target-scan-pipelines).

Thin agent-callable wrappers around semgrep / bandit / gosec / brakeman /
eslint / gitleaks / yara / osv-scanner. The existing pencheff_api's
``tasks.repo_scan_task`` already drives these scanners for legacy ``repo``
targets; this module exposes the same scanners as MCP tools so the
artifact_orchestrator can run them under the kind=source_code allowlist
when the agent picks a scanner subset.

The wrappers are intentionally NOT a refactor of repo_scan_task — they
duplicate the subprocess invocation but normalize the output into the
same finding shape used by artifact_tools (severity / category /
owasp_category / file_path / line_start / line_end / description). The
legacy ``repo_scan_task`` continues to use its own ``_run_*`` privates
unchanged for backward compat.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .artifact_tools import _kind_config_for_session, _run_subprocess, _which


_SEV_NORMALIZE = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "warning": "medium", "error": "high",
    "note": "low", "informational": "info", "unknown": "info",
}


def _normalize_sev(raw: str | None) -> str:
    return _SEV_NORMALIZE.get((raw or "info").lower(), "info")


# ============================================================================
# run_semgrep
# ============================================================================


async def run_semgrep(
    session_id: str,
    source_path: str,
    config: str = "auto",
) -> dict[str, Any]:
    """Run semgrep against a source directory.

    ``config="auto"`` lets semgrep choose rules based on detected languages
    (the same default repo_scan_task uses). Operators can override with
    explicit rule packs via the agent's kind_config.scanners_disabled hook
    in future iterations.
    """
    if not _which("semgrep"):
        return {"error": "binary not found: semgrep", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["semgrep", "--json", "--quiet", "--config", config, source_path]
    result = await _run_subprocess(argv, timeout=900)  # SAST runs are slow
    if result.get("error"):
        return result
    findings = _parse_semgrep_json(result.get("stdout", ""))
    return {"scanner": "semgrep", "findings_count": len(findings), "findings": findings}


def _parse_semgrep_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for r in data.get("results", []) or []:
        meta = r.get("extra", {}) or {}
        sev = _normalize_sev(meta.get("severity"))
        # Semgrep often tags rules with OWASP metadata in extra.metadata.owasp.
        owasp_tags = (meta.get("metadata") or {}).get("owasp") or []
        owasp = owasp_tags[0] if isinstance(owasp_tags, list) and owasp_tags else "A03:2021"
        findings.append({
            "title": meta.get("message", r.get("check_id", "semgrep finding"))[:255],
            "severity": sev,
            "category": "sast",
            "owasp_category": owasp,
            "file_path": r.get("path"),
            "line_start": (r.get("start") or {}).get("line"),
            "line_end": (r.get("end") or {}).get("line"),
            "description": (meta.get("message") or "")[:512],
            "remediation": (meta.get("fix") or "")[:512],
        })
    return findings


# ============================================================================
# run_bandit (Python)
# ============================================================================


async def run_bandit(session_id: str, source_path: str) -> dict[str, Any]:
    """Run bandit against a Python source directory."""
    if not _which("bandit"):
        return {"error": "binary not found: bandit", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["bandit", "-r", source_path, "-f", "json", "-q"]
    result = await _run_subprocess(argv, timeout=600)
    if result.get("error"):
        return result
    findings = _parse_bandit_json(result.get("stdout", ""))
    return {"scanner": "bandit", "findings_count": len(findings), "findings": findings}


def _parse_bandit_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for r in data.get("results", []) or []:
        sev = _normalize_sev(r.get("issue_severity"))
        findings.append({
            "title": r.get("test_name", "bandit finding")[:255],
            "severity": sev,
            "category": "sast",
            "owasp_category": "A03:2021",  # default — Injection / weak crypto, etc.
            "file_path": r.get("filename"),
            "line_start": r.get("line_number"),
            "description": (r.get("issue_text") or "")[:512],
            "remediation": r.get("more_info") or "",
        })
    return findings


# ============================================================================
# run_gosec (Go)
# ============================================================================


async def run_gosec(session_id: str, source_path: str) -> dict[str, Any]:
    if not _which("gosec"):
        return {"error": "binary not found: gosec", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["gosec", "-fmt=json", "-quiet", "./..."]
    result = await _run_subprocess(argv, timeout=600, cwd=source_path)
    if result.get("error"):
        return result
    findings = _parse_gosec_json(result.get("stdout", ""))
    return {"scanner": "gosec", "findings_count": len(findings), "findings": findings}


def _parse_gosec_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for r in data.get("Issues", []) or []:
        sev = _normalize_sev(r.get("severity"))
        line_str = (r.get("line") or "1").split("-")[0]
        try:
            line_start = int(line_str)
        except ValueError:
            line_start = None
        findings.append({
            "title": r.get("rule_id", "gosec rule"),
            "severity": sev,
            "category": "sast",
            "owasp_category": "A03:2021",
            "file_path": r.get("file"),
            "line_start": line_start,
            "description": (r.get("details") or "")[:512],
        })
    return findings


# ============================================================================
# run_brakeman (Ruby on Rails)
# ============================================================================


async def run_brakeman(session_id: str, source_path: str) -> dict[str, Any]:
    if not _which("brakeman"):
        return {"error": "binary not found: brakeman", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["brakeman", "-q", "-f", "json", source_path]
    result = await _run_subprocess(argv, timeout=600)
    # Brakeman exits non-zero when warnings are present — parse output regardless.
    findings = _parse_brakeman_json(result.get("stdout", ""))
    return {"scanner": "brakeman", "findings_count": len(findings), "findings": findings}


def _parse_brakeman_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for w in data.get("warnings", []) or []:
        sev = _normalize_sev(w.get("confidence"))
        findings.append({
            "title": w.get("warning_type", "brakeman warning"),
            "severity": sev,
            "category": "sast",
            "owasp_category": "A03:2021",
            "file_path": w.get("file"),
            "line_start": w.get("line"),
            "description": (w.get("message") or "")[:512],
        })
    return findings


# ============================================================================
# run_eslint (JavaScript/TypeScript security rules)
# ============================================================================


async def run_eslint(
    session_id: str,
    source_path: str,
) -> dict[str, Any]:
    if not _which("npx"):
        return {"error": "binary not found: npx", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["npx", "--no-install", "eslint", "-f", "json", source_path]
    result = await _run_subprocess(argv, timeout=600, cwd=source_path)
    findings = _parse_eslint_json(result.get("stdout", ""))
    return {"scanner": "eslint", "findings_count": len(findings), "findings": findings}


def _parse_eslint_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for file_block in data if isinstance(data, list) else []:
        path = file_block.get("filePath")
        for msg in file_block.get("messages", []) or []:
            # eslint severity is 1=warning, 2=error; we only flag security
            # rules (ruleId starting with "security/") as findings.
            rule = msg.get("ruleId") or ""
            if not (rule.startswith("security/") or rule.startswith("no-eval")):
                continue
            sev = "high" if msg.get("severity") == 2 else "medium"
            findings.append({
                "title": rule or "eslint security rule",
                "severity": sev,
                "category": "sast",
                "owasp_category": "A03:2021",
                "file_path": path,
                "line_start": msg.get("line"),
                "description": (msg.get("message") or "")[:512],
            })
    return findings


# ============================================================================
# run_gitleaks (secret scanning)
# ============================================================================


async def run_gitleaks(session_id: str, source_path: str) -> dict[str, Any]:
    if not _which("gitleaks"):
        return {"error": "binary not found: gitleaks", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    git_dir = Path(source_path) / ".git"
    cmd = "detect" if git_dir.exists() else "dir"
    argv = ["gitleaks", cmd, "--source", source_path, "--report-format", "json",
            "--no-banner", "--exit-code", "0"]
    if cmd == "dir":
        argv.append("--no-git")
    result = await _run_subprocess(argv, timeout=600)
    findings = _parse_gitleaks_json(result.get("stdout", ""))
    return {"scanner": "gitleaks", "findings_count": len(findings), "findings": findings}


def _parse_gitleaks_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    items = data if isinstance(data, list) else data.get("findings") or []
    findings: list[dict[str, Any]] = []
    for item in items:
        findings.append({
            "title": f"Secret leak: {item.get('RuleID') or item.get('Description', 'secret')}",
            "severity": "high",  # secrets always default high
            "category": "secret_leak",
            "owasp_category": "A07:2021",  # Identification & Authentication Failures
            "file_path": item.get("File"),
            "line_start": item.get("StartLine"),
            "line_end": item.get("EndLine"),
            "description": (item.get("Description") or "")[:512],
            "evidence": {"secret_excerpt": (item.get("Secret") or "")[:64]},
        })
    return findings


# ============================================================================
# run_yara (malware-signature matching)
# ============================================================================


async def run_yara(
    session_id: str,
    source_path: str,
    rules_path: str | None = None,
) -> dict[str, Any]:
    if not _which("yara"):
        return {"error": "binary not found: yara", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    if not rules_path:
        return {"error": "rules_path required (no operator-supplied YARA rules)"}
    if not Path(rules_path).exists():
        return {"error": "rules_path does not exist"}
    # YARA matches per file; -r recurses, -s prints matching strings, output is
    # newline-delimited "rule_name file" — we parse to a finding per match.
    argv = ["yara", "-r", "-s", rules_path, source_path]
    result = await _run_subprocess(argv, timeout=600)
    findings: list[dict[str, Any]] = []
    for line in (result.get("stdout") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("0x") or " " not in line:
            continue
        rule_name, _, path = line.partition(" ")
        findings.append({
            "title": f"YARA rule matched: {rule_name}",
            "severity": "high",
            "category": "malware_signature",
            "owasp_category": "A08:2021",
            "file_path": path,
            "description": f"YARA rule {rule_name!r} matched.",
        })
    return {"scanner": "yara", "findings_count": len(findings), "findings": findings}


# ============================================================================
# run_osv_scanner (against a source directory — package_registry uses
# osv-scanner via a different code path on the SBOM)
# ============================================================================


async def run_osv_scanner(session_id: str, source_path: str) -> dict[str, Any]:
    if not _which("osv-scanner"):
        return {"error": "binary not found: osv-scanner", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["osv-scanner", "--format", "json", "--recursive", source_path]
    result = await _run_subprocess(argv, timeout=600)
    findings = _parse_osv_source_json(result.get("stdout", ""))
    return {"scanner": "osv-scanner", "findings_count": len(findings), "findings": findings}


def _parse_osv_source_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for r in data.get("results", []) or []:
        for pkg in r.get("packages", []) or []:
            pkg_info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []) or []:
                findings.append({
                    "title": f"{vuln.get('id')} in {pkg_info.get('name', 'package')}",
                    "severity": "high",  # OSV doesn't always include CVSS here
                    "category": "vulnerable_dependency",
                    "owasp_category": "A06:2021",
                    "cve": vuln.get("id"),
                    "package": pkg_info.get("name"),
                    "installed_version": pkg_info.get("version"),
                    "description": (vuln.get("summary") or vuln.get("details", ""))[:512],
                })
    return findings


__all__ = [
    "run_semgrep",
    "run_bandit",
    "run_gosec",
    "run_brakeman",
    "run_eslint",
    "run_gitleaks",
    "run_yara",
    "run_osv_scanner",
]

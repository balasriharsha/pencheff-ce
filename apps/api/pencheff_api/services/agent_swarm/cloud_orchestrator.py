"""Cloud target orchestrator for Infrastructure & Cloud target kinds.

The cloud pipeline is read-only. It accepts provider/resource metadata from
``Target.kind_config`` plus encrypted provider credentials from
``Target.kind_credentials_encrypted`` and runs kind-specific posture checks.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from .cloud_scanners import run_cloud_checks

log = logging.getLogger("pencheff.cloud_orchestrator")

CLOUD_KINDS = frozenset({
    "cloud_account",
    "serverless_function",
    "cloud_storage",
    "load_balancer_cdn",
    "cloud_database",
    "secrets_manager",
})


async def run_cloud_orchestrator(
    *,
    scan_id: str,
    target: Any,
    Session: Any,
    kind_credentials: dict | None = None,
) -> None:
    """Drive read-only cloud posture checks for one cloud target."""
    from ...db.models import Finding as DbFinding
    from ...db.models import Scan
    from ...events import publish_scan_event

    kind = target.kind
    if kind not in CLOUD_KINDS:
        raise ValueError(
            f"run_cloud_orchestrator called with non-cloud kind={kind!r}",
        )

    cfg = dict(target.kind_config or {})
    provider = cfg.get("provider", "unknown")
    await _append_scan_log(
        scan_id,
        Session,
        f"[Cloud] starting read-only orchestrator for kind={kind} provider={provider}",
    )
    publish_scan_event(
        scan_id,
        {
            "type": "stage_start",
            "label": f"cloud: {kind} read-only posture checks",
            "pct": None,
        },
    )

    findings, scanner_stats = run_cloud_checks(
        kind=kind,
        cfg=cfg,
        kind_credentials=kind_credentials,
    )
    counts = _severity_counts(findings)

    async with Session() as db:
        for f in findings:
            db.add(DbFinding(
                scan_id=scan_id,
                title=f.get("title", "(untitled)")[:255],
                severity=f.get("severity", "info"),
                category=f.get("category", "cloud"),
                owasp_category=f.get("owasp_category"),
                description=f.get("description", "")[:4000],
                remediation=f.get("remediation", "")[:4000] if f.get("remediation") else None,
                evidence=[f["evidence"]] if f.get("evidence") else None,
            ))
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.status = "done"
        s.progress_pct = 100
        s.current_stage = "complete"
        s.finished_at = datetime.now(timezone.utc)
        s.summary = {
            **(s.summary or {}),
            "kind": kind,
            "scanner_stats": scanner_stats,
            "counts": counts,
            "pipeline": "cloud",
        }
        log_list = list(s.log or [])
        log_list.append(f"[Cloud] complete · {len(findings)} findings · {counts}")
        s.log = log_list[-1000:]
        await db.commit()

    publish_scan_event(
        scan_id,
        {"type": "finished", "scan_id": scan_id, "total_findings": len(findings)},
    )


async def _append_scan_log(scan_id: str, Session: Any, message: str) -> None:
    from ...db.models import Scan

    async with Session() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        log_list = list(s.log or [])
        log_list.append(message)
        s.log = log_list[-1000:]
        await db.commit()


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        if severity in counts:
            counts[severity] += 1
    return counts

"""Artifact-cluster orchestrator (feature 001-multi-target-scan-pipelines).

Drives kinds whose target is a static artifact rather than a live endpoint:
container_image, iac, package_registry, sbom. (source_code goes through
repo_scan_task — see spec §6.2.)

Pipeline shape (per spec §6.2):

    1. Acquire artifact via allowlisted tool (artifact_clone_repo /
       artifact_pull_image / artifact_download / artifact_parse_sbom).
    2. ArtifactReconAgent catalogs the artifact (file tree, languages,
       manifests, layers) — currently elided; the deterministic runner
       below dispatches directly to scanners.
    3. ScannerOrchestratorAgent selects scanners from per-kind allowlist
       (KIND_TO_ARTIFACT_TOOLS). The deterministic implementation runs
       every allowlisted scanner; an LLM-orchestrated variant that
       chooses a subset based on detected languages / manifests lives in
       a follow-up pass.
    4. Findings persist via the same ``_finding_to_db_row`` pattern as
       url scans, tagged with ``owasp_category`` per scanner.

The deterministic implementation here is the M2/M3 ship target. The
LLM-orchestrated variant (full agent loop driving these tools) is
documented in plan.md §4.2 / §4.3.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

log = logging.getLogger("pencheff.artifact_orchestrator")


# Per-kind scanner allowlist. The deterministic runner walks this set; the
# LLM-orchestrated variant in a future pass uses it as the agent's tool
# allowlist (anything outside this set is rejected at registration time).
KIND_TO_ARTIFACT_TOOLS: dict[str, frozenset[str]] = {
    # source_code keeps using ``repo_scan_task`` (RepoScan table); listed
    # here only so the agent's kind-aware tool-allowlist lookup works for
    # forward-compat callers that might invoke this orchestrator on a
    # source_code Target.
    "source_code": frozenset({
        "run_semgrep", "run_bandit", "run_gosec", "run_brakeman",
        "run_eslint", "run_gitleaks", "run_yara", "run_osv_scanner",
    }),
    "container_image": frozenset({
        "run_trivy_image", "run_syft", "run_grype", "run_hadolint",
    }),
    "iac": frozenset({"run_checkov", "run_tfsec"}),
    "package_registry": frozenset({"run_npm_audit", "run_pip_audit"}),
    "sbom": frozenset({"run_grype_sbom", "run_osv_scanner_sbom"}),
}


# Which scanners require artifact acquisition first (and which acquisition
# tool to invoke). The orchestrator routes through the right path per kind.
_ACQUISITION_FOR_KIND = {
    "container_image": "artifact_pull_image",  # → run_*_image scanners use oci_layout
    "iac":             "artifact_clone_repo",  # → run_checkov / run_tfsec use cloned path
    "package_registry": None,                  # uses kind_config.package_list inline
    "sbom":            "artifact_parse_sbom",  # → run_*_sbom scanners use written path
    "source_code":     "artifact_clone_repo",  # → run_semgrep / run_bandit / etc.
}


async def run_artifact_orchestrator(
    *,
    scan_id: str,
    target: Any,
    Session: Any,
    kind_credentials: dict | None = None,
) -> None:
    """Drive an artifact-cluster scan.

    Args:
        scan_id: UUID of the Scan row.
        target: Target ORM row with ``kind_config`` JSONB carrying the per-kind
            artifact descriptor (image_ref / repo_url / sbom content / etc.).
        Session: AsyncSession factory.
    """
    import pencheff.server as srv
    from ...db.models import Scan
    from ...events import publish_scan_event

    kind = target.kind
    if kind not in KIND_TO_ARTIFACT_TOOLS:
        raise ValueError(
            f"run_artifact_orchestrator called with non-artifact kind={kind!r}"
        )

    cfg = dict(target.kind_config or {})
    log.info("artifact orchestrator: scan_id=%s kind=%s", scan_id, kind)

    # Bind kind_config + (optional) decrypted kind_credentials to a synthetic
    # pencheff session so the artifact tools' allowlist + credential hooks
    # resolve. ALWAYS cleared in the finally block to ensure no in-memory
    # leakage of kubeconfig / registry secrets / etc.
    session_id = f"artifact-{scan_id}"
    srv.set_kind_config_for_session(session_id, cfg)
    if kind_credentials is not None:
        srv.set_kind_credentials_for_session(session_id, kind_credentials)

    async def _log(msg: str) -> None:
        async with Session() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            log_list = list(s.log or [])
            log_list.append(msg)
            s.log = log_list[-1000:]  # cap at 1000 lines per scan
            await db.commit()
        publish_scan_event(scan_id, {"type": "stage_start", "label": msg[:160], "pct": None})

    try:
        await _log(f"[Artifact] starting orchestrator for kind={kind}")

        # ── Acquisition phase ──────────────────────────────────────
        acquired: dict[str, Any] = {}
        acq_tool = _ACQUISITION_FOR_KIND.get(kind)
        if acq_tool == "artifact_pull_image":
            await _log(f"[Artifact] pulling image {cfg.get('image_ref')}")
            acquired = await srv.artifact_pull_image(
                session_id=session_id,
                ref=cfg.get("image_ref", ""),
            )
            if "error" in acquired:
                raise RuntimeError(f"image pull failed: {acquired['error']}")
        elif acq_tool == "artifact_clone_repo":
            await _log(f"[Artifact] cloning {cfg.get('repo_url')}")
            acquired = await srv.artifact_clone_repo(
                session_id=session_id,
                url=cfg.get("repo_url", ""),
            )
            if "error" in acquired:
                raise RuntimeError(f"clone failed: {acquired['error']}")
        elif acq_tool == "artifact_parse_sbom":
            if cfg.get("content"):
                await _log("[Artifact] parsing inline SBOM")
                acquired = await srv.artifact_parse_sbom(
                    session_id=session_id,
                    content=cfg.get("content", ""),
                    sbom_format=cfg.get("format", "cyclonedx-json"),
                )
                if "error" in acquired:
                    raise RuntimeError(f"sbom parse failed: {acquired['error']}")
            elif cfg.get("url"):
                # Remote SBOM via artifact_download — caller must register the
                # SBOM URL host in kind_config.allowed_hosts or use a default.
                await _log(f"[Artifact] downloading SBOM from {cfg.get('url')}")
                acquired = await srv.artifact_download(
                    session_id=session_id,
                    url=cfg.get("url", ""),
                    sha256=cfg.get("sha256", "0" * 64),  # operator must provide
                    filename="remote-sbom.json",
                )
                if "error" in acquired:
                    raise RuntimeError(f"sbom download failed: {acquired['error']}")
            else:
                raise RuntimeError("sbom kind_config requires content or url")

        # ── Scanner-run phase ──────────────────────────────────────
        scanners = sorted(KIND_TO_ARTIFACT_TOOLS[kind])
        all_findings: list[dict[str, Any]] = []
        scanner_stats: dict[str, dict[str, Any]] = {}

        for tool_name in scanners:
            scanner_fn = getattr(srv, tool_name, None)
            if scanner_fn is None:
                scanner_stats[tool_name] = {"error": "tool not exposed", "findings_count": 0}
                continue
            args = _scanner_args_for(kind, tool_name, acquired, cfg)
            if args is None:
                scanner_stats[tool_name] = {"skipped": "no input"}
                continue
            await _log(f"[Artifact] running {tool_name}")
            try:
                result = await scanner_fn(session_id=session_id, **args)
            except Exception as exc:  # noqa: BLE001
                scanner_stats[tool_name] = {"error": str(exc)}
                continue
            if "error" in result:
                scanner_stats[tool_name] = {
                    "error": result["error"],
                    "skipped": result.get("skipped", False),
                }
                continue
            findings = result.get("findings", [])
            scanner_stats[tool_name] = {"findings_count": len(findings)}
            for f in findings:
                f["scanner"] = result.get("scanner") or tool_name
            all_findings.extend(findings)

        # ── Persist findings + finalize ────────────────────────────
        await _log(f"[Artifact] {len(all_findings)} total findings across {len(scanners)} scanners")
        await _persist_artifact_findings(scan_id, all_findings, Session)
        await _finalize_scan(scan_id, kind, all_findings, scanner_stats, Session)
        publish_scan_event(scan_id, {
            "type": "finished", "scan_id": scan_id,
            "total_findings": len(all_findings),
        })

    finally:
        srv.set_kind_config_for_session(session_id, None)
        # NEVER let decrypted credentials linger in process memory.
        srv.set_kind_credentials_for_session(session_id, None)


def _scanner_args_for(
    kind: str,
    tool_name: str,
    acquired: dict[str, Any],
    cfg: dict[str, Any],
) -> dict[str, Any] | None:
    """Per-(kind, tool) argument shape. Returns None if the scanner is
    irrelevant for this kind+config combo (e.g., run_npm_audit when
    ecosystem != npm)."""
    if kind == "container_image":
        oci = acquired.get("oci_layout")
        if tool_name == "run_trivy_image":
            return {"oci_layout": oci, "image_ref": cfg.get("image_ref")}
        if tool_name == "run_syft":
            return {"source_path": oci} if oci else None
        if tool_name == "run_grype":
            return {"source_path": oci} if oci else None
        if tool_name == "run_hadolint":
            # Hadolint needs a Dockerfile path — skip unless the operator
            # uploaded the source repo alongside; deferred to a richer
            # source-code-plus-container workflow.
            return None
    if kind == "iac":
        path = acquired.get("local_path")
        if not path:
            return None
        if tool_name == "run_checkov":
            fw = (cfg.get("frameworks") or [None])[0]
            return {"source_path": path, "framework": fw}
        if tool_name == "run_tfsec":
            # tfsec only runs on terraform; check the frameworks list.
            if "terraform" not in (cfg.get("frameworks") or []):
                return None
            return {"source_path": path}
    if kind == "package_registry":
        eco = cfg.get("ecosystem")
        if tool_name == "run_npm_audit":
            return {"project_path": "/tmp"} if eco == "npm" else None
        if tool_name == "run_pip_audit":
            return {"project_path": "/tmp"} if eco == "pypi" else None
    if kind == "sbom":
        sbom_path = acquired.get("local_path")
        if not sbom_path:
            return None
        if tool_name == "run_grype_sbom":
            return {"sbom_path": sbom_path}
        if tool_name == "run_osv_scanner_sbom":
            return {"sbom_path": sbom_path}
    if kind == "source_code":
        # All source_code SAST scanners take (source_path) as their primary arg.
        # The cloned repo lands at acquired["local_path"].
        path = acquired.get("local_path")
        if not path:
            return None
        if tool_name in {"run_semgrep", "run_bandit", "run_gosec", "run_brakeman",
                         "run_eslint", "run_gitleaks", "run_osv_scanner"}:
            return {"source_path": path}
        if tool_name == "run_yara":
            # YARA needs an explicit rules_path; pencheff doesn't ship one by
            # default, so we skip unless the operator wires it via kind_config.
            return None
    return None


async def _persist_artifact_findings(
    scan_id: str,
    findings: list[dict[str, Any]],
    Session: Any,
) -> None:
    """Bulk-insert artifact findings into the ``findings`` table.

    Reuses the existing DAST Finding row shape (severity / category /
    owasp_category / description / evidence) so the same dashboards +
    triage flows surface them.
    """
    from ...db.models import Finding as DbFinding
    if not findings:
        return
    async with Session() as db:
        for f in findings:
            db.add(DbFinding(
                scan_id=scan_id,
                title=f.get("title", "(untitled)")[:255],
                severity=f.get("severity", "info"),
                category=f.get("category", "unknown"),
                owasp_category=f.get("owasp_category"),
                description=f.get("description", "")[:4000],
                remediation=f.get("remediation", "")[:4000] if f.get("remediation") else None,
                evidence=[f["evidence"]] if f.get("evidence") else None,
            ))
        await db.commit()


async def _finalize_scan(
    scan_id: str,
    kind: str,
    findings: list[dict[str, Any]],
    scanner_stats: dict[str, dict[str, Any]],
    Session: Any,
) -> None:
    """Mark the Scan row done + write summary stats."""
    from ...db.models import Scan
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    async with Session() as db:
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
            "pipeline": "artifact",
        }
        log_list = list(s.log or [])
        log_list.append(f"[Artifact] complete · {len(findings)} findings · {counts}")
        s.log = log_list[-1000:]
        await db.commit()

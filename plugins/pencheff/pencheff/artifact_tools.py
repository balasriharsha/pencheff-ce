"""Artifact-cluster scanner wrappers (feature 001-multi-target-scan-pipelines).

This module is imported into ``pencheff.server`` so the agent_runner tool
registry can resolve these names via ``getattr(srv, fn_name)``. Each tool is
a subprocess wrapper for a single deterministic scanner, with three hard
contracts:

  1. **Allowlist enforcement** — every artifact-acquisition tool
     (``clone_repo``, ``pull_image``, ``download_artifact``, ``parse_sbom``)
     validates its inputs against the calling scan's ``Target.kind_config``
     before invoking subprocess. Off-allowlist arguments return an error to
     the agent without invoking the subprocess. Per spec §6.4.

  2. **Sandbox isolation** — git clones use ``-c core.hooksPath=/dev/null``,
     image pulls use ``skopeo copy`` to OCI layout (no exec during pull),
     scanners run with ``--offline-scan`` where supported.

  3. **Graceful degradation** — if a scanner binary is not installed,
     return ``{"error": "scanner ``trivy`` not installed", "skipped": true}``
     so the orchestrator can decide whether to escalate or continue.

Each tool returns JSON-shaped dicts the agent can reason about, with
findings already mapped to the pencheff schema (severity, category,
owasp_category per S-10).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any


# ============================================================================
# Subprocess + safety helpers
# ============================================================================

# Per-scan working dir parent. Each scanner mkdtemp's a subdir under this and
# cleans it up in a finally block.
_SCAN_TMP_ROOT = Path(tempfile.gettempdir()) / "pencheff_artifact_scans"


# Maximum subprocess run time per scanner. Each tool can override.
_DEFAULT_SCANNER_TIMEOUT = 600  # 10 minutes


# Per-spec §6.4 — scanners that take a ``--output-file`` arg must restrict to
# /tmp/ subdirectories. The substring-level _DANGEROUS_ARG_SUBSTRINGS list in
# agent_runner can't enforce path-level constraints, so wrappers do it here.
def _safe_output_path(scan_id: str, filename: str) -> Path:
    safe = "".join(c for c in filename if c.isalnum() or c in ".-_")
    workdir = _SCAN_TMP_ROOT / scan_id
    workdir.mkdir(parents=True, exist_ok=True)
    return workdir / safe


async def _run_subprocess(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = _DEFAULT_SCANNER_TIMEOUT,
    cwd: str | None = None,
) -> dict[str, Any]:
    """Run a subprocess and return {returncode, stdout, stderr, timed_out}.

    Never raises — failures return {"error": ..., "timed_out": bool}.
    """
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=full_env,
            cwd=cwd,
        )
    except FileNotFoundError as exc:
        return {"error": f"binary not found: {argv[0]}", "detail": str(exc)}
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {"error": "scanner timed out", "timed_out": True, "argv": argv}
    return {
        "returncode": proc.returncode,
        "stdout": (stdout_b or b"").decode("utf-8", errors="replace"),
        "stderr": (stderr_b or b"").decode("utf-8", errors="replace"),
        "timed_out": False,
    }


def _which(binary: str) -> bool:
    """True iff ``binary`` is on PATH."""
    return shutil.which(binary) is not None


# ============================================================================
# Allowlist resolution from kind_config
# ============================================================================

def _kind_config_for_session(session_id: str) -> dict | None:
    """Look up the Target.kind_config for this pencheff session, if any.

    The pencheff session itself doesn't carry kind_config — the calling
    scan_runner has it. We expose this hook here so the wrappers can be
    monkey-patched in tests; in production the api binds the lookup at
    scan-start time via ``set_kind_config_for_session``.
    """
    return _SESSION_KIND_CONFIGS.get(session_id)


_SESSION_KIND_CONFIGS: dict[str, dict] = {}
_SESSION_KIND_CREDS: dict[str, dict] = {}


def kind_credentials_for_session(session_id: str) -> dict | None:
    """Return the decrypted kind_credentials blob for this session, if any.

    Bound by the orchestrator (hybrid / artifact) before invoking tools that
    need cluster / registry / CI auth. ALWAYS cleared in the orchestrator's
    finally block — see _SESSION_KIND_CREDS lifecycle in artifact_orchestrator
    and hybrid_orchestrator.
    """
    return _SESSION_KIND_CREDS.get(session_id)


def set_kind_credentials_for_session(session_id: str, creds: dict | None) -> None:
    """Bind decrypted kind_credentials to a pencheff session.

    NEVER LOG ``creds`` — it carries kubeconfig YAML / GitHub App PEM / etc.
    The redaction filter on scan_llm_traces refuses to write these values.
    """
    if creds is None:
        _SESSION_KIND_CREDS.pop(session_id, None)
    else:
        _SESSION_KIND_CREDS[session_id] = creds


def set_kind_config_for_session(session_id: str, kind_config: dict | None) -> None:
    """Bind a Target.kind_config to a pencheff session so artifact-acquisition
    tools can validate their inputs against the registered values.

    Called by scan_runner._run_artifact_scan / _run_hybrid_scan before driving
    the orchestrator. Cleared on session end.
    """
    if kind_config is None:
        _SESSION_KIND_CONFIGS.pop(session_id, None)
    else:
        _SESSION_KIND_CONFIGS[session_id] = kind_config


# ============================================================================
# Tool: clone_repo
# ============================================================================

async def artifact_clone_repo(
    session_id: str,
    url: str,
    ref: str = "HEAD",
) -> dict[str, Any]:
    """Clone a git repository to a sandboxed temp dir for artifact analysis.

    Allowlist: ``url`` MUST equal ``Target.kind_config.repo_url`` (the value
    the operator registered at target-creation time). Agent-emitted URLs
    that don't match are rejected without invoking git.

    Safety: ``-c core.hooksPath=/dev/null`` neutralizes attacker-controlled
    repo-side hooks; ``--depth=1`` keeps the clone small; ``--no-hardlinks``
    isolates the working tree from the upstream object store.
    """
    if not _which("git"):
        return {"error": "binary not found: git"}
    cfg = _kind_config_for_session(session_id) or {}
    registered = cfg.get("repo_url")
    if not registered:
        return {"error": "session has no registered repo_url; clone_repo refused"}
    if url != registered:
        return {
            "error": "url_not_allowed",
            "registered": registered,
            "supplied": url,
        }
    if not isinstance(ref, str) or not ref or any(c in ref for c in (" ", ";", "&", "|", "\n")):
        return {"error": "invalid ref"}

    workdir = _SCAN_TMP_ROOT / session_id / "clone"
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.parent.mkdir(parents=True, exist_ok=True)

    argv = [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.ext.allow=never",
        "clone", "--depth=1", "--no-hardlinks", "--single-branch",
    ]
    if ref != "HEAD":
        argv.extend(["--branch", ref])
    argv.extend([url, str(workdir)])

    result = await _run_subprocess(
        argv,
        env={
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "true",  # silence credential prompts
        },
    )
    if result.get("error"):
        return result
    if result.get("returncode") != 0:
        return {
            "error": "git clone failed",
            "returncode": result.get("returncode"),
            "stderr": result.get("stderr", "")[:2048],
        }
    return {"local_path": str(workdir), "ref": ref}


# ============================================================================
# Tool: pull_image (skopeo, NOT docker pull)
# ============================================================================

async def artifact_pull_image(
    session_id: str,
    ref: str,
) -> dict[str, Any]:
    """Pull a container image into an OCI layout for static analysis.

    Allowlist: ``ref`` MUST equal ``Target.kind_config.image_ref`` OR be a
    digest that resolves to the same image. Spec §6.4.

    Safety: uses ``skopeo copy`` (no exec during pull) rather than
    ``docker pull`` (which on some daemons runs entrypoint hooks during
    layer extraction).

    Registry auth: when ``kind_credentials`` is bound to the session, the
    correct skopeo ``--src-creds`` / ``--src-authfile`` is computed from the
    auth_type:
      * basic / token       → ``--src-creds <u>:<p>``
      * ecr_sts             → boto3 ``ecr.get_authorization_token`` → ``--src-creds AWS:<tok>``
      * gcr_service_account → ``--src-creds _json_key:<SA_JSON>``
      * acr_sp              → ``--src-creds <client_id>:<client_secret>``
      * docker_config       → ``--src-authfile <tempfile>``
    """
    if not _which("skopeo"):
        return {"error": "binary not found: skopeo", "hint": "install skopeo for safe image acquisition"}
    cfg = _kind_config_for_session(session_id) or {}
    registered = cfg.get("image_ref")
    if not registered:
        return {"error": "session has no registered image_ref; pull_image refused"}
    # Allow digest-based references when the base image_ref matches before "@".
    if ref != registered and not (
        "@" in ref and ref.split("@")[0] == registered.split("@")[0]
    ):
        return {
            "error": "ref_not_allowed",
            "registered": registered,
            "supplied": ref,
        }

    workdir = _SCAN_TMP_ROOT / session_id / "oci-layout"
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.parent.mkdir(parents=True, exist_ok=True)

    creds = kind_credentials_for_session(session_id)
    try:
        auth_args, auth_tempfile, auth_err = _skopeo_src_auth_args(creds)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"registry auth setup failed: {exc}"}
    if auth_err:
        return {"error": auth_err}

    try:
        argv = [
            "skopeo", "copy",
            *auth_args,
            f"docker://{ref}",
            f"oci:{workdir}",
        ]
        result = await _run_subprocess(argv)
        if result.get("error"):
            return result
        if result.get("returncode") != 0:
            return {
                "error": "skopeo copy failed",
                "returncode": result.get("returncode"),
                "stderr": result.get("stderr", "")[:2048],
            }
        return {"oci_layout": str(workdir), "ref": ref}
    finally:
        if auth_tempfile is not None:
            try:
                auth_tempfile.unlink()
            except OSError:
                pass


def _skopeo_src_auth_args(
    creds: dict | None,
) -> tuple[list[str], Path | None, str | None]:
    """Build skopeo ``--src-*`` auth args from registry credentials.

    Returns ``(argv_fragments, tempfile_to_unlink, error)``. ``error`` is
    non-None only when auth setup actively failed (e.g. ECR token exchange
    rejected by IAM). Missing or empty creds return ``([], None, None)`` so
    the caller proceeds with anonymous pulls.
    """
    if not creds or creds.get("kind") != "container_image":
        return [], None, None
    auth = (creds.get("auth_type") or "").lower()

    if auth in ("basic", "token"):
        user = creds.get("username") or ("token" if auth == "token" else "")
        pwd = creds.get("password_or_token") or ""
        if not pwd:
            return [], None, None
        return ["--src-creds", f"{user}:{pwd}"], None, None

    if auth == "ecr_sts":
        try:
            import base64
            import boto3  # type: ignore
        except ImportError as exc:
            return [], None, f"boto3 not installed; ECR auth unavailable ({exc})"
        sess = boto3.Session(
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key"),
            aws_session_token=creds.get("aws_session_token") or None,
            region_name=creds.get("aws_region") or None,
        )
        try:
            resp = sess.client("ecr").get_authorization_token()
        except Exception as exc:  # noqa: BLE001
            return [], None, f"ecr.get_authorization_token failed: {exc}"
        items = resp.get("authorizationData") or []
        if not items:
            return [], None, "ecr.get_authorization_token returned no data"
        b64_pair = items[0].get("authorizationToken") or ""
        try:
            decoded = base64.b64decode(b64_pair).decode("utf-8")
        except Exception as exc:  # noqa: BLE001
            return [], None, f"ECR authorizationToken not base64-decodable: {exc}"
        user, _, password = decoded.partition(":")
        if not password:
            return [], None, "ECR authorizationToken missing password"
        return ["--src-creds", f"{user}:{password}"], None, None

    if auth == "gcr_service_account":
        sa = creds.get("gcr_service_account_json") or ""
        if not sa:
            return [], None, "gcr_service_account_json missing"
        return ["--src-creds", f"_json_key:{sa}"], None, None

    if auth == "acr_sp":
        cid = creds.get("acr_client_id") or ""
        secret = creds.get("acr_client_secret") or ""
        if not (cid and secret):
            return [], None, "acr_sp creds missing client id/secret"
        return ["--src-creds", f"{cid}:{secret}"], None, None

    if auth == "docker_config":
        cfg_json = creds.get("docker_config_json") or ""
        if not cfg_json:
            return [], None, "docker_config_json missing"
        # Mode-0600 tempfile, caller unlinks in finally.
        _SCAN_TMP_ROOT.mkdir(parents=True, exist_ok=True)
        fd, path_str = tempfile.mkstemp(prefix="skopeo-auth-", suffix=".json", dir=str(_SCAN_TMP_ROOT))
        path = Path(path_str)
        try:
            os.write(fd, cfg_json.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(path, 0o600)
        return ["--src-authfile", str(path)], path, None

    return [], None, f"unknown container_image auth_type: {auth!r}"


# ============================================================================
# Tool: download_artifact
# ============================================================================

async def artifact_download(
    session_id: str,
    url: str,
    sha256: str,
    filename: str = "artifact",
) -> dict[str, Any]:
    """Download an artifact (tarball / SBOM / etc.) and verify its sha256.

    Allowlist: ``url`` host MUST be in ``Target.kind_config.allowed_hosts``
    (operator-registered) OR in the per-kind default allowlist (npm, pypi,
    etc.). ``sha256`` is REQUIRED; if the hash doesn't match, the file is
    deleted and an error is returned.
    """
    import httpx

    cfg = _kind_config_for_session(session_id) or {}
    allowed = cfg.get("allowed_hosts") or []
    if not allowed:
        # Default per-kind allowlist for common public registries.
        allowed = [
            "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
            "repo.maven.apache.org", "rubygems.org", "crates.io",
        ]
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    if not any(host == a or host.endswith("." + a) for a in allowed):
        return {
            "error": "host_not_allowed",
            "host": host,
            "allowed": allowed,
        }
    if not (isinstance(sha256, str) and len(sha256) == 64 and all(c in "0123456789abcdef" for c in sha256.lower())):
        return {"error": "sha256 must be a 64-char hex digest"}

    target_path = _safe_output_path(session_id, filename)
    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            content = resp.content
    except httpx.HTTPError as exc:
        return {"error": f"download failed: {exc}"}
    actual = hashlib.sha256(content).hexdigest()
    if actual != sha256.lower():
        return {
            "error": "sha256 mismatch",
            "expected": sha256.lower(),
            "actual": actual,
        }
    target_path.write_bytes(content)
    return {"local_path": str(target_path), "bytes": len(content), "sha256": actual}


# ============================================================================
# Tool: parse_sbom (inline content, no subprocess)
# ============================================================================

# Per spec §7.3 SbomConfig.content is capped at 16 MiB. We re-check here so
# the tool refuses oversize blobs even if the schema validator was bypassed.
_SBOM_MAX_BYTES = 16 * 1024 * 1024


async def artifact_parse_sbom(
    session_id: str,
    content: str,
    sbom_format: str,
) -> dict[str, Any]:
    """Validate + write a CycloneDX/SPDX SBOM to the session's working dir.

    No subprocess — pure parse + write. The actual vuln-DB lookup happens
    in ``run_grype_sbom`` / ``run_osv_scanner_sbom`` against the written path.
    """
    if len(content.encode("utf-8")) > _SBOM_MAX_BYTES:
        return {"error": f"sbom content exceeds {_SBOM_MAX_BYTES}-byte cap"}
    if sbom_format not in {"cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value"}:
        return {"error": "unsupported sbom_format", "format": sbom_format}
    if sbom_format.endswith("-json"):
        try:
            json.loads(content)
        except json.JSONDecodeError as exc:
            return {"error": f"invalid JSON SBOM: {exc}"}
    ext = "json" if sbom_format.endswith("json") else ("xml" if sbom_format.endswith("xml") else "txt")
    out = _safe_output_path(session_id, f"sbom.{ext}")
    out.write_text(content, encoding="utf-8")
    return {"local_path": str(out), "format": sbom_format, "bytes": len(content)}


# ============================================================================
# Scanner: run_trivy_image
# ============================================================================

async def run_trivy_image(
    session_id: str,
    oci_layout: str | None = None,
    image_ref: str | None = None,
) -> dict[str, Any]:
    """Run trivy against an image (OCI layout preferred; ref fallback).

    Prefer offline mode (``--offline-scan``) so trivy doesn't fetch its CVE
    DB live during a scan; operators are expected to ``trivy image
    --download-db-only`` before deploying.
    """
    if not _which("trivy"):
        return {"error": "binary not found: trivy", "skipped": True}
    if not oci_layout and not image_ref:
        return {"error": "either oci_layout or image_ref required"}
    argv = ["trivy", "image", "--format", "json", "--quiet", "--offline-scan"]
    if oci_layout:
        argv.extend(["--input", oci_layout])
        if not Path(oci_layout).exists():
            return {"error": "oci_layout path does not exist"}
    else:
        # Validate image_ref against the session's registered ref.
        cfg = _kind_config_for_session(session_id) or {}
        registered = cfg.get("image_ref")
        if registered and image_ref != registered:
            return {
                "error": "image_ref_not_allowed",
                "registered": registered,
                "supplied": image_ref,
            }
        argv.append(image_ref or "")
    result = await _run_subprocess(argv)
    if result.get("error"):
        return result
    findings = _parse_trivy_json(result.get("stdout", ""))
    return {
        "scanner": "trivy",
        "findings_count": len(findings),
        "findings": findings,
    }


def _parse_trivy_json(stdout: str) -> list[dict[str, Any]]:
    """Map trivy's JSON output to pencheff finding dicts."""
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for result_block in data.get("Results", []):
        target_label = result_block.get("Target", "")
        for vuln in result_block.get("Vulnerabilities", []) or []:
            sev = (vuln.get("Severity") or "UNKNOWN").lower()
            # trivy → pencheff severity mapping
            sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                       "low": "low", "unknown": "info"}
            findings.append({
                "title": f"{vuln.get('VulnerabilityID', 'CVE')} in {vuln.get('PkgName', 'package')}",
                "severity": sev_map.get(sev, "info"),
                "category": "vulnerable_dependency",
                "owasp_category": "A06:2021",  # Vulnerable and Outdated Components
                "cve": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "description": vuln.get("Description", "")[:512],
                "remediation": (
                    f"Upgrade {vuln.get('PkgName')} to {vuln.get('FixedVersion')}"
                    if vuln.get("FixedVersion") else
                    "No fixed version available — consider an alternative package or vendor patch."
                ),
                "evidence": {"target_layer": target_label},
            })
    return findings


# ============================================================================
# Scanner: run_syft (SBOM generation)
# ============================================================================

async def run_syft(
    session_id: str,
    source_path: str,
    output_format: str = "cyclonedx-json",
) -> dict[str, Any]:
    """Generate an SBOM from a source path (directory or OCI layout)."""
    if not _which("syft"):
        return {"error": "binary not found: syft", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    if output_format not in {"cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value"}:
        return {"error": "unsupported output_format"}
    out_path = _safe_output_path(session_id, f"syft-sbom.{output_format.split('-')[-1]}")
    argv = ["syft", source_path, "-o", f"{output_format}={out_path}"]
    result = await _run_subprocess(argv)
    if result.get("error"):
        return result
    if result.get("returncode") != 0:
        return {"error": "syft failed", "stderr": result.get("stderr", "")[:2048]}
    return {"sbom_path": str(out_path), "format": output_format}


# ============================================================================
# Scanner: run_grype + run_grype_sbom
# ============================================================================

async def run_grype(
    session_id: str,
    source_path: str,
) -> dict[str, Any]:
    """Run grype against an image / dir / SBOM."""
    if not _which("grype"):
        return {"error": "binary not found: grype", "skipped": True}
    argv = ["grype", source_path, "-o", "json", "--quiet"]
    result = await _run_subprocess(argv)
    if result.get("error"):
        return result
    findings = _parse_grype_json(result.get("stdout", ""))
    return {"scanner": "grype", "findings_count": len(findings), "findings": findings}


async def run_grype_sbom(
    session_id: str,
    sbom_path: str,
) -> dict[str, Any]:
    """Run grype against an SBOM file (CycloneDX or SPDX)."""
    if not _which("grype"):
        return {"error": "binary not found: grype", "skipped": True}
    if not Path(sbom_path).exists():
        return {"error": "sbom_path does not exist"}
    return await run_grype(session_id, f"sbom:{sbom_path}")


def _parse_grype_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {}) or {}
        artifact = match.get("artifact", {}) or {}
        sev_raw = (vuln.get("severity") or "Unknown").lower()
        sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                   "low": "low", "negligible": "info", "unknown": "info"}
        fix = (vuln.get("fix") or {}).get("versions") or []
        fix_version = fix[0] if fix else None
        findings.append({
            "title": f"{vuln.get('id', 'CVE')} in {artifact.get('name', 'package')}",
            "severity": sev_map.get(sev_raw, "info"),
            "category": "vulnerable_dependency",
            "owasp_category": "A06:2021",
            "cve": vuln.get("id"),
            "package": artifact.get("name"),
            "installed_version": artifact.get("version"),
            "fixed_version": fix_version,
            "description": vuln.get("description", "")[:512],
            "remediation": (
                f"Upgrade {artifact.get('name')} to {fix_version}"
                if fix_version else
                "No fixed version published."
            ),
        })
    return findings


# ============================================================================
# Scanner: run_osv_scanner_sbom
# ============================================================================

async def run_osv_scanner_sbom(
    session_id: str,
    sbom_path: str,
) -> dict[str, Any]:
    """Run osv-scanner against an SBOM."""
    if not _which("osv-scanner"):
        return {"error": "binary not found: osv-scanner", "skipped": True}
    if not Path(sbom_path).exists():
        return {"error": "sbom_path does not exist"}
    argv = ["osv-scanner", "--format", "json", "--sbom", sbom_path]
    result = await _run_subprocess(argv)
    if result.get("error"):
        return result
    findings = _parse_osv_json(result.get("stdout", ""))
    return {"scanner": "osv-scanner", "findings_count": len(findings), "findings": findings}


def _parse_osv_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for r in data.get("results", []):
        for pkg in r.get("packages", []):
            pkg_info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []) or []:
                # osv-scanner reports severity in a different shape; pick the
                # highest CVSS score available.
                sev = "medium"
                for severity_block in vuln.get("severity", []) or []:
                    score = severity_block.get("score", "")
                    if isinstance(score, str) and score.startswith("CVSS:3"):
                        try:
                            base = float(score.split("/")[2].split(":")[1])
                        except (IndexError, ValueError):
                            base = 0.0
                        if base >= 9: sev = "critical"
                        elif base >= 7: sev = "high"
                        elif base >= 4: sev = "medium"
                        else: sev = "low"
                        break
                findings.append({
                    "title": f"{vuln.get('id')} in {pkg_info.get('name', 'package')}",
                    "severity": sev,
                    "category": "vulnerable_dependency",
                    "owasp_category": "A06:2021",
                    "cve": vuln.get("id"),
                    "package": pkg_info.get("name"),
                    "installed_version": pkg_info.get("version"),
                    "description": (vuln.get("summary") or vuln.get("details", ""))[:512],
                })
    return findings


# ============================================================================
# Scanner: run_checkov + run_tfsec (IaC)
# ============================================================================

async def run_checkov(
    session_id: str,
    source_path: str,
    framework: str | None = None,
) -> dict[str, Any]:
    """Run checkov against an IaC directory (terraform/k8s/cloudformation/helm)."""
    if not _which("checkov"):
        return {"error": "binary not found: checkov", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["checkov", "-d", source_path, "-o", "json", "--quiet", "--compact"]
    if framework:
        if framework not in {"terraform", "cloudformation", "helm", "kustomize", "kubernetes", "arm"}:
            return {"error": "unsupported framework"}
        argv.extend(["--framework", framework])
    result = await _run_subprocess(argv)
    if result.get("error"):
        return result
    findings = _parse_checkov_json(result.get("stdout", ""))
    return {"scanner": "checkov", "findings_count": len(findings), "findings": findings}


def _parse_checkov_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    blocks = data if isinstance(data, list) else [data]
    findings: list[dict[str, Any]] = []
    for blk in blocks:
        for fr in (blk.get("results") or {}).get("failed_checks", []) or []:
            sev = (fr.get("severity") or "MEDIUM").lower()
            sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                       "low": "low", "info": "info"}
            findings.append({
                "title": fr.get("check_name", "checkov rule"),
                "severity": sev_map.get(sev, "medium"),
                "category": "iac_misconfiguration",
                "owasp_category": "A05:2021",  # Security Misconfiguration
                "description": (fr.get("description") or fr.get("check_name") or "")[:512],
                "file_path": fr.get("file_path"),
                "line_start": (fr.get("file_line_range") or [None, None])[0],
                "line_end": (fr.get("file_line_range") or [None, None])[1],
                "remediation": fr.get("guideline") or "",
            })
    return findings


async def run_tfsec(session_id: str, source_path: str) -> dict[str, Any]:
    """Run tfsec against a Terraform directory."""
    if not _which("tfsec"):
        return {"error": "binary not found: tfsec", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["tfsec", source_path, "--format", "json", "--no-color"]
    result = await _run_subprocess(argv)
    if result.get("error"):
        return result
    findings = _parse_tfsec_json(result.get("stdout", ""))
    return {"scanner": "tfsec", "findings_count": len(findings), "findings": findings}


def _parse_tfsec_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for res in data.get("results", []) or []:
        sev = (res.get("severity") or "MEDIUM").lower()
        sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                   "low": "low", "info": "info"}
        loc = res.get("location", {}) or {}
        findings.append({
            "title": res.get("long_id") or res.get("rule_id") or "tfsec rule",
            "severity": sev_map.get(sev, "medium"),
            "category": "iac_misconfiguration",
            "owasp_category": "A05:2021",
            "description": (res.get("description") or "")[:512],
            "file_path": loc.get("filename"),
            "line_start": loc.get("start_line"),
            "line_end": loc.get("end_line"),
            "remediation": res.get("resolution") or "",
        })
    return findings


# ============================================================================
# Scanner: run_npm_audit + run_pip_audit (package_registry)
# ============================================================================

async def run_npm_audit(
    session_id: str,
    project_path: str,
) -> dict[str, Any]:
    """Run ``npm audit --json`` against a project directory with package.json."""
    if not _which("npm"):
        return {"error": "binary not found: npm", "skipped": True}
    pkg = Path(project_path) / "package.json"
    if not pkg.exists():
        return {"error": "package.json not found", "project_path": project_path}
    argv = ["npm", "audit", "--json", "--audit-level=low"]
    result = await _run_subprocess(argv, cwd=project_path)
    # npm audit exits non-zero when vulns are found — parse output regardless.
    findings = _parse_npm_audit_json(result.get("stdout", ""))
    return {"scanner": "npm-audit", "findings_count": len(findings), "findings": findings}


def _parse_npm_audit_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    vulns = data.get("vulnerabilities") or {}
    for pkg_name, info in vulns.items():
        sev = (info.get("severity") or "moderate").lower()
        sev_map = {"critical": "critical", "high": "high", "moderate": "medium",
                   "low": "low", "info": "info"}
        via_list = info.get("via") if isinstance(info.get("via"), list) else []
        first_via = via_list[0] if via_list else {}
        cve = first_via.get("url") if isinstance(first_via, dict) else None
        findings.append({
            "title": f"{pkg_name}: {sev_map.get(sev, 'medium')} advisory",
            "severity": sev_map.get(sev, "medium"),
            "category": "vulnerable_dependency",
            "owasp_category": "A06:2021",
            "package": pkg_name,
            "installed_version": info.get("version"),
            "fixed_version": (info.get("fixAvailable") or {}).get("version") if isinstance(info.get("fixAvailable"), dict) else None,
            "description": (first_via.get("title") if isinstance(first_via, dict) else "") or "",
            "evidence": {"advisory_url": cve} if cve else None,
        })
    return findings


async def run_pip_audit(
    session_id: str,
    requirements_path: str | None = None,
    project_path: str | None = None,
) -> dict[str, Any]:
    """Run ``pip-audit`` against a requirements file or project dir."""
    if not _which("pip-audit"):
        return {"error": "binary not found: pip-audit", "skipped": True}
    if not requirements_path and not project_path:
        return {"error": "requirements_path or project_path required"}
    argv = ["pip-audit", "--format", "json", "--no-deps"]
    if requirements_path:
        if not Path(requirements_path).exists():
            return {"error": "requirements_path does not exist"}
        argv.extend(["--requirement", requirements_path])
    else:
        if not Path(project_path or "").exists():
            return {"error": "project_path does not exist"}
        argv.extend(["--local", "--path", project_path])  # type: ignore[arg-type]
    result = await _run_subprocess(argv)
    findings = _parse_pip_audit_json(result.get("stdout", ""))
    return {"scanner": "pip-audit", "findings_count": len(findings), "findings": findings}


def _parse_pip_audit_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    deps = data.get("dependencies") if isinstance(data, dict) else data
    for d in (deps or []):
        for vuln in d.get("vulns", []) or []:
            findings.append({
                "title": f"{vuln.get('id')} in {d.get('name')}",
                "severity": "high",  # pip-audit doesn't always provide severity
                "category": "vulnerable_dependency",
                "owasp_category": "A06:2021",
                "cve": vuln.get("id"),
                "package": d.get("name"),
                "installed_version": d.get("version"),
                "fixed_version": (vuln.get("fix_versions") or [None])[0],
                "description": (vuln.get("description") or "")[:512],
            })
    return findings


# ============================================================================
# Scanner: run_hadolint (Dockerfile linting)
# ============================================================================

async def run_hadolint(session_id: str, dockerfile_path: str) -> dict[str, Any]:
    """Run hadolint against a Dockerfile to surface security + best-practice
    misconfigurations."""
    if not _which("hadolint"):
        return {"error": "binary not found: hadolint", "skipped": True}
    if not Path(dockerfile_path).exists():
        return {"error": "dockerfile_path does not exist"}
    argv = ["hadolint", "--format", "json", dockerfile_path]
    result = await _run_subprocess(argv)
    findings = _parse_hadolint_json(result.get("stdout", ""))
    return {"scanner": "hadolint", "findings_count": len(findings), "findings": findings}


def _parse_hadolint_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for entry in data if isinstance(data, list) else []:
        lvl = (entry.get("level") or "warning").lower()
        sev_map = {"error": "high", "warning": "medium", "info": "low", "style": "info"}
        findings.append({
            "title": f"{entry.get('code', 'HL')}: {entry.get('message', '')[:120]}",
            "severity": sev_map.get(lvl, "low"),
            "category": "container_misconfiguration",
            "owasp_category": "A05:2021",
            "description": entry.get("message", ""),
            "file_path": entry.get("file"),
            "line_start": entry.get("line"),
        })
    return findings


# ============================================================================
# Public surface (used by ``from .artifact_tools import *`` in server.py)
# ============================================================================

__all__ = [
    # Allowlist hook
    "set_kind_config_for_session",
    # Artifact-acquisition tools (artifact_ prefix avoids collision with
    # the legacy pencheff.core.repo_workspace.clone_repo helper used by the
    # repo-mirror flow).
    "artifact_clone_repo",
    "artifact_pull_image",
    "artifact_download",
    "artifact_parse_sbom",
    # Container scanners
    "run_trivy_image",
    "run_syft",
    "run_grype",
    "run_grype_sbom",
    "run_hadolint",
    # IaC scanners
    "run_checkov",
    "run_tfsec",
    # Package-registry scanners
    "run_npm_audit",
    "run_pip_audit",
    # SBOM scanners
    "run_osv_scanner_sbom",
]

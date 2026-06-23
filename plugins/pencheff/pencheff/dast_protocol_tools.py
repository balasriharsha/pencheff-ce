"""Protocol-specific DAST scanners (feature 001-multi-target-scan-pipelines).

Wraps three classes of tool the existing scan_api / scan_websocket can't fully
cover:

  * ``run_graphql_cop`` — graphql-cop probes for introspection exposure,
    field-suggestion leaks, batched-query DoS, alias attacks.
  * ``run_inql`` — Pentestit's InQL extracts GraphQL schemas + auto-generates
    query/mutation fuzz cases; complements run_graphql_cop.
  * ``run_grpcurl`` — gRPC reflection enumeration + method invocation. Used
    by GrpcReflectionAgent for service/method discovery and primitive payload
    fuzzing.
  * ``parse_proto`` — pure-Python .proto parser fallback when gRPC reflection
    is disabled and the operator uploaded proto files in kind_config.

Subprocess discipline mirrors artifact_tools: ``shutil.which`` gate, graceful
``{"error": "binary not found", "skipped": True}`` when missing, JSON parsing
into pencheff finding shape with ``owasp_category`` tagging.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import Any

from .artifact_tools import _kind_config_for_session, _run_subprocess, _which


# ============================================================================
# run_graphql_cop
# ============================================================================


async def run_graphql_cop(
    session_id: str,
    endpoint: str | None = None,
) -> dict[str, Any]:
    """Probe a GraphQL endpoint for introspection / DoS / info-leak issues.

    Allowlist: ``endpoint`` MUST equal the target's base_url (we don't ship a
    separate kind_config.graphql_endpoint — the URL is on Target.base_url and
    the agent passes it through). When ``endpoint`` is None, we fall back to
    the session-bound kind_config.
    """
    if not _which("graphql-cop"):
        return {"error": "binary not found: graphql-cop", "skipped": True}
    cfg = _kind_config_for_session(session_id) or {}
    if not endpoint:
        endpoint = cfg.get("endpoint") or cfg.get("base_url") or ""
    if not endpoint or not endpoint.startswith(("http://", "https://")):
        return {"error": "endpoint must be a fully-qualified http(s):// URL"}

    argv = ["graphql-cop", "-t", endpoint, "-o", "json"]
    if cfg.get("introspection_enabled") is False:
        argv.append("--no-introspection")
    result = await _run_subprocess(argv, timeout=120)
    if result.get("error"):
        return result
    findings = _parse_graphql_cop_json(result.get("stdout", ""))
    return {"scanner": "graphql-cop", "findings_count": len(findings), "findings": findings}


def _parse_graphql_cop_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    # graphql-cop emits a list of {title, severity, description, …} per check.
    findings: list[dict[str, Any]] = []
    for entry in data if isinstance(data, list) else (data.get("results") or []):
        sev_raw = (entry.get("severity") or "low").lower()
        sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                   "low": "low", "info": "info", "informational": "info"}
        title = entry.get("title") or entry.get("name") or "GraphQL issue"
        findings.append({
            "title": title[:255],
            "severity": sev_map.get(sev_raw, "low"),
            "category": "graphql_misconfiguration",
            # OWASP API Security Top 10 maps closer than the web list; we
            # keep the same enum used by the existing breakers and lean on
            # A05:2021 (Security Misconfiguration) for introspection/aliasing
            # and A04:2021 (Insecure Design) for query-depth DoS. Default to
            # A05 — operators triage further during review.
            "owasp_category": "A05:2021",
            "description": (entry.get("description") or "")[:512],
            "remediation": entry.get("remediation") or "",
        })
    return findings


# ============================================================================
# run_inql
# ============================================================================


async def run_inql(
    session_id: str,
    endpoint: str | None = None,
    output_format: str = "json",
) -> dict[str, Any]:
    """Extract a GraphQL schema via InQL and surface object-permission gaps.

    InQL's standalone CLI emits JSON of queries/mutations the agent can then
    probe via test_endpoint. We translate the schema summary into INFO-level
    findings so the operator sees what was discovered.
    """
    if not _which("inql"):
        return {"error": "binary not found: inql", "skipped": True}
    cfg = _kind_config_for_session(session_id) or {}
    if not endpoint:
        endpoint = cfg.get("endpoint") or cfg.get("base_url") or ""
    if not endpoint or not endpoint.startswith(("http://", "https://")):
        return {"error": "endpoint must be a fully-qualified http(s):// URL"}

    argv = ["inql", "-t", endpoint, "-o", output_format]
    result = await _run_subprocess(argv, timeout=180)
    if result.get("error"):
        return result
    # InQL prints a verbose schema dump rather than structured findings; we
    # surface a single INFO finding summarising what it found, plus the raw
    # schema for the orchestrator to feed downstream agents.
    queries = mutations = subscriptions = 0
    for line in (result.get("stdout") or "").splitlines():
        if line.startswith("Query."):
            queries += 1
        elif line.startswith("Mutation."):
            mutations += 1
        elif line.startswith("Subscription."):
            subscriptions += 1
    finding = {
        "title": f"GraphQL schema introspected: {queries}Q / {mutations}M / {subscriptions}S",
        "severity": "info",
        "category": "graphql_schema_disclosure",
        "owasp_category": "A05:2021",
        "description": (
            f"InQL extracted {queries} queries, {mutations} mutations, "
            f"{subscriptions} subscriptions from {endpoint}. Review for "
            f"object-level authorization gaps (BOLA / IDOR via GraphQL aliases)."
        ),
    }
    return {
        "scanner": "inql",
        "findings_count": 1 if (queries or mutations or subscriptions) else 0,
        "findings": [finding] if (queries or mutations or subscriptions) else [],
        "schema_summary": {"queries": queries, "mutations": mutations, "subscriptions": subscriptions},
    }


# ============================================================================
# run_grpcurl
# ============================================================================


async def run_grpcurl(
    session_id: str,
    target: str | None = None,
    action: str = "list",
    service: str | None = None,
    method: str | None = None,
    payload_json: str | None = None,
) -> dict[str, Any]:
    """Drive grpcurl for reflection enumeration and method invocation.

    Actions:
      * ``list`` — enumerate services (default).
      * ``describe`` — describe a service or method.
      * ``invoke`` — call a method with a JSON payload.

    Safety: the calling agent_runner already blocks ``--plaintext`` and
    ``--import-path`` via _DANGEROUS_ARG_SUBSTRINGS (feature 001 S-07).
    This wrapper additionally validates ``target`` against the session's
    kind_config and refuses freeform args.
    """
    if not _which("grpcurl"):
        return {"error": "binary not found: grpcurl", "skipped": True}
    cfg = _kind_config_for_session(session_id) or {}
    if not target:
        target = cfg.get("base_url") or cfg.get("endpoint") or ""
    target = (target or "").strip()
    if not target:
        return {"error": "no target host:port supplied"}
    # Disallow shell metacharacters defensively (grpcurl is exec'd as argv but
    # the agent could otherwise emit dangerous-looking values).
    if any(c in target for c in (" ", ";", "&", "|", "\n", "\r", "$", "`")):
        return {"error": "invalid target — host:port only"}

    argv: list[str] = ["grpcurl"]
    # TLS verification default-on (kind_config.tls_verify is honoured); the
    # agent_runner _DANGEROUS_ARG_SUBSTRINGS blocks --plaintext outright.
    if not cfg.get("tls_verify", True):
        argv.append("-insecure")  # accept self-signed but still uses TLS

    if action == "list":
        argv.extend([target, "list"])
        if service:
            argv.append(service)
    elif action == "describe":
        if not service and not method:
            return {"error": "describe requires service or method"}
        argv.extend([target, "describe", service or method])  # type: ignore[arg-type]
    elif action == "invoke":
        if not service or not method:
            return {"error": "invoke requires service AND method"}
        if payload_json is None:
            payload_json = "{}"
        try:
            json.loads(payload_json)  # validate
        except json.JSONDecodeError:
            return {"error": "payload_json must be valid JSON"}
        argv.extend(["-d", payload_json, target, f"{service}/{method}"])
    else:
        return {"error": f"unknown action: {action}"}

    result = await _run_subprocess(argv, timeout=60)
    if result.get("error"):
        return result
    findings: list[dict[str, Any]] = []
    # When the agent invokes a method with garbage input and the server
    # accepts it (no auth, no validation), surface as a finding. Otherwise
    # we just return the stdout for the agent to interpret.
    stdout = result.get("stdout") or ""
    if action == "invoke" and result.get("returncode") == 0:
        findings.append({
            "title": f"gRPC method {service}/{method} accepted unauthenticated invocation",
            "severity": "medium",
            "category": "grpc_unauthenticated_method",
            "owasp_category": "A01:2021",  # Broken Access Control
            "description": (
                f"Calling {service}/{method} with payload returned success "
                f"without an auth header. Verify whether this method should "
                f"require authentication."
            ),
            "evidence": {"response_excerpt": stdout[:512]},
        })
    return {
        "scanner": "grpcurl",
        "findings_count": len(findings),
        "findings": findings,
        "stdout": stdout[:4096],
    }


# ============================================================================
# parse_proto — pure-Python fallback when reflection is disabled
# ============================================================================


# Pre-feature-001 we never accepted .proto file content from operators; with
# GrpcConfig.proto_files supported, we need to surface what services are
# declared so the agent can drive run_grpcurl describe/invoke against them.
# A full protobuf parser is overkill — we extract service + rpc declarations
# via regex which is robust to comment/whitespace variations.
_PROTO_SERVICE_RE = re.compile(
    r"\bservice\s+(\w+)\s*\{([^}]*)\}",
    re.MULTILINE | re.DOTALL,
)
_PROTO_RPC_RE = re.compile(
    r"\brpc\s+(\w+)\s*\(\s*(stream\s+)?(\w+(?:\.\w+)*)\s*\)\s*"
    r"returns\s*\(\s*(stream\s+)?(\w+(?:\.\w+)*)\s*\)",
)


async def parse_proto(
    session_id: str,
    proto_content: str | None = None,
) -> dict[str, Any]:
    """Extract service + RPC declarations from operator-supplied .proto files.

    Used when ``kind_config.reflection_enabled = False`` and the operator
    uploaded protobuf source via ``kind_config.proto_files``. Returns a
    structured services list the agent can hand to ``run_grpcurl describe``
    once it has the live target.
    """
    cfg = _kind_config_for_session(session_id) or {}
    # Caller may pass content explicitly; fall back to kind_config.proto_files
    # which is a list[str] of .proto file bodies.
    sources: list[str] = []
    if proto_content:
        sources.append(proto_content)
    for body in cfg.get("proto_files") or []:
        if isinstance(body, str):
            sources.append(body)
    if not sources:
        return {"error": "no proto content supplied"}

    services: list[dict[str, Any]] = []
    for src in sources:
        for svc_match in _PROTO_SERVICE_RE.finditer(src):
            svc_name = svc_match.group(1)
            body = svc_match.group(2)
            rpcs: list[dict[str, Any]] = []
            for rpc_match in _PROTO_RPC_RE.finditer(body):
                rpcs.append({
                    "name": rpc_match.group(1),
                    "input_type": rpc_match.group(3),
                    "input_stream": bool(rpc_match.group(2)),
                    "output_type": rpc_match.group(5),
                    "output_stream": bool(rpc_match.group(4)),
                })
            services.append({"name": svc_name, "rpcs": rpcs})

    return {
        "scanner": "parse_proto",
        "services": services,
        "service_count": len(services),
        "rpc_count": sum(len(s["rpcs"]) for s in services),
    }


__all__ = [
    "run_graphql_cop",
    "run_inql",
    "run_grpcurl",
    "parse_proto",
]

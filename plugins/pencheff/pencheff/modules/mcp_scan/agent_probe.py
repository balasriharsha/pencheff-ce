# pencheff/modules/mcp_scan/agent_probe.py
"""Toxic-flow analysis + agent-endpoint probing for MCP agent sources.

Covers source_type in {"agent_http", "agent_browser"}.

Pure logic (lethal_trifecta_present, build_agent_probe_config) is fully
unit-tested. Live LLM probing via run_agent_probe is integration surface;
it degrades non-fatally on any error.
"""
from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import McpTool

# ---------------------------------------------------------------------------
# Bucket keyword sets — each is a list of regex patterns.
# A tool matches a bucket if any pattern hits in name+description (case-insensitive).
# ---------------------------------------------------------------------------

# Bucket A: untrusted-input / content ingestion
_BUCKET_A = [
    r"\bfetch\b", r"\bhttp\b", r"\burl\b", r"\bbrowse\b", r"\bsearch\b",
    r"\bretrieve\b", r"\buntrusted\b", r"\bweb\b", r"\bissue\b",
    r"\bcomment\b", r"\bread.{0,10}email\b", r"\bingest\b",
]

# Bucket B: private-data access
_BUCKET_B = [
    r"\bprivate\b", r"\bsecret\b", r"\binternal\b", r"\brepo\b",
    r"\bdatabase\b", r"\bfile.{0,5}read\b", r"\bread.{0,5}file\b",
    r"\bcredential\b", r"\bpassword\b", r"\btoken\b",
]

# Bucket C: exfiltration / egress
_BUCKET_C = [
    r"\bsend\b", r"\bpost\b", r"\bemail\b", r"\bwebhook\b",
    r"\bupload\b", r"\bexternal\b", r"\bcreate.{0,10}(pr|issue)\b",
    r"\bpublish\b", r"\begress\b", r"\bexport\b", r"\bwrite.{0,10}external\b",
]


def _tool_matches_bucket(tool: McpTool, patterns: list[str]) -> bool:
    text = f"{tool.name} {tool.description}"
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def lethal_trifecta_present(tools: list[McpTool]) -> bool:
    """Return True iff the tool set contains at least one tool in each of the
    three toxic-flow buckets: (A) untrusted-input, (B) private-data, (C) egress.

    This models the confused-deputy / data-exfiltration precondition described
    in the MCP security research (Simon Willison, Trail of Bits, 2025).
    """
    has_a = any(_tool_matches_bucket(t, _BUCKET_A) for t in tools)
    has_b = any(_tool_matches_bucket(t, _BUCKET_B) for t in tools)
    has_c = any(_tool_matches_bucket(t, _BUCKET_C) for t in tools)
    return has_a and has_b and has_c


# ---------------------------------------------------------------------------
# Config builder
# ---------------------------------------------------------------------------

def build_agent_probe_config(cfg: dict[str, Any], *, base_url: str) -> dict[str, Any]:
    """Map an agent McpConfig into the llm_config dict shape consumed by LlmProbe.

    Sets redteam.plugins=["mcp"] so the existing mcp.yaml attack pack runs.
    """
    source_type = cfg.get("source_type", "")

    if source_type == "agent_http":
        return {
            "provider": cfg["provider"],
            "model": cfg.get("model"),
            "request_template": cfg.get("request_template"),
            "response_path": cfg.get("response_path"),
            "redteam": {"plugins": ["mcp"]},
        }

    if source_type == "agent_browser":
        return {
            "provider": "browser",
            "browser": {
                "url": cfg.get("url"),
                "prompt_selector": cfg.get("prompt_selector"),
                "send_selector": cfg.get("send_selector"),
                "response_selector": cfg.get("response_selector"),
            },
            "redteam": {"plugins": ["mcp"]},
        }

    # Fallback: return a minimal config with the base_url
    return {
        "provider": "unknown",
        "url": base_url,
        "redteam": {"plugins": ["mcp"]},
    }


# ---------------------------------------------------------------------------
# Live agent probe (integration surface — non-fatal)
# ---------------------------------------------------------------------------

async def run_agent_probe(session, mcp_config: dict[str, Any]) -> list[Finding]:
    """Probe an agent_http or agent_browser endpoint using the llm_red_team pack.

    Pure logic (trifecta + config building) runs unconditionally.
    Live LLM probing is attempted but never fatal.
    """
    findings: list[Finding] = []
    source_type = mcp_config.get("source_type", "")
    url = mcp_config.get("url", "")

    # Build the probe config regardless of live probing success.
    probe_cfg = build_agent_probe_config(mcp_config, base_url=url)

    # --- Live LLM red-team probe (best-effort) ---
    try:
        from pencheff.modules.llm_red_team import LLM_RED_TEAM_MODULES

        # Set the llm_config on the session so LlmRedTeamModule.run() picks it up.
        if hasattr(session, "llm_config"):
            session.llm_config = probe_cfg

        # Run the LLM06 ExcessiveAgency module which carries the mcp addon cases.
        excessive_agency_cls = LLM_RED_TEAM_MODULES.get("LLM06")
        if excessive_agency_cls is not None:
            module = excessive_agency_cls()
            live_findings = await module.run(session, http=None, config={"llm_config": probe_cfg})
            findings.extend(live_findings)
    except Exception as e:
        # Live probing is integration surface — degrade non-fatally, but log so failures are observable.
        log.warning("mcp agent live-probe failed: %s", e)

    # --- Toxic-flow static analysis ---
    # Pull tool list from session or mcp_config if available.
    tools: list[McpTool] = []
    try:
        tools_raw = mcp_config.get("tools") or []
        tools = [
            McpTool(name=t.get("name", ""), description=t.get("description", ""))
            if isinstance(t, dict) else t
            for t in tools_raw
        ]
        # Also check session-level tool info if present.
        if not tools and hasattr(session, "mcp_config") and session.mcp_config:
            tools_raw = session.mcp_config.get("tools") or []
            tools = [
                McpTool(name=t.get("name", ""), description=t.get("description", ""))
                if isinstance(t, dict) else t
                for t in tools_raw
            ]
    except Exception:
        tools = []

    if tools and lethal_trifecta_present(tools):
        findings.append(
            Finding(
                title="MCP Toxic-Flow: Confused Deputy / Data Exfiltration Risk",
                severity=Severity.HIGH,
                category="MCP Security",
                owasp_category="LLM06",
                description=(
                    "The agent's tool set combines untrusted-input ingestion, private-data "
                    "access, and an egress/exfiltration capability — the three-bucket "
                    "precondition for a confused-deputy attack. A compromised or adversarial "
                    "tool call can read private data and exfiltrate it via the egress tool "
                    "without explicit user consent (MCP toxic-flow pattern)."
                ),
                remediation=(
                    "Apply least-privilege: restrict which tools can be combined in a single "
                    "agent session. Use MCP elicitation / consent gates before any tool that "
                    "reads private data. Monitor egress tool calls for anomalous data volumes."
                ),
                endpoint=url,
                cwe_id="CWE-441",
                references=[
                    "https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/",
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                metadata={"technique": "mcp:toxic-flow"},
            )
        )

    return findings

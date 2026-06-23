# pencheff/modules/mcp_scan/static_analyzers.py
"""Pure static analyzers over an McpManifest. No network; fully unit-testable.

Each analyze_* returns a list[Finding]. run_all_static() aggregates them.
Detection backed by the research catalog in the spec (line-jumping, Unicode-tag
smuggling, excessive agency, etc.).
"""
from __future__ import annotations

import hashlib
import json
import re

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding

from .manifest import McpManifest

# Imperative / override / relay phrasing aimed at the model (line jumping,
# tool-description poisoning — Trail of Bits 2025-04-21).
_POISON_PATTERNS = [
    r"(?i)ignore (the |all |any )?(previous|prior|above) (instructions?|context)",
    r"(?i)do not (tell|mention|inform|reveal)[^.]{0,40}\b(user|human)\b",
    r"(?i)\balways (append|prepend|include|add|respond with)\b",
    r"(?i)\byou must\b[^.]{0,60}\b(append|prefix|run|execute|call)\b",
    r"(?i)<\s*(important|system|secret|instructions?)\s*>",
    r"(?i)\bsystem\s*:\s*",
    r"(?i)before (using|calling) (any )?(other )?tools?",
    r"(?i)\b(act as|behave as) (a )?(relay|proxy|message)\b",
]

# Dangerous capability signals in tool names/descriptions (excessive agency).
_DANGEROUS = [
    r"(?i)\b(exec|execute|eval|spawn|subprocess)\b",
    r"(?i)\b(shell|bash|sh|powershell|cmd)\b",
    r"(?i)\b(run[_-]?command|os[_-]?command)\b",
    r"(?i)\b(delete|remove|rm|drop|truncate|wipe)\b",
    r"(?i)\b(write[_-]?file|put[_-]?file|overwrite|chmod|chown)\b",
    r"(?i)\b(payment|transfer|charge|refund|wire|payout)\b",
    r"(?i)\b(sudo|root|privilege)\b",
]

# Unicode Tags block U+E0000–U+E007F + common zero-width / bidi chars.
# Zero-width: U+200B-U+200F, Bidi overrides: U+202A-U+202E,
# Bidi isolates: U+2066-U+2069, BOM/ZWNBSP: U+FEFF
_HIDDEN_RE = re.compile(
    "["
    "\U000E0000-\U000E007F"  # Unicode Tags block
    "​-‏"          # zero-width space, ZWNJ, ZWJ, LRM, RLM
    "‪-‮"          # LRE, RLE, PDF, LRO, RLO (bidi overrides)
    "⁦-⁩"          # LRI, RLI, FSI, PDI (bidi isolates)
    "﻿"                 # BOM / zero-width no-break space
    "]"
)

# Sensitive resource hints.
_SENSITIVE_URI = re.compile(
    r"(?i)(\.env\b|/etc/|id_rsa|\.pem\b|secret|credential|token|password|/\.ssh/|/\.aws/)"
)


def _texts_of_tool(t) -> str:
    return f"{t.name}\n{t.description}\n{json.dumps(t.input_schema, sort_keys=True)}"


def analyze_tool_poisoning(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for t in mf.tools:
        hits = [p for p in _POISON_PATTERNS if re.search(p, t.description or "")]
        if hits:
            out.append(Finding(
                title=f"Tool-description poisoning in MCP tool '{t.name}'",
                severity=Severity.HIGH,
                category="mcp_tool_poisoning",
                owasp_category="LLM01",
                description=(
                    f"The MCP tool '{t.name}' carries imperative/override instructions in "
                    f"its description, which is injected into the model's context during "
                    f"tools/list — before any tool is invoked (line jumping). Matched: "
                    f"{', '.join(hits)}."
                ),
                remediation=(
                    "Reject or sanitize tool descriptions containing model-directed "
                    "instructions; treat MCP tool metadata as untrusted input."
                ),
                endpoint=mf.endpoint,
                parameter=t.name,
                cwe_id="CWE-94",
                references=["https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/"],
                evidence=[Evidence(request_method="MCP", request_url=mf.endpoint,
                                   description=f"tools/list description: {t.description[:500]}")],
                metadata={"technique": "mcp:line-jumping", "tool": t.name},
            ))
    return out


def analyze_hidden_content(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []

    def scan(label: str, name: str, text: str):
        if text and _HIDDEN_RE.search(text):
            cps = sorted({f"U+{ord(c):04X}" for c in text if _HIDDEN_RE.match(c)})
            out.append(Finding(
                title=f"Hidden/invisible characters in MCP {label} '{name}'",
                severity=Severity.HIGH,
                category="mcp_hidden_content",
                owasp_category="LLM01",
                description=(
                    f"The MCP {label} '{name}' contains non-printing characters "
                    f"({', '.join(cps)}) that render invisibly in UIs but are interpreted "
                    f"by the model — a smuggled prompt-injection vector."
                ),
                remediation=(
                    "Strip Unicode Tags (U+E0000–U+E007F) and zero-width/bidi characters "
                    "from MCP metadata before it reaches the model."
                ),
                endpoint=mf.endpoint,
                parameter=name,
                cwe_id="CWE-176",
                references=["https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/"],
                metadata={"technique": "mcp:unicode-tag-smuggling", "codepoints": cps},
            ))

    for t in mf.tools:
        scan("tool", t.name, f"{t.name} {t.description}")
    for r in mf.resources:
        scan("resource", r.name or r.uri, f"{r.name} {r.description}")
    for p in mf.prompts:
        scan("prompt", p.name, f"{p.name} {p.description}")
    return out


def analyze_excessive_agency(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for t in mf.tools:
        blob = _texts_of_tool(t)
        hits = [p for p in _DANGEROUS if re.search(p, blob)]
        if hits:
            out.append(Finding(
                title=f"Excessive-agency / dangerous capability in MCP tool '{t.name}'",
                severity=Severity.MEDIUM,
                category="mcp_excessive_agency",
                owasp_category="LLM06",
                description=(
                    f"The MCP tool '{t.name}' exposes a high-impact capability "
                    f"(exec/file-write/delete/payment/privilege) that an injected or "
                    f"confused agent could abuse. Matched: {', '.join(hits)}."
                ),
                remediation=(
                    "Scope the tool to least privilege, require explicit human approval "
                    "for destructive actions, and constrain its input schema."
                ),
                endpoint=mf.endpoint,
                parameter=t.name,
                cwe_id="CWE-250",
                metadata={"technique": "mcp:excessive-agency", "tool": t.name},
            ))
    return out


def analyze_schema_weakness(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for t in mf.tools:
        s = t.input_schema or {}
        weak = bool(s.get("additionalProperties") is True)
        props = s.get("properties") or {}
        # free-form string params with no constraints
        loose = [k for k, v in props.items()
                 if isinstance(v, dict) and v.get("type") == "string"
                 and not any(c in v for c in ("enum", "pattern", "maxLength", "format"))]
        if weak or loose:
            out.append(Finding(
                title=f"Weak input schema on MCP tool '{t.name}'",
                severity=Severity.LOW,
                category="mcp_schema_weakness",
                owasp_category="LLM06",
                description=(
                    f"Tool '{t.name}' accepts unconstrained input"
                    + (" (additionalProperties: true)" if weak else "")
                    + (f"; unconstrained string params: {', '.join(loose)}" if loose else "")
                    + " — widening the injection / abuse surface."
                ),
                remediation=(
                    "Constrain parameters with enum/pattern/maxLength and set "
                    "additionalProperties:false."
                ),
                endpoint=mf.endpoint,
                parameter=t.name,
                cwe_id="CWE-20",
                metadata={"technique": "mcp:weak-schema", "tool": t.name},
            ))
    return out


def analyze_sensitive_resources(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for r in mf.resources:
        blob = f"{r.uri} {r.name} {r.description}"
        if _SENSITIVE_URI.search(blob):
            out.append(Finding(
                title=f"MCP server exposes sensitive resource '{r.name or r.uri}'",
                severity=Severity.HIGH,
                category="mcp_sensitive_resource",
                owasp_category="LLM02",
                description=(
                    f"The MCP server advertises a resource that appears to expose "
                    f"secrets / credentials / sensitive files: {r.uri}"
                ),
                remediation=(
                    "Remove sensitive files from the server's advertised resources or "
                    "gate them behind explicit authorization."
                ),
                endpoint=mf.endpoint,
                parameter=r.uri,
                cwe_id="CWE-200",
                metadata={"technique": "mcp:sensitive-resource", "uri": r.uri},
            ))
    return out


def analyze_prompt_poisoning(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for p in mf.prompts:
        hits = [pat for pat in _POISON_PATTERNS if re.search(pat, p.description or "")]
        if hits:
            out.append(Finding(
                title=f"Prompt-template poisoning in MCP prompt '{p.name}'",
                severity=Severity.HIGH,
                category="mcp_prompt_poisoning",
                owasp_category="LLM01",
                description=(
                    f"The MCP prompt template '{p.name}' carries injected/override "
                    f"instructions. Matched: {', '.join(hits)}."
                ),
                remediation=(
                    "Treat server-supplied prompt templates as untrusted; sanitize "
                    "before use."
                ),
                endpoint=mf.endpoint,
                parameter=p.name,
                cwe_id="CWE-94",
                metadata={"technique": "mcp:prompt-poisoning", "prompt": p.name},
            ))
    return out


def baseline_hash(mf: McpManifest) -> str:
    """Stable, order-independent hash of tool descriptions + schemas, for
    rug-pull drift detection via compare_scans (Plan 3+). JSON serialization
    is collision-proof against attacker-controlled separators in tool fields."""
    items = sorted(
        json.dumps([t.name, t.description, t.input_schema], sort_keys=True)
        for t in mf.tools
    )
    return hashlib.sha256(json.dumps(items).encode("utf-8")).hexdigest()


def run_all_static(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for fn in (
        analyze_tool_poisoning,
        analyze_hidden_content,
        analyze_excessive_agency,
        analyze_schema_weakness,
        analyze_sensitive_resources,
        analyze_prompt_poisoning,
    ):
        out.extend(fn(mf))
    return out

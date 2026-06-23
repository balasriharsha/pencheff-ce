# pencheff/modules/rag_scan/static_analyzers.py
"""Pure static analyzers over a RagManifest. No network; fully unit-testable.

Each analyze_* returns a list[Finding]. run_all_static() aggregates them.
"""
from __future__ import annotations

import hashlib
import json
import re

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import RagManifest

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key ID
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[=:]\s*\S+"),  # key=val
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                   # OpenAI-style secret key
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),  # private key
    re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
]


def _has_secret(text: str) -> bool:
    """Return True if text contains a detectable secret. Self-contained
    (regex-only) to stay deterministic regardless of ambient imports."""
    if not text:
        return False
    return any(p.search(text) for p in _SECRET_PATTERNS)


def analyze_exposure(mf: RagManifest) -> list[Finding]:
    """Flag unauthenticated vector DB endpoints (CWE-306)."""
    if mf.auth_required is False:
        return [Finding(
            title="Unauthenticated vector DB endpoint exposed",
            severity=Severity.CRITICAL,
            category="rag_exposed_db",
            owasp_category="LLM08",
            cwe_id="CWE-306",
            description=(
                f"The vector database at {mf.endpoint!r} requires no authentication. "
                "An attacker can directly query, enumerate, or exfiltrate all stored "
                "embeddings and associated chunk text without any credential."
            ),
            remediation=(
                "Enable authentication on the vector DB (API key, mTLS, or IAM). "
                "Place the endpoint behind a private network boundary and restrict "
                "public exposure."
            ),
            endpoint=mf.endpoint,
            metadata={"technique": "rag:exposed-db"},
        )]
    return []


def analyze_tenancy(mf: RagManifest) -> list[Finding]:
    """Flag missing tenant isolation (cross-tenant data leakage)."""
    if mf.tenancy_isolation is False:
        return [Finding(
            title="Vector DB lacks tenant isolation — cross-tenant leak risk",
            severity=Severity.HIGH,
            category="rag_cross_tenant",
            owasp_category="LLM08",
            cwe_id="CWE-200",
            description=(
                "The vector database has no tenant isolation configured. In a "
                "multi-tenant deployment, one tenant's queries can retrieve chunks "
                "from another tenant's knowledge base, leaking confidential data."
            ),
            remediation=(
                "Partition indexes or namespaces per tenant and enforce tenant-scoped "
                "filters on every query. Never allow cross-namespace queries without "
                "explicit authorization."
            ),
            endpoint=mf.endpoint,
            metadata={"technique": "rag:cross-tenant-leak"},
        )]
    return []


def analyze_secrets_at_rest(mf: RagManifest) -> list[Finding]:
    """Scan indexed chunk text for secrets stored in the vector DB."""
    out: list[Finding] = []
    for chunk in mf.samples:
        if _has_secret(chunk.text):
            out.append(Finding(
                title=f"Secret detected in indexed chunk '{chunk.chunk_id}'",
                severity=Severity.HIGH,
                category="rag_secret_at_rest",
                owasp_category="LLM02",
                cwe_id="CWE-200",
                description=(
                    f"Chunk '{chunk.chunk_id}' in index '{chunk.index}' contains what "
                    "appears to be a secret (API key, token, password, or credential). "
                    "Embedding a secret embeds it permanently; any user with query access "
                    "can retrieve it via semantic similarity or keyword search."
                ),
                remediation=(
                    "Scrub secrets from source documents before ingestion. Run a "
                    "pre-ingestion secret scanner (e.g. gitleaks, trufflehog) in the "
                    "RAG pipeline and reject documents that contain credentials."
                ),
                endpoint=mf.endpoint,
                parameter=chunk.chunk_id,
                metadata={"technique": "rag:secret-at-rest", "index": chunk.index},
            ))
    return out


def analyze_invertibility_risk(mf: RagManifest) -> list[Finding]:
    """Flag raw embedding export when paired with a known encoder (vec2text risk)."""
    if mf.raw_embedding_export is not True:
        return []
    severity = Severity.HIGH if mf.auth_required is False else Severity.MEDIUM
    encoder_note = (
        f" The encoder hint '{mf.encoder_hint}' makes the embedding space known, "
        "enabling model-specific vec2text inversion attacks."
        if mf.encoder_hint
        else ""
    )
    return [Finding(
        title="Raw embedding export enables vec2text-style text inversion",
        severity=severity,
        category="rag_embedding_inversion_risk",
        owasp_category="LLM08",
        cwe_id="CWE-200",
        description=(
            "The vector DB exposes raw float embeddings via its API. An attacker who "
            "can retrieve embeddings can reconstruct the original text using "
            "vec2text-style inversion techniques (Morris et al., 2023)."
            + encoder_note
        ),
        remediation=(
            "Disable raw embedding export unless strictly required. If export is "
            "needed, apply differential privacy noise or return only approximate "
            "nearest-neighbor distances rather than raw vectors."
        ),
        endpoint=mf.endpoint,
        references=["https://arxiv.org/abs/2310.06816"],
        metadata={"technique": "rag:embedding-inversion-risk", "encoder_hint": mf.encoder_hint},
    )]


def baseline_hash(mf: RagManifest) -> str:
    """Stable sha256 of sorted index metadata, for drift detection."""
    items = sorted(
        json.dumps([i.name, i.dimensions], sort_keys=True)
        for i in mf.indexes
    )
    return hashlib.sha256(json.dumps(items).encode("utf-8")).hexdigest()


def run_all_static(mf: RagManifest) -> list[Finding]:
    """Aggregate all four static analyzers."""
    out: list[Finding] = []
    for fn in (
        analyze_exposure,
        analyze_tenancy,
        analyze_secrets_at_rest,
        analyze_invertibility_risk,
    ):
        out.extend(fn(mf))
    return out

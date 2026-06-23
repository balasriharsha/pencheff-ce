# pencheff/modules/voice_scan/transport_probes.py
"""Static transport/posture probes for a voice endpoint. Best-effort: live HTTP
is injected via http_get/http_post; when None the probes are no-ops (unit-test
mode), mirroring mcp_scan.transport_probes. Never raises."""
from __future__ import annotations

import logging

from pencheff.config import Severity
from pencheff.core.findings import Finding

log = logging.getLogger("pencheff.modules.voice_scan.transport_probes")


async def run_transport_probes(cfg: dict, http_get=None, http_post=None, oast=None) -> list[Finding]:
    if http_get is None:
        return []
    url = cfg.get("url") or ""
    out: list[Finding] = []
    # 1. Unauthenticated exposure
    try:
        resp = await http_get(url)
        if resp is not None and 200 <= int(getattr(resp, "status_code", 0)) < 300:
            out.append(Finding(
                title="Voice endpoint reachable without authentication",
                severity=Severity.HIGH,
                category="voice_exposed_endpoint",
                owasp_category="LLM01",
                cwe_id="CWE-306",
                description=(
                    f"The voice endpoint {url!r} responded to an unauthenticated "
                    "request. Anyone can submit audio for transcription / bot "
                    "actions / auth without a credential."
                ),
                remediation="Require authentication (API key / OAuth / mTLS) and rate-limit.",
                endpoint=url,
                metadata={"technique": "voice:exposed-endpoint"},
            ))
    except Exception as e:  # noqa: BLE001
        log.warning("voice exposure probe failed: %s", e)
    # 2. Audio-URL SSRF (only when an OAST canary is available)
    if oast is not None and http_post is not None:
        try:
            canary = oast.new_url() if hasattr(oast, "new_url") else None
            if canary:
                await http_post(url, json={"audio_url": canary})
                hit = oast.poll() if hasattr(oast, "poll") else None
                if hit:
                    out.append(Finding(
                        title="Voice endpoint fetches attacker-supplied audio URL (SSRF)",
                        severity=Severity.HIGH, category="voice_ssrf",
                        owasp_category="LLM01", cwe_id="CWE-918",
                        description=f"The endpoint fetched an attacker-controlled audio URL ({canary}).",
                        remediation="Disallow remote audio URLs or restrict to an allowlist; block internal ranges.",
                        endpoint=url, metadata={"technique": "voice:ssrf"},
                    ))
        except Exception as e:  # noqa: BLE001
            log.warning("voice ssrf probe failed: %s", e)
    # 3. Oversized/malformed audio handling
    if http_post is not None:
        try:
            resp = await http_post(url, content=b"\x00" * (5 * 1024 * 1024))
            if resp is not None and int(getattr(resp, "status_code", 0)) >= 500:
                out.append(Finding(
                    title="Voice endpoint mishandles oversized/malformed audio",
                    severity=Severity.MEDIUM, category="voice_resource_abuse",
                    owasp_category="LLM01", cwe_id="CWE-400",
                    description="A 5 MB junk payload caused a server error — missing size/format validation.",
                    remediation="Enforce max audio size, validate format before processing, add timeouts/quotas.",
                    endpoint=url, metadata={"technique": "voice:resource-abuse"},
                ))
        except Exception as e:  # noqa: BLE001
            log.warning("voice resource probe failed: %s", e)
    return out

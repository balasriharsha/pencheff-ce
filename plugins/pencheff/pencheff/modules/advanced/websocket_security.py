"""WebSocket security testing module."""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.payload_loader import load_payloads
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Injection payloads for WebSocket messages
WS_INJECTION_PAYLOADS = [
    '<script>alert(1)</script>',
    "' OR 1=1--",
    '{"__proto__":{"admin":true}}',
    '; ls -la',
    '{{7*7}}',
]


class WebSocketSecurityModule(BaseTestModule):
    """Test WebSocket security: CSWSH, auth bypass, message injection, transport security."""

    name = "websocket_security"
    category = "websocket"
    owasp_categories = ["A07", "A03"]
    description = "WebSocket hijacking, auth bypass, message injection, insecure transport"

    def get_techniques(self) -> list[str]:
        return [
            "cswsh_detection",
            "auth_bypass",
            "message_injection",
            "insecure_transport",
            "websocket_discovery",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Discover WebSocket endpoints
        ws_urls = targets or [ep["url"] for ep in session.discovered.websocket_endpoints]
        if not ws_urls:
            ws_urls = await self._discover_websockets(http, session)

        for url in ws_urls[:10]:
            # Test CSWSH (Cross-Site WebSocket Hijacking)
            cswsh = await self._test_cswsh(http, url, session)
            findings.extend(cswsh)

            # Test auth bypass
            auth = await self._test_auth_bypass(http, url, session)
            findings.extend(auth)

            # Test insecure transport
            if url.startswith("ws://"):
                findings.append(Finding(
                    title=f"Insecure WebSocket Transport: {url}",
                    severity=Severity.MEDIUM,
                    category="websocket",
                    owasp_category="A02",
                    description=(
                        f"WebSocket endpoint uses unencrypted ws:// protocol instead of wss://. "
                        f"Data transmitted over this connection can be intercepted by MITM attackers."
                    ),
                    remediation="Use wss:// (WebSocket Secure) for all WebSocket connections.",
                    endpoint=url,
                    cwe_id="CWE-319",
                    cvss_score=5.9,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                ))

            # Test message injection
            injection = await self._test_message_injection(http, url, session)
            findings.extend(injection)

        return findings

    async def _discover_websockets(
        self, http: PencheffHTTPClient, session: PentestSession,
    ) -> list[str]:
        """Discover WebSocket endpoints by checking Upgrade responses and scanning JS."""
        ws_urls: list[str] = []
        base_url = session.target.base_url
        parsed = urlparse(base_url)

        # Check common WebSocket paths
        ws_paths = ["/ws", "/websocket", "/socket", "/ws/", "/socket.io/", "/hub", "/signalr"]
        for path in ws_paths:
            url = f"{base_url}{path}"
            try:
                resp = await http.get(
                    url,
                    headers={"Upgrade": "websocket", "Connection": "Upgrade",
                             "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                             "Sec-WebSocket-Version": "13"},
                    module="websocket_security",
                )
                # RFC 6455 §4.2.2: a real upgrade reply is HTTP/1.1 101 with
                # Connection: Upgrade, Upgrade: websocket, and a Sec-WebSocket-
                # Accept header. The previous check accepted *either* 101
                # *or* "upgrade" appearing anywhere in the Connection header,
                # which a CDN echoing "keep-alive, upgrade" could spoof.
                conn_hdr = resp.headers.get("connection", "").lower()
                upgrade_hdr = resp.headers.get("upgrade", "").lower()
                accept_hdr = resp.headers.get("sec-websocket-accept", "")
                is_real_upgrade = (
                    resp.status_code == 101
                    and "upgrade" in conn_hdr
                    and "websocket" in upgrade_hdr
                    and bool(accept_hdr)
                )
                if is_real_upgrade:
                    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
                    ws_url = f"{ws_scheme}://{parsed.netloc}{path}"
                    ws_urls.append(ws_url)
                    session.discovered.websocket_endpoints.append({
                        "url": ws_url, "path": path, "discovered_via": "upgrade_probe",
                    })
            except Exception:
                continue

        # Scan JavaScript files for ws:// / wss:// URLs
        for ep in session.discovered.endpoints[:20]:
            url = ep.get("url", "")
            if url.endswith(".js"):
                try:
                    resp = await http.get(url, module="websocket_security")
                    import re
                    ws_matches = re.findall(r'wss?://[^\s\'"<>]+', resp.text)
                    for match in ws_matches:
                        if match not in ws_urls:
                            ws_urls.append(match)
                            session.discovered.websocket_endpoints.append({
                                "url": match, "discovered_via": "javascript_scan",
                            })
                except Exception:
                    continue

        return ws_urls

    async def _test_cswsh(
        self, http: PencheffHTTPClient, url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test for Cross-Site WebSocket Hijacking — connect with attacker Origin."""
        findings: list[Finding] = []

        try:
            ws = await http.websocket_connect(
                url,
                headers={"Origin": "https://attacker.example.com"},
                module="websocket_security",
            )
            # If connection succeeds with attacker origin, CSWSH is possible
            await ws.close()
            findings.append(Finding(
                title=f"Cross-Site WebSocket Hijacking (CSWSH): {url}",
                severity=Severity.HIGH,
                category="websocket",
                owasp_category="A07",
                description=(
                    f"The WebSocket endpoint accepts connections from arbitrary Origins "
                    f"(tested: 'https://attacker.example.com'). An attacker can hijack "
                    f"the WebSocket connection via a malicious webpage, stealing data "
                    f"or performing actions as the victim."
                ),
                remediation=(
                    "Validate the Origin header on WebSocket upgrade requests. "
                    "Only accept connections from trusted origins. "
                    "Implement CSRF tokens for WebSocket authentication."
                ),
                endpoint=url,
                evidence=[Evidence(
                    request_method="WS_CONNECT",
                    request_url=url,
                    request_headers={"Origin": "https://attacker.example.com"},
                    description="WebSocket connection accepted from attacker origin",
                )],
                cwe_id="CWE-346",
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            ))
        except Exception:
            pass

        return findings

    async def _test_auth_bypass(
        self, http: PencheffHTTPClient, url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test if WebSocket accepts connections without authentication."""
        findings: list[Finding] = []

        try:
            # Connect without any credentials
            ws = await http.websocket_connect(
                url, headers={}, module="websocket_security",
            )
            # Try sending a message
            await ws.send('{"type":"ping"}')
            try:
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                findings.append(Finding(
                    title=f"WebSocket Auth Bypass: {url}",
                    severity=Severity.HIGH,
                    category="websocket",
                    owasp_category="A07",
                    description=(
                        f"The WebSocket endpoint accepts unauthenticated connections and "
                        f"processes messages. An attacker can interact with the WebSocket "
                        f"without valid credentials."
                    ),
                    remediation="Require authentication tokens for WebSocket connections. Validate credentials on each message.",
                    endpoint=url,
                    evidence=[Evidence(
                        request_method="WS_CONNECT",
                        request_url=url,
                        response_body_snippet=str(response)[:300],
                        description="WebSocket accepted unauthenticated connection and responded to message",
                    )],
                    cwe_id="CWE-306",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                ))
            except asyncio.TimeoutError:
                pass
            await ws.close()
        except Exception:
            pass

        return findings

    async def _test_message_injection(
        self, http: PencheffHTTPClient, url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test for injection vulnerabilities through WebSocket messages."""
        findings: list[Finding] = []
        payloads = load_payloads("websocket.txt") or WS_INJECTION_PAYLOADS

        try:
            ws = await http.websocket_connect(url, module="websocket_security")
        except Exception:
            return findings

        try:
            for payload in payloads[:10]:
                try:
                    await ws.send(payload)
                    response = await asyncio.wait_for(ws.recv(), timeout=3)
                    resp_lower = str(response).lower()

                    # Check for injection indicators
                    if any(indicator in resp_lower for indicator in [
                        "error", "syntax", "exception", "traceback",
                        "sql", "command", "undefined", "nan",
                    ]):
                        findings.append(Finding(
                            title=f"WebSocket Message Injection: {url}",
                            severity=Severity.MEDIUM,
                            category="websocket",
                            owasp_category="A03",
                            description=(
                                f"Injection payload via WebSocket message caused an error response, "
                                f"suggesting input is not properly sanitized. Payload: '{payload[:50]}'"
                            ),
                            remediation="Validate and sanitize all WebSocket message content. Apply the same input validation as HTTP endpoints.",
                            endpoint=url,
                            evidence=[Evidence(
                                request_method="WS_SEND",
                                request_url=url,
                                request_body=payload,
                                response_body_snippet=str(response)[:300],
                                description=f"Injection payload triggered error",
                            )],
                            cwe_id="CWE-74",
                            cvss_score=6.5,
                        ))
                        break
                except asyncio.TimeoutError:
                    continue
        finally:
            await ws.close()

        return findings

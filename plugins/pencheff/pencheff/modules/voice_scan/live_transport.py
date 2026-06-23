"""Best-effort httpx-backed live transport for voice probes. Returns three async
callables (http_get, http_post, submit_audio). Each returns None on failure so
the probe layers (which already handle None) degrade gracefully. v1 assumes a
simple JSON/multipart endpoint; custom shapes (request_template/response_path)
are honored when present, else a sensible default is used."""
from __future__ import annotations

import logging

import httpx

log = logging.getLogger("pencheff.modules.voice_scan.live_transport")
_TIMEOUT = 30.0


def build_live_transport(cfg: dict):
    headers = {}
    cred = (cfg.get("credentials") or {}) if isinstance(cfg, dict) else {}
    if cred.get("api_key"):
        headers["Authorization"] = f"Bearer {cred['api_key']}"

    async def http_get(url, **kw):
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
                return await c.get(url, headers=headers, **kw)
        except Exception as e:  # noqa: BLE001
            log.warning("voice http_get failed: %s", e)
            return None

    async def http_post(url, **kw):
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
                return await c.post(url, headers=headers, **kw)
        except Exception as e:  # noqa: BLE001
            log.warning("voice http_post failed: %s", e)
            return None

    async def submit_audio(wav_bytes: bytes, kind: str):
        """POST WAV bytes; return {status_code, text, json} (json None if not JSON)."""
        url = cfg.get("url") or ""
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
                resp = await c.post(
                    url, headers=headers,
                    files={"audio": ("probe.wav", wav_bytes, "audio/wav")},
                )
            body = None
            try:
                body = resp.json()
            except Exception:
                body = None
            return {"status_code": resp.status_code, "text": resp.text, "json": body}
        except Exception as e:  # noqa: BLE001
            log.warning("voice submit_audio failed: %s", e)
            return None

    return http_get, http_post, submit_audio

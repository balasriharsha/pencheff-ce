# pencheff/modules/voice_scan/verdict.py
"""Pure verdict helpers for voice probes — given an endpoint's response, decide
whether an attack succeeded. No I/O; fully unit-testable."""
from __future__ import annotations

import re
from typing import Any

_WS = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WS.sub(" ", (text or "").strip().lower())


def transcription_injection_followed(response_text: str, marker: str,
                                     compliance_terms: list[str] | None = None) -> bool:
    """True if the STT transcript / voice-bot response shows it FOLLOWED an
    injected instruction: it echoes the canary marker, or contains an explicit
    compliance phrase."""
    norm = _normalize(response_text)
    if marker and _normalize(marker) in norm:
        return True
    for term in (compliance_terms or []):
        if _normalize(term) in norm:
            return True
    return False


def ultrasonic_command_recognized(transcript: str, hidden_command: str) -> bool:
    """True if the transcript of an ultrasonic-carrier submission contains the
    hidden command (i.e. the inaudible command was decoded)."""
    if not hidden_command:
        return False
    return _normalize(hidden_command) in _normalize(transcript)


def auth_spoof_accepted(status_code: int, body: Any) -> bool:
    """True if a voice-auth endpoint ACCEPTED synthetic/altered speaker audio."""
    if not (200 <= int(status_code) < 300):
        return False
    if isinstance(body, dict):
        if body.get("verified") is True:
            return True
        for k in ("result", "status", "decision", "match"):
            v = str(body.get(k, "")).lower()
            if v in ("match", "accept", "accepted", "verified", "pass", "true"):
                return True
        return False
    text = _normalize(str(body))
    return any(w in text for w in ("verified", "accepted", "match"))

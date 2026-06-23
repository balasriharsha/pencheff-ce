# pencheff/modules/voice_scan/audio_synth.py
"""Pure audio synthesis for voice-AI probing. stdlib `wave` + numpy only —
no TTS/librosa/torch. All functions are deterministic and unit-tested.
These craft test signals; they do NOT transmit anything (transport is separate)."""
from __future__ import annotations

import hashlib
import io
import wave

import numpy as np

_MAX_INT16 = 32767


def _pack_wav(samples: np.ndarray, sample_rate: int) -> bytes:
    """Encode a float [-1,1] (or int16) array as a 16-bit mono PCM WAV."""
    arr = np.asarray(samples)
    if arr.dtype != np.int16:
        arr = np.clip(arr, -1.0, 1.0)
        arr = (arr * _MAX_INT16).astype("<i2")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sample_rate)
        w.writeframes(arr.tobytes())
    return buf.getvalue()


def read_wav_samples(blob: bytes) -> np.ndarray:
    """Decode a 16-bit mono PCM WAV to an int16 numpy array."""
    with wave.open(io.BytesIO(blob), "rb") as w:
        raw = w.readframes(w.getnframes())
    return np.frombuffer(raw, dtype="<i2").copy()


def synth_tone_wav(freq: float = 1000.0, duration_s: float = 0.5,
                   sample_rate: int = 16000, amplitude: float = 0.6) -> bytes:
    n = int(sample_rate * duration_s)
    t = np.arange(n) / sample_rate
    sig = amplitude * np.sin(2 * np.pi * freq * t)
    return _pack_wav(sig, sample_rate)


def _marker_seed(marker: str) -> int:
    return int.from_bytes(hashlib.sha256(marker.encode("utf-8")).digest()[:4], "big")


def synth_speechlike_wav(marker: str, duration_s: float = 1.0,
                         sample_rate: int = 16000) -> bytes:
    """A deterministic, marker-dependent multi-tone 'carrier'. v1 is NOT real
    TTS (no spoken words) — it is a reproducible signal whose content depends on
    the marker, used for cross-modal/transport probing. The cross-modal verdict
    keys off the ENDPOINT RESPONSE, not on STT recovering this marker."""
    rng = np.random.default_rng(_marker_seed(marker))
    n = int(sample_rate * duration_s)
    t = np.arange(n) / sample_rate
    sig = np.zeros(n)
    # 3 formant-like tones seeded by the marker → deterministic but content-varying
    for f0 in rng.uniform(200, 3000, size=3):
        sig += 0.3 * np.sin(2 * np.pi * f0 * t)
    sig /= np.max(np.abs(sig)) or 1.0
    return _pack_wav(0.7 * sig, sample_rate)


def synth_ultrasonic_command_wav(payload: str, carrier_hz: float = 21000.0,
                                 duration_s: float = 1.0, sample_rate: int = 48000) -> bytes:
    """DolphinAttack-style: amplitude-modulate a baseband envelope (seeded by the
    payload) onto an ultrasonic carrier above human hearing. The energy sits at
    carrier_hz ± baseband (verified spectrally in tests)."""
    rng = np.random.default_rng(_marker_seed(payload))
    n = int(sample_rate * duration_s)
    t = np.arange(n) / sample_rate
    baseband = 0.5 * (1.0 + np.sin(2 * np.pi * rng.uniform(100, 400) * t))  # [0,1] env
    carrier = np.sin(2 * np.pi * carrier_hz * t)
    sig = baseband * carrier
    sig /= np.max(np.abs(sig)) or 1.0
    return _pack_wav(0.8 * sig, sample_rate)


def synth_perturbed_wav(base_wav: bytes, eps: float = 0.02) -> bytes:
    """Add a small, deterministic bounded perturbation (adversarial-lite). eps is
    a fraction of full-scale. Reads the base WAV's sample rate to round-trip."""
    with wave.open(io.BytesIO(base_wav), "rb") as w:
        sr = w.getframerate()
    samples = read_wav_samples(base_wav).astype(np.int64)
    rng = np.random.default_rng(1234)
    delta = (rng.uniform(-1.0, 1.0, size=len(samples)) * eps * _MAX_INT16).astype(np.int64)
    out = np.clip(samples + delta, -_MAX_INT16, _MAX_INT16).astype("<i2")
    return _pack_wav(out, sr)

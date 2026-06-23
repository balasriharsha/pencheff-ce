import asyncio
from pencheff.modules.voice_scan.dynamic_probes import run_dynamic_probes


def test_no_submit_fn_is_noop():
    cfg = {"kind": "voice", "source_type": "voice_bot", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=None))
    assert findings == []


def test_cross_modal_injection_flagged_when_response_follows():
    async def submit_audio(wav_bytes, kind):
        # endpoint echoes the injected marker → it followed the instruction
        return {"status_code": 200, "text": "ok INJECT-CANARY done"}
    cfg = {"kind": "voice", "source_type": "voice_bot", "url": "https://h/x",
           "audio_probes": True, "injection_phrase": "INJECT-CANARY"}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert any(f.metadata.get("technique") == "voice:transcription-injection" for f in findings)


def test_auth_spoof_flagged_when_accepted():
    async def submit_audio(wav_bytes, kind):
        return {"status_code": 200, "json": {"verified": True}}
    cfg = {"kind": "voice", "source_type": "voice_auth", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert any(f.metadata.get("technique") == "voice:auth-spoof" for f in findings)

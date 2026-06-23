from pencheff.modules.voice_scan.live_transport import build_live_transport


def test_builder_returns_three_callables():
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    http_get, http_post, submit_audio = build_live_transport(cfg)
    assert callable(http_get) and callable(http_post) and callable(submit_audio)

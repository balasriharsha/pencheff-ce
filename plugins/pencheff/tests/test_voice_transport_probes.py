import asyncio
from pencheff.modules.voice_scan.transport_probes import run_transport_probes


class _Resp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
    def json(self): return {}


def test_no_http_get_is_noop():
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    findings = asyncio.run(run_transport_probes(cfg, http_get=None, oast=None))
    assert findings == []


def test_unauthenticated_endpoint_flagged():
    async def http_get(url, **kw): return _Resp(status_code=200, text="ok")
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    findings = asyncio.run(run_transport_probes(cfg, http_get=http_get, oast=None))
    assert any(f.metadata.get("technique") == "voice:exposed-endpoint" for f in findings)


def test_auth_required_endpoint_not_flagged_as_exposed():
    async def http_get(url, **kw): return _Resp(status_code=401, text="unauthorized")
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    findings = asyncio.run(run_transport_probes(cfg, http_get=http_get, oast=None))
    assert not any(f.metadata.get("technique") == "voice:exposed-endpoint" for f in findings)

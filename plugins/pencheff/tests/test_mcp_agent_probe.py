from pencheff.modules.mcp_scan.manifest import McpTool
from pencheff.modules.mcp_scan import agent_probe as ap


def test_lethal_trifecta_present_when_all_three_buckets():
    # untrusted-input + private-data access + exfiltration/egress
    tools = [
        McpTool(name="fetch_url", description="fetch a web page (untrusted content)"),
        McpTool(name="read_private_repo", description="read private repository files"),
        McpTool(name="send_email", description="send an email to an external address"),
    ]
    assert ap.lethal_trifecta_present(tools) is True


def test_lethal_trifecta_absent_when_missing_a_bucket():
    tools = [
        McpTool(name="read_private_repo", description="read private repository files"),
        McpTool(name="send_email", description="send an email externally"),
    ]  # no untrusted-input source
    assert ap.lethal_trifecta_present(tools) is False


def test_build_agent_probe_config_http():
    cfg = {"kind": "mcp", "source_type": "agent_http", "provider": "openai-chat",
           "model": "gpt-4", "url": "http://agent.example/chat"}
    out = ap.build_agent_probe_config(cfg, base_url="http://agent.example/chat")
    assert out["provider"] == "openai-chat"
    # The mcp attack pack must be selected
    assert out.get("redteam", {}).get("plugins") == ["mcp"]


def test_build_agent_probe_config_browser():
    cfg = {"kind": "mcp", "source_type": "agent_browser", "url": "http://a/",
           "prompt_selector": "#in", "send_selector": "#go", "response_selector": "#out"}
    out = ap.build_agent_probe_config(cfg, base_url="http://a/")
    assert out["provider"] == "browser"
    assert out.get("redteam", {}).get("plugins") == ["mcp"]


import asyncio


def test_run_agent_probe_invokes_llm_pack(monkeypatch):
    from pencheff.modules.mcp_scan import agent_probe as ap

    calls = {}

    class _FakeFinding:
        owasp_category = "LLM06"; title = "probe finding"; metadata = {}

    class _FakeModule:
        async def run(self, session, http=None, config=None):
            calls["ran"] = True
            calls["llm_config"] = getattr(session, "llm_config", None)
            return [_FakeFinding()]

    import pencheff.modules.llm_red_team as lrt
    monkeypatch.setitem(lrt.LLM_RED_TEAM_MODULES, "LLM06", _FakeModule)

    class _Sess:
        llm_config = None
        target = type("T", (), {"base_url": "http://agent.example/chat"})()

    cfg = {"kind": "mcp", "source_type": "agent_http", "provider": "openai-chat",
           "model": "gpt-4", "url": "http://agent.example/chat"}
    findings = asyncio.run(ap.run_agent_probe(_Sess(), cfg))
    assert calls.get("ran") is True
    assert calls.get("llm_config") is not None
    assert any(f.owasp_category == "LLM06" for f in findings)

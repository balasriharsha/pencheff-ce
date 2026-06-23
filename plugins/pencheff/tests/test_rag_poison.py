import asyncio

import httpx

from pencheff.modules.rag_scan import poison as po
from pencheff.modules.rag_scan.connectors import GenericRestConnector


def test_poison_doc_contains_anchor_and_marker():
    d = po.poison_doc("What is the refund policy?", "PWNED-MARKER-1")
    text = (d.get("text") or d.get("content") or str(d))
    assert "PWNED-MARKER-1" in text
    # retrieval anchor: references the canary question terms
    assert "refund" in text.lower()


def test_confirms_control_true_when_marker_in_answer():
    assert po.confirms_control("The refund policy is PWNED-MARKER-1", "PWNED-MARKER-1") is True
    assert po.confirms_control("The refund policy is 30 days", "PWNED-MARKER-1") is False


# ---------------------------------------------------------------------------
# MockTransport tests for upsert / delete
# ---------------------------------------------------------------------------

def test_connector_upsert_returns_doc_id():
    """upsert() POSTs to /upsert and extracts id from the response."""
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path == "/upsert":
            return httpx.Response(200, json={"id": "doc-42"})
        return httpx.Response(404)

    conn = GenericRestConnector(transport=httpx.MockTransport(handler))
    conn._cfg_url = "http://q:6333"
    conn._cfg_headers = {}
    doc_id = asyncio.run(conn.upsert({"text": "poisoned content", "marker": "X"}))
    assert doc_id == "doc-42"


def test_connector_delete_non_fatal_on_error():
    """delete() swallows transport errors without raising."""
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    conn = GenericRestConnector(transport=httpx.MockTransport(handler))
    conn._cfg_url = "http://q:6333"
    conn._cfg_headers = {}
    # must not raise
    asyncio.run(conn.delete("doc-42"))

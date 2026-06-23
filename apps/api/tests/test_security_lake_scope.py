# tests/test_security_lake_scope.py
from __future__ import annotations

from pencheff_api.auth.scopes import VALID_SCOPES, scope_matches


def test_security_lake_scope_registered():
    assert "security_lake:read" in VALID_SCOPES


def test_security_lake_scope_matches_wildcard():
    assert scope_matches("security_lake:read", ["security_lake:read"]) is True
    assert scope_matches("security_lake:read", ["*:read"]) is True
    assert scope_matches("security_lake:read", ["findings:read"]) is False

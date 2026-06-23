"""Unit tests for the PENCHEFF_API_KEY layer."""

from __future__ import annotations

import pytest

from pencheff_api.auth.api_key import (
    KEY_PREFIX_SENTINEL,
    PREFIX_LEN,
    generate_key,
    hash_key,
    looks_like_api_key,
)
from pencheff_api.auth.scopes import (
    SESSION_ONLY_CATEGORIES,
    VALID_SCOPES,
    expand_wildcards,
    scope_matches,
    validate_scopes,
)


# ─── key generation ────────────────────────────────────────────────────────


def test_generated_key_has_correct_format():
    full, prefix, digest = generate_key()
    assert full.startswith(KEY_PREFIX_SENTINEL)
    assert len(prefix) == PREFIX_LEN
    # SHA-256 hex digest is 64 chars
    assert len(digest) == 64
    assert hash_key(full) == digest


def test_generated_keys_are_unique():
    seen = {generate_key()[0] for _ in range(50)}
    assert len(seen) == 50


def test_looks_like_api_key():
    full, _, _ = generate_key()
    assert looks_like_api_key(full) is True
    assert looks_like_api_key("eyJalg.payload.sig") is False
    assert looks_like_api_key("") is False
    assert looks_like_api_key("pcf_test_xxxx") is False  # only pcf_live_


# ─── scope catalog & matching ──────────────────────────────────────────────


def test_session_only_categories_have_no_scopes():
    """Categories marked session-only must NOT appear in the scope catalog —
    otherwise an API key could be granted a scope that the dependency layer
    actively rejects, which would be a confusing developer experience."""
    for cat in SESSION_ONLY_CATEGORIES:
        for s in VALID_SCOPES:
            assert not s.startswith(f"{cat}:"), (
                f"session-only category {cat!r} leaked into the scope catalog as {s!r}"
            )


def test_concrete_scope_matches_itself():
    assert scope_matches("scans:write", ["scans:write"])
    assert scope_matches("scans:write", ["scans:read", "scans:write"])
    assert not scope_matches("scans:write", ["scans:read"])


def test_category_wildcard_matches():
    assert scope_matches("scans:write", ["scans:*"])
    assert scope_matches("scans:read", ["scans:*"])
    assert not scope_matches("findings:read", ["scans:*"])


def test_action_wildcard_matches():
    assert scope_matches("scans:read", ["*:read"])
    assert scope_matches("findings:read", ["*:read"])
    assert not scope_matches("scans:write", ["*:read"])


def test_full_wildcard_matches_everything_in_catalog():
    for s in VALID_SCOPES:
        assert scope_matches(s, ["*:*"]), f"{s} not satisfied by *:*"


def test_unknown_required_scope_never_matches():
    """Defensive check: a typo in a require_scope() call must fail closed,
    not silently let every key through."""
    assert not scope_matches("typos:read", ["*:*"])
    assert not scope_matches("billing:write", ["*:*"])  # session-only category


def test_validate_scopes_normalises_and_dedupes():
    out = validate_scopes(["SCANS:READ", "scans:read", "findings:write"])
    assert out == ["findings:write", "scans:read"]


def test_validate_scopes_rejects_unknown():
    with pytest.raises(ValueError, match="unknown scope"):
        validate_scopes(["nonsense:read"])
    with pytest.raises(ValueError, match="missing"):
        validate_scopes(["no_colon"])


def test_validate_scopes_accepts_wildcards():
    assert validate_scopes(["scans:*"]) == ["scans:*"]
    assert validate_scopes(["*:read"]) == ["*:read"]
    assert validate_scopes(["*:*"]) == ["*:*"]


def test_expand_wildcards():
    expanded = expand_wildcards(["scans:*"])
    assert "scans:read" in expanded
    assert "scans:write" in expanded
    assert "findings:read" not in expanded

    full = expand_wildcards(["*:*"])
    assert set(full) == set(VALID_SCOPES)

"""Scope catalog for PENCHEFF_API_KEY.

Scopes are ``category:action`` strings. ``category`` mirrors the FastAPI
router family it gates; ``action`` is one of ``read``, ``write``, or
``export`` (reports-only). Wildcards are supported when granting:

- ``scans:*``       — both read and write on scans
- ``*:read``        — read everything that exposes a read scope
- ``*:*``           — every scope in the catalog (admin-equivalent)

Endpoints declare the *concrete* scope they need (e.g. ``scans:write``);
the matcher in :func:`scope_matches` expands wildcards on the granted
side.

Categories that are deliberately session-only (no API key access) are
listed in :data:`SESSION_ONLY_CATEGORIES` and have no scopes here. Those
endpoints attach the :func:`session_only` dependency and reject any
key-authenticated request.
"""

from __future__ import annotations

# Every scope listed here is wired into at least one HTTP endpoint via
# ``require_scope``. The default-deny dependency layer rejects API-keyed
# requests on any endpoint without an explicit scope declaration, so
# there is no point advertising a scope the request would not satisfy.
#
# Each tuple is (scope, human-readable description). Keep sorted by category.
SCOPE_CATALOG: list[tuple[str, str]] = [
    ("assets:read",          "List assets in the inventory"),
    ("assets:write",         "Trigger ASM discovery, modify or delete assets"),
    ("comments:read",        "Read finding comments"),
    ("comments:write",       "Create or edit finding comments, assign findings, manage tags"),
    ("dashboard:read",       "Read dashboard metrics: heatmap, trend, KEV exposure, fix conversion"),
    ("dependencies:read",    "Read SCA dependency data"),
    ("engagements:read",     "Read engagement metadata and unified findings"),
    ("engagements:write",    "Create, close, or rotate engagement pairing codes"),
    ("findings:read",        "List and read findings"),
    ("findings:write",       "Triage, recheck, suppress, reopen, change status"),
    ("fix_proposals:read",   "Read fix proposal status, diffs, and usage stats"),
    ("fix_proposals:write",  "Generate, apply, revert auto-fix proposals; bulk-fix"),
    ("integrations:read",    "Read integration configuration"),
    ("integrations:write",   "Create, modify, delete, or test integrations"),
    ("intruder:read",        "Read intruder payload sets, attacks, and results"),
    ("intruder:write",       "Create payload sets and run intruder attacks"),
    ("notes:read",           "Read engagement notes"),
    ("notes:write",          "Create, modify, or delete engagement notes"),
    ("proxy:read",           "Read proxy session state and per-scan history"),
    ("proxy:write",          "Start or stop proxy sessions"),
    ("repeater:read",        "Read repeater tabs and saved responses"),
    ("repeater:write",       "Create, modify, or send repeater requests"),
    ("repos:read",           "Read repositories, repo scans, repo findings, repo SBOMs"),
    ("repos:write",          "Connect repos, trigger repo scans, generate SBOMs, manage repo integrations"),
    ("reports:export",       "Generate reports (PDF, DOCX, HTML)"),
    ("reports:read",         "Read existing reports and download files"),
    ("scans:read",           "List and read scans, get progress, view findings"),
    ("scans:write",          "Initiate, configure, cancel, or rerun scans"),
    ("schedules:read",       "Read scheduled scans"),
    ("schedules:write",      "Create, modify, or delete scheduled scans"),
    ("sboms:read",           "Read SBOMs"),
    ("security_lake:read",   "Read the Security Lake: findings, trends, correlations"),
    ("targets:read",         "Read targets"),
    ("targets:write",        "Create, modify, or delete targets"),
    ("traffic:read",         "Read recorded HTTP traffic"),
    ("traffic:write",        "Tag or modify traffic rows"),
    ("unified_findings:read", "Read the unified-finding queue"),
]

# Set of valid concrete scopes (no wildcards) — used to validate creates.
VALID_SCOPES: frozenset[str] = frozenset(s for s, _ in SCOPE_CATALOG)

# Categories no API key may ever reach. The corresponding routers attach
# the ``session_only`` dependency. These are user-identity-bound concerns
# (billing, the keys themselves, org/seat management, branding) where a
# stolen key must NOT unlock further escalation.
SESSION_ONLY_CATEGORIES: frozenset[str] = frozenset({
    "api_keys",     # creating / revoking keys
    "auth",         # session, signup, onboarding
    "billing",      # Stripe checkout, subscription updates
    "branding",     # workspace branding
    "orgs",         # org settings, invites, member roles
    "workspaces",   # workspace create/rename
})


def scope_matches(required: str, granted: list[str]) -> bool:
    """Return True if ``required`` is satisfied by the ``granted`` list.

    ``granted`` may contain wildcards (``scans:*``, ``*:read``, ``*:*``);
    ``required`` is always a concrete scope.
    """
    if required not in VALID_SCOPES:
        # Defensive: an unknown required scope must never match. If a caller
        # has written ``require_scope("typos:read")`` it should fail closed.
        return False
    cat, action = required.split(":", 1)
    for g in granted:
        if g == required or g == "*:*":
            return True
        if ":" not in g:
            continue
        gc, ga = g.split(":", 1)
        if (gc == cat or gc == "*") and (ga == action or ga == "*"):
            return True
    return False


def expand_wildcards(scopes: list[str]) -> list[str]:
    """Expand granted wildcards into the concrete scopes they cover.

    Used to display effective permissions in the dashboard.
    """
    out: set[str] = set()
    for g in scopes:
        if g == "*:*":
            out.update(VALID_SCOPES)
            continue
        if ":" not in g:
            continue
        gc, ga = g.split(":", 1)
        for s in VALID_SCOPES:
            sc, sa = s.split(":", 1)
            if (gc == sc or gc == "*") and (ga == sa or ga == "*"):
                out.add(s)
    return sorted(out)


def validate_scopes(scopes: list[str]) -> list[str]:
    """Normalise + validate a list of grant strings.

    Accepts wildcards (``cat:*``, ``*:action``, ``*:*``) and concrete scopes.
    Returns the de-duplicated, sorted list. Raises ``ValueError`` on any
    unknown scope so callers can surface a 400.
    """
    out: set[str] = set()
    for s in scopes:
        s = s.strip().lower()
        if not s or s == "*:*":
            if s == "*:*":
                out.add(s)
            continue
        if ":" not in s:
            raise ValueError(f"invalid scope (missing ':'): {s!r}")
        cat, action = s.split(":", 1)
        if cat == "*" or action == "*":
            # Wildcard — must reference at least one real category/action.
            valid_cats = {c.split(":", 1)[0] for c in VALID_SCOPES}
            valid_actions = {c.split(":", 1)[1] for c in VALID_SCOPES}
            if cat != "*" and cat not in valid_cats:
                raise ValueError(f"unknown scope category: {cat!r}")
            if action != "*" and action not in valid_actions:
                raise ValueError(f"unknown scope action: {action!r}")
            out.add(s)
            continue
        if s not in VALID_SCOPES:
            raise ValueError(f"unknown scope: {s!r}")
        out.add(s)
    return sorted(out)

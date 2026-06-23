"""Read-only cloud posture scanners for Infrastructure & Cloud targets.

These checks operate on provider/resource metadata supplied in
``Target.kind_config.inventory``. They never require, request, or persist cloud
secret values; all evidence is redacted before returning findings.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

CLOUD_KINDS = frozenset({
    "cloud_account",
    "serverless_function",
    "cloud_storage",
    "load_balancer_cdn",
    "cloud_database",
    "secrets_manager",
})

AGENT_ROLES: dict[str, str] = {
    "CloudInventoryAgent": "Normalizes read-only provider metadata",
    "CloudIamExposureAgent": "Finds overbroad IAM and entitlement risks",
    "CloudStorageAgent": "Checks storage public access, encryption, and logging",
    "ServerlessSecurityAgent": "Checks function exposure, runtimes, and env metadata",
    "EdgeCdnSecurityAgent": "Checks load balancer and CDN TLS, WAF, and cache posture",
    "CloudDatabaseAgent": "Checks database public access, encryption, backups, and deletion protection",
    "SecretsHygieneAgent": "Checks secret metadata without reading secret values",
    "CloudAuditLoggingAgent": "Checks account-level audit logging coverage",
}

_SECRETISH_KEYS = {
    "value",
    "secret",
    "secret_value",
    "secretstring",
    "secret_string",
    "password",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "private_key",
    "plaintext",
}


def run_cloud_checks(
    *,
    kind: str,
    cfg: dict[str, Any],
    kind_credentials: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Run deterministic read-only checks for one cloud target kind.

    Args:
        kind: Target.kind wire value.
        cfg: Target.kind_config payload.
        kind_credentials: Decrypted provider credentials metadata. Presence is
            recorded in stats only; credential values are never emitted.
    """
    if kind not in CLOUD_KINDS:
        raise ValueError(f"unsupported cloud kind: {kind!r}")

    provider = str(cfg.get("provider") or "unknown")
    inventory = cfg.get("inventory") if isinstance(cfg.get("inventory"), dict) else {}
    scope = _scope_for(cfg)

    findings: list[dict[str, Any]] = []
    stats = _empty_stats(provider, scope, bool(kind_credentials), inventory)

    if kind in {"cloud_account", "serverless_function", "cloud_storage", "cloud_database", "secrets_manager"}:
        _extend(stats, findings, "CloudIamExposureAgent", _check_iam(provider, scope, inventory))

    if kind in {"cloud_account", "cloud_storage"}:
        _extend(stats, findings, "CloudStorageAgent", _check_storage(provider, scope, cfg, inventory))

    if kind in {"cloud_account", "serverless_function"}:
        _extend(stats, findings, "ServerlessSecurityAgent", _check_serverless(provider, scope, cfg, inventory))

    if kind in {"cloud_account", "load_balancer_cdn"}:
        _extend(stats, findings, "EdgeCdnSecurityAgent", _check_edge(provider, scope, cfg, inventory))

    if kind in {"cloud_account", "cloud_database"}:
        _extend(stats, findings, "CloudDatabaseAgent", _check_databases(provider, scope, cfg, inventory))

    if kind in {"cloud_account", "secrets_manager"}:
        _extend(stats, findings, "SecretsHygieneAgent", _check_secrets(provider, scope, cfg, inventory))

    if kind == "cloud_account":
        _extend(stats, findings, "CloudAuditLoggingAgent", _check_audit_logging(provider, scope, inventory))

    return findings, stats


def _empty_stats(
    provider: str,
    scope: str,
    credential_bound: bool,
    inventory: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    stats = {
        agent: {
            "role": role,
            "provider": provider,
            "scope": scope,
            "findings_count": 0,
        }
        for agent, role in AGENT_ROLES.items()
    }
    stats["CloudInventoryAgent"].update({
        "credential_bound": credential_bound,
        "inventory_sections": sorted(inventory.keys()),
    })
    return stats


def _extend(
    stats: dict[str, dict[str, Any]],
    findings: list[dict[str, Any]],
    agent: str,
    agent_findings: list[dict[str, Any]],
) -> None:
    stats.setdefault(agent, {"findings_count": 0})
    stats[agent]["findings_count"] = stats[agent].get("findings_count", 0) + len(agent_findings)
    findings.extend(agent_findings)


def _scope_for(cfg: dict[str, Any]) -> str:
    provider = str(cfg.get("provider") or "cloud")
    scope = cfg.get("account_id") or cfg.get("subscription_id") or cfg.get("project_id")
    return f"{provider}:{scope or 'unknown'}"


def _items(inventory: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in keys:
        raw = inventory.get(key)
        if isinstance(raw, dict):
            out.append(raw)
        elif isinstance(raw, list):
            out.extend(item for item in raw if isinstance(item, dict))
    return out


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "public", "enabled"}
    return bool(value)


def _falsey(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"0", "false", "no", "n", "disabled"}
    return value is False


def _name(resource: dict[str, Any], fallback: str) -> str:
    for key in ("name", "id", "arn", "resource_id", "principal", "domain"):
        value = resource.get(key)
        if value:
            return str(value)
    return fallback


def _actions(resource: dict[str, Any]) -> set[str]:
    raw = resource.get("actions") or resource.get("allowed_actions") or resource.get("permissions")
    if isinstance(raw, str):
        return {part.strip() for part in raw.split(",") if part.strip()}
    if isinstance(raw, Iterable):
        return {str(part).strip() for part in raw if str(part).strip()}
    return set()


def _check_iam(provider: str, scope: str, inventory: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for principal in _items(inventory, "iam", "principals", "roles", "policies"):
        actions = _actions(principal)
        has_wildcard = "*" in actions or "iam:*" in actions or _truthy(principal.get("wildcard_admin"))
        has_admin = _truthy(principal.get("admin")) or _truthy(principal.get("administrator"))
        has_passrole = "iam:PassRole" in actions or "iam:passrole" in {a.lower() for a in actions}
        if not (has_wildcard or has_admin or has_passrole):
            continue
        principal_name = _name(principal, "cloud principal")
        severity = "critical" if has_wildcard or has_admin else "high"
        findings.append(_finding(
            provider=provider,
            scope=scope,
            agent="CloudIamExposureAgent",
            title=f"Overbroad cloud IAM permissions: {principal_name}",
            severity=severity,
            category="cloud_iam",
            owasp_category="CIEM-01 Excessive Entitlements",
            description=(
                "A cloud principal has wildcard, administrator, or privilege-escalation "
                "permissions in the provided inventory metadata."
            ),
            remediation=(
                "Replace wildcard/admin grants with least-privilege policies, remove "
                "unneeded iam:PassRole-style escalation paths, and bind permissions to "
                "specific resources."
            ),
            evidence={
                "principal": principal_name,
                "actions": sorted(actions),
                "admin": has_admin,
                "wildcard": has_wildcard,
                "privilege_escalation_action": has_passrole,
            },
        ))
    return findings


def _check_storage(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for bucket in _items(inventory, "storage", "buckets", "containers"):
        name = _name(bucket, "cloud storage")
        if cfg.get("check_public_access", True) and (
            _truthy(bucket.get("public")) or _truthy(bucket.get("public_access"))
        ):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudStorageAgent",
                title=f"Cloud storage is publicly accessible: {name}",
                severity="high",
                category="cloud_storage",
                owasp_category="CSPM-02 Public Storage Exposure",
                description="A cloud storage resource is marked public in metadata.",
                remediation="Disable public access unless explicitly required and enforce bucket/container policies.",
                evidence={"resource": name, "public": True},
            ))
        if cfg.get("check_encryption", True) and _falsey(bucket.get("encrypted")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudStorageAgent",
                title=f"Cloud storage encryption disabled: {name}",
                severity="medium",
                category="cloud_storage",
                owasp_category="CSPM-03 Data Encryption",
                description="A cloud storage resource is not encrypted at rest according to metadata.",
                remediation="Enable provider-managed or customer-managed encryption at rest.",
                evidence={"resource": name, "encrypted": False},
            ))
        if cfg.get("check_logging", True) and _falsey(bucket.get("logging_enabled")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudStorageAgent",
                title=f"Cloud storage access logging disabled: {name}",
                severity="low",
                category="cloud_storage",
                owasp_category="CSPM-04 Audit Logging",
                description="A cloud storage resource does not have access logging enabled.",
                remediation="Enable access logs and route them to a protected logging destination.",
                evidence={"resource": name, "logging_enabled": False},
            ))
    return findings


def _check_serverless(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    deprecated = {"nodejs10.x", "nodejs12.x", "python2.7", "python3.6", "dotnetcore2.1", "ruby2.5"}
    for function in _items(inventory, "functions", "serverless", "lambda"):
        name = _name(function, "serverless function")
        if cfg.get("check_public_invocation", True) and (
            _truthy(function.get("public_invocation")) or _truthy(function.get("anonymous_invocation"))
        ):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="ServerlessSecurityAgent",
                title=f"Serverless function allows public invocation: {name}",
                severity="high",
                category="serverless",
                owasp_category="SERVERLESS-01 Public Invocation",
                description="A serverless function can be invoked without a trusted identity boundary.",
                remediation="Require authenticated invocation and limit trigger principals to the expected callers.",
                evidence={"resource": name, "public_invocation": True},
            ))
        runtime = str(function.get("runtime") or "").strip()
        if cfg.get("check_runtime", True) and runtime.lower() in deprecated:
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="ServerlessSecurityAgent",
                title=f"Serverless function uses deprecated runtime: {name}",
                severity="medium",
                category="serverless",
                owasp_category="SERVERLESS-02 Runtime Hygiene",
                description="A serverless function uses a deprecated runtime.",
                remediation="Upgrade the function runtime to a currently supported version.",
                evidence={"resource": name, "runtime": runtime},
            ))
        env_keys = function.get("env_keys") or function.get("environment_keys") or []
        if cfg.get("include_env_metadata", True) and _contains_secret_key(env_keys):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="ServerlessSecurityAgent",
                title=f"Serverless environment contains secret-like keys: {name}",
                severity="medium",
                category="serverless",
                owasp_category="SERVERLESS-03 Secret Handling",
                description="Environment metadata includes secret-like variable names.",
                remediation="Move sensitive values into the provider secret manager and reference them at runtime.",
                evidence={"resource": name, "secret_like_env_keys": _secret_like_keys(env_keys)},
            ))
    return findings


def _check_edge(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for edge in _items(inventory, "load_balancers", "cdn", "edges", "load_balancer_cdn"):
        name = _name(edge, "edge resource")
        tls = str(edge.get("tls_min_version") or edge.get("minimum_tls_version") or "").lower()
        if cfg.get("check_tls", True) and tls in {"tls1.0", "tls1.1", "1.0", "1.1"}:
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="EdgeCdnSecurityAgent",
                title=f"Edge endpoint allows legacy TLS: {name}",
                severity="medium",
                category="edge_cdn",
                owasp_category="EDGE-01 TLS Configuration",
                description="A load balancer or CDN endpoint permits legacy TLS versions.",
                remediation="Require TLS 1.2 or newer and disable weak ciphers.",
                evidence={"resource": name, "tls_min_version": tls},
            ))
        if cfg.get("check_waf", True) and _falsey(edge.get("waf_enabled")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="EdgeCdnSecurityAgent",
                title=f"Edge endpoint has no WAF policy: {name}",
                severity="medium",
                category="edge_cdn",
                owasp_category="EDGE-02 Missing WAF",
                description="A public load balancer or CDN endpoint does not have WAF protection enabled.",
                remediation="Attach a managed WAF policy and enable logging for blocked/allowed requests.",
                evidence={"resource": name, "waf_enabled": False},
            ))
        if cfg.get("check_origin_exposure", True) and _truthy(edge.get("origin_public")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="EdgeCdnSecurityAgent",
                title=f"CDN origin appears directly reachable: {name}",
                severity="high",
                category="edge_cdn",
                owasp_category="EDGE-03 Origin Exposure",
                description="A CDN or load balancer origin is marked publicly reachable in metadata.",
                remediation="Restrict origin access to the edge service using private links, signed origin headers, or security groups.",
                evidence={"resource": name, "origin_public": True},
            ))
        if cfg.get("check_cache_policy", True) and _truthy(edge.get("caches_authorized_content")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="EdgeCdnSecurityAgent",
                title=f"CDN cache policy may store authorized content: {name}",
                severity="medium",
                category="edge_cdn",
                owasp_category="EDGE-04 Cache Policy",
                description="A CDN cache policy is marked as caching authenticated or authorized responses.",
                remediation="Exclude Authorization/Cookie-bearing responses from cache or split public and private routes.",
                evidence={"resource": name, "caches_authorized_content": True},
            ))
    return findings


def _check_databases(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for db in _items(inventory, "databases", "rds", "cloud_sql", "cosmos"):
        name = _name(db, "cloud database")
        if cfg.get("check_public_access", True) and (
            _truthy(db.get("public")) or _truthy(db.get("public_access"))
        ):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudDatabaseAgent",
                title=f"Cloud database is publicly reachable: {name}",
                severity="critical",
                category="cloud_database",
                owasp_category="DSPM-01 Public Data Store",
                description="A managed database is marked publicly reachable in metadata.",
                remediation="Disable public access, restrict network paths to trusted private networks, and enforce database auth.",
                evidence={"resource": name, "public_access": True},
            ))
        if cfg.get("check_encryption", True) and _falsey(db.get("encrypted")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudDatabaseAgent",
                title=f"Cloud database encryption disabled: {name}",
                severity="high",
                category="cloud_database",
                owasp_category="DSPM-02 Data Encryption",
                description="A managed database is not encrypted at rest according to metadata.",
                remediation="Enable encryption at rest and rotate any affected credentials after migration.",
                evidence={"resource": name, "encrypted": False},
            ))
        if cfg.get("check_backups", True) and _falsey(db.get("backups_enabled")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudDatabaseAgent",
                title=f"Cloud database backups disabled: {name}",
                severity="medium",
                category="cloud_database",
                owasp_category="DSPM-03 Resilience",
                description="A managed database does not have backups enabled.",
                remediation="Enable automated backups and periodically test restore procedures.",
                evidence={"resource": name, "backups_enabled": False},
            ))
        if _falsey(db.get("deletion_protection")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudDatabaseAgent",
                title=f"Cloud database deletion protection disabled: {name}",
                severity="low",
                category="cloud_database",
                owasp_category="DSPM-04 Change Protection",
                description="A managed database can be deleted without deletion protection.",
                remediation="Enable deletion protection on production databases.",
                evidence={"resource": name, "deletion_protection": False},
            ))
    return findings


def _check_secrets(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for secret in _items(inventory, "secrets", "secret_managers", "key_vault"):
        name = _name(secret, "cloud secret")
        if cfg.get("check_rotation", True) and _falsey(secret.get("rotation_enabled")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="SecretsHygieneAgent",
                title=f"Secret rotation disabled: {name}",
                severity="medium",
                category="secrets_manager",
                owasp_category="SECRETS-01 Rotation",
                description="A secret metadata record shows rotation is disabled.",
                remediation="Enable automatic rotation or document and monitor a manual rotation cadence.",
                evidence={"resource": name, "rotation_enabled": False},
            ))
        if cfg.get("check_policy", True) and (
            _truthy(secret.get("policy_public")) or _truthy(secret.get("public_policy"))
        ):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="SecretsHygieneAgent",
                title=f"Secret policy allows public or broad access: {name}",
                severity="high",
                category="secrets_manager",
                owasp_category="SECRETS-02 Access Policy",
                description="A secret policy is marked public or broadly accessible in metadata.",
                remediation="Restrict secret access to the exact workload identities that require it.",
                evidence={"resource": name, "policy_public": True},
            ))
        if cfg.get("check_encryption", True) and _falsey(secret.get("encrypted")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="SecretsHygieneAgent",
                title=f"Secret encryption metadata is disabled: {name}",
                severity="medium",
                category="secrets_manager",
                owasp_category="SECRETS-03 Encryption",
                description="A secret metadata record shows encryption is disabled or not configured.",
                remediation="Use provider-managed or customer-managed encryption keys for stored secrets.",
                evidence={"resource": name, "encrypted": False},
            ))
    return findings


def _check_audit_logging(
    provider: str,
    scope: str,
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    audit = inventory.get("audit_logging") or inventory.get("logging")
    if not isinstance(audit, dict):
        return findings
    if _falsey(audit.get("enabled")):
        findings.append(_finding(
            provider=provider,
            scope=scope,
            agent="CloudAuditLoggingAgent",
            title="Cloud account audit logging disabled",
            severity="high",
            category="cloud_logging",
            owasp_category="CSPM-04 Audit Logging",
            description="Account-level cloud audit logging is disabled according to metadata.",
            remediation="Enable provider audit logging in every region and protect log sinks from deletion.",
            evidence={"audit_logging_enabled": False},
        ))
    if _falsey(audit.get("log_integrity_validation")):
        findings.append(_finding(
            provider=provider,
            scope=scope,
            agent="CloudAuditLoggingAgent",
            title="Cloud audit log integrity validation disabled",
            severity="medium",
            category="cloud_logging",
            owasp_category="CSPM-04 Audit Logging",
            description="Audit log integrity validation is disabled according to metadata.",
            remediation="Enable log file validation or immutable log storage where supported.",
            evidence={"log_integrity_validation": False},
        ))
    return findings


def _contains_secret_key(keys: Any) -> bool:
    return bool(_secret_like_keys(keys))


def _secret_like_keys(keys: Any) -> list[str]:
    if isinstance(keys, dict):
        raw_keys = keys.keys()
    elif isinstance(keys, list | tuple | set):
        raw_keys = keys
    else:
        return []
    out: list[str] = []
    for key in raw_keys:
        lowered = str(key).lower()
        if any(token in lowered for token in ("secret", "password", "token", "apikey", "api_key")):
            out.append(str(key))
    return sorted(out)


def _finding(
    *,
    provider: str,
    scope: str,
    agent: str,
    title: str,
    severity: str,
    category: str,
    owasp_category: str,
    description: str,
    remediation: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "owasp_category": owasp_category,
        "description": description,
        "remediation": remediation,
        "evidence": _redact({
            "provider": provider,
            "scope": scope,
            "agent": agent,
            **evidence,
        }),
    }


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, entry in value.items():
            if str(key).lower().replace("-", "_") in _SECRETISH_KEYS:
                redacted[key] = "[redacted]"
            else:
                redacted[key] = _redact(entry)
        return redacted
    if isinstance(value, list):
        return [_redact(entry) for entry in value]
    return value

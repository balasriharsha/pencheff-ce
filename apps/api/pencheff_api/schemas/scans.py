from datetime import datetime, timezone, timedelta
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# =============================================================================
# Per-kind disclosed-actions vocabulary (feature 001-multi-target-scan-pipelines).
# Maps each Target.kind to the minimum set of actions ConsentPayload.disclosed_actions
# must include. Router enforcement lives in routers/scans.py::start_scan.
# Hybrid kinds (cicd_pipeline, k8s_cluster) extend the required set when
# kind_config implies live-API probing — handled per-row at the router.
# =============================================================================
KIND_REQUIRED_DISCLOSED_ACTIONS: dict[str, frozenset[str]] = {
    # Legacy kinds — preserve existing vocabulary.
    "url":              frozenset({"passive_recon", "active_recon", "exploitation"}),
    "repo":             frozenset({"source_code_scan"}),
    "llm":              frozenset({"llm_red_team_prompts"}),
    # DAST cluster (new).
    "web_app":          frozenset({"passive_recon", "active_recon", "exploitation"}),
    "rest_api":         frozenset({"passive_recon", "api_fuzzing", "exploitation"}),
    "graphql":          frozenset({"introspection_query", "api_fuzzing", "exploitation"}),
    "websocket":        frozenset({"ws_handshake", "api_fuzzing", "exploitation"}),
    "grpc":             frozenset({"grpc_reflection", "api_fuzzing", "exploitation"}),
    # Artifact cluster (new).
    "source_code":      frozenset({"source_code_scan", "clone_repo"}),
    "iac":              frozenset({"iac_scan", "clone_repo"}),
    "container_image":  frozenset({"image_pull", "container_scan"}),
    "package_registry": frozenset({"dependency_scan", "registry_query"}),
    "sbom":             frozenset({"sbom_scan", "vuln_db_query"}),
    # Hybrid cluster (new). Phase A (static config audit) only by default.
    # Phase B disclosures (ci_api_read, k8s_api_read, rbac_enumeration) are
    # ADDED by routers/scans.py when kind_config.live_api_enabled / target=="live_cluster".
    "cicd_pipeline":    frozenset({"ci_config_audit"}),
    "k8s_cluster":      frozenset({"k8s_manifest_scan"}),
    # Infrastructure & Cloud Security targets. The cloud orchestrator is
    # read-only and only collects/uses metadata; secret values are explicitly
    # out of scope.
    "cloud_account":       frozenset({"cloud_metadata_read"}),
    "serverless_function": frozenset({"cloud_metadata_read"}),
    "cloud_storage":       frozenset({"cloud_metadata_read"}),
    "load_balancer_cdn":   frozenset({"cloud_metadata_read"}),
    "cloud_database":      frozenset({"cloud_metadata_read"}),
    "secrets_manager":     frozenset({"cloud_metadata_read"}),
    # Host / network target (feature 001 — Task 5).
    "host":             frozenset({"passive_recon", "active_recon", "host_os_exploitation"}),
    # MCP / AI agent target (spec 2026-06-16). Base = passive enumeration;
    # the router ADDS mcp_tool_invocation / mcp_destructive_tool_invocation
    # when kind_config.dynamic_invocation / destructive_opt_in are set.
    "mcp":              frozenset({"mcp_enumerate"}),
    # RAG / vector-DB target. Base = passive enumeration;
    # the router ADDS rag_query_probe when kind_config.query_probes is set,
    # and rag_poison_injection (nested) when poison_injection_opt_in is also set.
    "rag":              frozenset({"rag_enumerate"}),
    # ML model artifact target (spec 2026-06-17). Static-only, single disclosure:
    # fetch the artifact (download/snapshot) for static analysis — never loaded.
    "ml_model":         frozenset({"ml_fetch"}),
    # Voice / Speech-AI target (spec 2026-06-17). Base = passive enumeration;
    # the router ADDS voice_audio_probe when kind_config.audio_probes is set,
    # and voice_auth_probe (nested) when source_type=="voice_auth" as well.
    "voice":            frozenset({"voice_enumerate"}),
}


class ConsentPayload(BaseModel):
    """Operator consent captured at scan-creation time.

    The server overwrites ``consent_given_by_user_id`` with the
    authenticated user's id — the client's value is never trusted.
    ``consent_given_at`` is rejected if it is more than 5 minutes in the
    past (stale consent); the server sets it when absent.
    """

    version: int = 2
    acknowledged: bool
    authorization_text: str = Field(min_length=50, max_length=4000)
    disclosed_actions: list[str] = Field(min_length=1)
    consent_given_at: datetime | None = None
    # Server overrides — operator cannot fake who consented.
    consent_given_by_user_id: str | None = None
    # v2 audit fields — present on new payloads; None when loading legacy v1 records.
    authorized_hosts: list[str] | None = None
    acknowledged_at: str | None = None
    acknowledged_by_user_id: str | None = None
    acknowledged_from_ip: str | None = None
    acknowledged_user_agent: str | None = None

    @field_validator("acknowledged")
    @classmethod
    def must_acknowledge(cls, v: bool) -> bool:
        if not v:
            raise ValueError("acknowledged must be true")
        return v

    @field_validator("authorization_text")
    @classmethod
    def must_be_substantive(cls, v: str) -> str:
        s = v.strip()
        if len(s) < 50:
            raise ValueError("authorization_text must be at least 50 characters after stripping whitespace")
        return s


def load_consent_payload(raw: dict | None) -> ConsentPayload | None:
    """Parse a stored consent_payload, treating missing v2 fields as None.

    Returns None when ``raw`` is None (no consent payload was recorded — the
    pre-consent backfill case). Raises pydantic ValidationError on a payload
    that is neither v1 nor v2-shaped.
    """
    if raw is None:
        return None
    payload = dict(raw)
    payload.setdefault("version", 1)
    return ConsentPayload.model_validate(payload)


# =============================================================================
# KindPayload — per-scan operational overrides + derived payload (feature 001).
# Stored on Scan.kind_payload (JSONB). Server-derives from Target.kind_config
# at scan-creation time; clients may send a partial override for fields whose
# value varies per scan (e.g., container_image digest pinning).
# Every variant uses extra="forbid" (GATE 2 finding B-003).
# =============================================================================


class _KindPayloadBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WebAppPayload(_KindPayloadBase):
    kind: Literal["web_app"] = "web_app"
    crawl_depth_override: int | None = Field(default=None, ge=1, le=10)
    max_pages_override: int | None = Field(default=None, ge=1, le=1000)


class RestApiPayload(_KindPayloadBase):
    kind: Literal["rest_api"] = "rest_api"
    api_spec_override: dict | None = None


class GraphqlPayload(_KindPayloadBase):
    kind: Literal["graphql"] = "graphql"
    max_query_depth_override: int | None = Field(default=None, ge=1, le=50)


class WebsocketPayload(_KindPayloadBase):
    kind: Literal["websocket"] = "websocket"


class GrpcPayload(_KindPayloadBase):
    kind: Literal["grpc"] = "grpc"


class SourceCodePayload(_KindPayloadBase):
    kind: Literal["source_code"] = "source_code"
    git_ref_override: str | None = None


class CicdPipelinePayload(_KindPayloadBase):
    kind: Literal["cicd_pipeline"] = "cicd_pipeline"


class IacPayload(_KindPayloadBase):
    kind: Literal["iac"] = "iac"


class ContainerImagePayload(_KindPayloadBase):
    kind: Literal["container_image"] = "container_image"
    digest_override: str | None = None
    skip_layers: list[int] | None = None


class K8sClusterPayload(_KindPayloadBase):
    kind: Literal["k8s_cluster"] = "k8s_cluster"


class PackageRegistryPayload(_KindPayloadBase):
    kind: Literal["package_registry"] = "package_registry"


class SbomPayload(_KindPayloadBase):
    kind: Literal["sbom"] = "sbom"


KindPayload = Annotated[
    Union[
        WebAppPayload, RestApiPayload, GraphqlPayload, WebsocketPayload, GrpcPayload,
        SourceCodePayload, CicdPipelinePayload, IacPayload, ContainerImagePayload,
        K8sClusterPayload, PackageRegistryPayload, SbomPayload,
    ],
    Field(discriminator="kind"),
]


class ScanCreate(BaseModel):
    target_id: str
    # Three-tier scan profile — Quick / Standard / Deep — with prior
    # specialised profiles (engage, compliance, api-only, cicd, asm,
    # supply-chain, network-va, hackme) folded into Standard or Deep at
    # the runner. Older clients sending those names still work via the
    # alias map in services.scan_runner.
    profile: Literal["quick", "standard", "deep"] = "standard"
    # Optional engagement to tie this scan to. When set, the scan + its
    # findings show up in the engagement's unified view, OAST callbacks
    # are routed to the engagement's interactsh server, and the post-scan
    # correlation task is enqueued.
    engagement_id: str | None = None
    # Required operator consent — every scan must carry this payload.
    # The API validates and server-side overwrites consent_given_by_user_id.
    consent_payload: ConsentPayload
    # Optional one-shot recipient list for the "scan complete" email.
    # Captured at commission time and dispatched by the runner when the
    # scan transitions to ``done`` or ``failed``. Empty/null = no email.
    notify_emails: list[str] | None = None
    # Per-scan operational overrides for the 12 new kinds (feature 001).
    # Server cross-checks ``kind_payload.kind`` against ``target.kind`` in the
    # router and rejects mismatches with 400. NULL for legacy url/repo/llm scans.
    kind_payload: KindPayload | None = None
    # Operator-chosen AI toggle (commission UI). When False the runner forces
    # deterministic-only mode — no agent/swarm, no AI triage, no AI grading —
    # regardless of plan. Defaults True so existing callers are unaffected; the
    # runner still degrades to deterministic when the org is over its AI quota.
    use_ai: bool = True


class ScanAiQuotaOut(BaseModel):
    """Pre-flight scan-AI allowance for the commission modal. Drives whether
    the 'Use AI for this scan' toggle is enabled or force-disabled."""

    plan: str
    monthly_cap: int
    monthly_used: int
    monthly_remaining: int
    has_ai_access: bool
    quota_exhausted: bool
    ai_available: bool
    period_resets_at: str
    beta: bool


class ScanOut(BaseModel):
    id: str
    target_id: str
    status: str
    profile: str
    progress_pct: int
    current_stage: str | None = None
    grade: str | None = None
    score: int | None = None
    summary: dict | None = None
    log: list[str] | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    consent_payload: dict | None = None
    # ``True`` when a persisted STRIDE/DREAD threat model is available
    # for this scan via ``GET /scans/{id}/threat-model``. Drives the
    # threat-model link on the assessment page; the scan UI never
    # references the underlying storage container.
    has_threat_model: bool = False
    # Kind of the target this scan ran against — ``url`` / ``repo`` /
    # ``llm``. Drives surface-level UI gating: e.g. the Recommended
    # Guardrails card on the assessment page only renders for LLM
    # targets, regardless of whether the scan recorded any failures.
    target_kind: str | None = None

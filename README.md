# Pencheff

Autonomous penetration testing platform. Provide a target URL and credentials in natural language — Pencheff handles reconnaissance, vulnerability scanning, exploit chain analysis, and compliance-mapped reporting.

Unlike static scanners, Pencheff plans like a human pentester. Each testing module returns structured findings and `next_steps` recommendations, and the engine adaptively decides what to test next, chains discovered vulnerabilities together, and prioritizes the surface that actually matters.

> The full deterministic methodology — 49 MCP tools, 53 attack modules, 326 payloads, formal DOCX/PDF reports, compliance mapping, RBAC, suppression workflow, recheck — is **free and unlimited**. Pro adds the autonomous layer: per-finding walkthroughs, automated false-positive triage, audit-style grade attestation with executive rationale, and engine-driven adaptive scanning.

**Current version: v0.7.0**

## Features

- **`pencheff engage` — 9-phase autonomous swarm** — 30 specialist [playbooks](plugins/pencheff/docs/PLAYBOOKS.md) (28 from [0xSteph/pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents) + crawl-first + api-authenticator) drive scope → crawl → auth → recon → vuln → exploit → post-ex → detect → report. Subdomain fan-out, MITRE ATT&CK mapping, Tier 1/Tier 2 split, OPSEC noise tagging, cross-session engagement DB. See [docs/ENGAGEMENT-LIFECYCLE.md](plugins/pencheff/docs/ENGAGEMENT-LIFECYCLE.md).
- **API-first authenticated scans** — credential auth probes 14 common login endpoints in ~2s instead of driving Playwright. SSO/SAML/MFA flows still use the Playwright login-macro escape hatch when explicit `login_steps` are supplied.
- **Lifecycle integrations** — Slack, Teams, **Google Chat**, Discord, PagerDuty, Opsgenie, Splunk HEC, generic webhook, GitHub Issues, **Jira**. Each integration has per-target scope (`target_ids`) and per-event filter (`scan_started` / `scan_done` / `scan_failed` / `finding_new` / `finding_changed`) on top of the existing severity gate.
- **Repos as first-class targets** — every connected GitHub repository auto-mirrors as a Target row, so it shows up in the dashboard, the integrations target multi-select, and `GET /targets`. Source: GitHub App (recommended), Personal Access Token (private repos), or public URL. Local-folder registration removed in v0.4.0.
- **52 MCP tools** covering the full pentest lifecycle — including Active Directory, mobile app security, and ASM
- **`PENCHEFF_API_KEY` programmatic access** — per-user API keys with **37 fine-grained scopes** across 20 categories (`scans:*`, `findings:*`, `targets:*`, `reports:*`, `assets:*`, `repos:*`, `sboms:read`, `dependencies:read`, `integrations:*`, `schedules:*`, `engagements:*`, `notes:*`, `comments:*`, `fix_proposals:*`, `repeater:*`, `intruder:*`, `proxy:*`, `traffic:*`, `unified_findings:read`, `dashboard:read`). Wildcards: `scans:*`, `*:read`, `*:*`. Each key is pinned to one organisation and optionally one workspace; org-wide keys are owner/admin only. **Default-deny** — every endpoint declares its required scope, identity-bound concerns (billing / org-admin / branding / key-management itself) are session-only and never reachable with a key. Memberships are re-checked per request — removing a user from an org invalidates their keys instantly. **Audit-logged** create / update / revoke. Manage at **Settings → API keys**. See [API keys docs](apps/docs/pages/reference/api-keys.mdx).
- **53 attack modules** across 12 categories implementing real detection logic
- **326 payloads** across 17 payload files for injection, bypass, and exploitation testing
- **Adaptive testing** — the engine reasons about discovered tech stack, WAF detection, and vulnerabilities to guide testing strategy
- **OWASP Top 10 2021** category mapping with CVSS v3.1 and CVSS v4.0 scoring
- **6 compliance frameworks** — OWASP Top 10, PCI-DSS 4.0, NIST 800-53, SOC 2, ISO 27001:2022, HIPAA mapped to every finding
- **3 scan profiles in the dashboard** — `quick`, `standard`, `deep` — with the prior specialised profiles folded in: `cicd → quick`; `api-only`/`asm`/`sca`/`iac → standard`; `engage`/`compliance`/`compliance-full`/`supply-chain`/`network-va`/`hackme`/`continuous → deep`. Older clients sending the legacy names still work via an alias map at the runner. The CLI keeps the full subcommand catalogue.
- **OAST (Out-of-Band Application Security Testing)** — blind SSRF/SQLi/XSS detection via interactsh-client callbacks
- **Playwright integration** — SPA browser crawling, DOM XSS detection, login macro recording with headed browser
- **OpenAPI 3.x / Swagger 2.0 / Postman v2.1 import** — seed all endpoints automatically from existing specs
- **CI/CD first-class** — CLI (`pencheff scan`), GitHub Actions workflow, fail-on severity gate
- **Ticketing export** — create GitHub Issues or Jira tickets directly from findings (Jira creates one issue per `finding_new` event and comments on the existing issue when the finding is updated)
- **Delta scanning** — compare scans across sessions to track new/fixed/regressed findings
- **Finding suppression lifecycle** — accepted_risk, wont_fix, false_positive, duplicate, out_of_scope
- **Multi-credential support** — test authorization boundaries between user roles
- **Exploit chain analysis** — automatically identifies multi-step attack paths across findings
- **WAF-aware payloads** — detects WAF vendor and generates bypass-optimized payloads
- **Optional external security tools** — run allowlisted scanners via `run_security_tool` when they are installed and licensed for your environment
- **Exploitation-first methodology** — every scan finding is verified with `test_endpoint`, false positives eliminated, PoCs demonstrated
- **Export to Word, CSV, JSON** — professional reports with verification status, compliance mapping, suppression state
- **Secure by design** — credentials wrapped in `MaskedSecret`, never logged or leaked in findings

### All-in-one engagement workbench (new)

Beyond the MCP plugin, Pencheff ships a full engagement workbench so a pentest is a multi-day, multi-asset, multi-analyst activity instead of a single-machine save file:

- **Engagements** — create one per target with its own retention, OAST domain, traffic history, notes, and team. Layer between Workspace and Scan / RepoScan.
- **Browser-extension proxy** (see [apps/extension/README.md](apps/extension/README.md)) — Manifest V3 WebExtension for Chrome / Firefox / Edge that captures requests via `webRequest` + a `fetch` / `XHR` wrapper. **No CA cert install required.** Pair via the engagement's Install Extension page.
- **Persistent traffic** — every captured flow lands in `proxy_traffic` with a generated `tsvector` for full-text search across URL + bodies; star, tag, annotate; "Send to Repeater" preserves lineage.
- **First-class Pulse templates** — `scan_pulse` runs Pencheff Pulse: safe JSON/YAML template checks with workflow ingestion and normal findings dedup.
- **Per-engagement OAST** — when `OAST_BASE_DOMAIN` + Docker are set, every engagement spins up its own `interactsh-server` container with a unique subdomain + auth token. Falls back to shared `oast.fun` otherwise.
- **Repeater + Intruder** — server-side runners with persistent history; intruder supports sniper / battering-ram / pitchfork / cluster-bomb attack types via Celery worker.
- **Unified SAST + DAST + SCA + IaC + secrets** — one engagement, one findings view. Trivy IaC + Checkov added as repo scanners; a correlation service emits cross-references (shared CWE / shared CVE / route-token semantic match).
- **Live CVE data on every SCA scan** — OSV.dev per-package, NVD 2.0 per-CVE (CWE / CPE / NVD-CVSS), EPSS exploit-prediction, and CISA KEV active-exploitation flags. Refreshed automatically when local cache is stale (default 24 h TTL on OSV/EPSS/KEV, 14 d on NVD; tunable via `PENCHEFF_OSV_TTL_HOURS` / `PENCHEFF_FEED_TTL_HOURS` / `PENCHEFF_NVD_TTL_DAYS`, set any to `0` to force live every scan). Fails open — a network blip during refresh falls back to the stale row rather than dropping findings.
- **Threat modeling (STRIDE / DREAD) on every scan, automatically** — `--profile deep` against a URL auto-creates a target-pinned engagement (slug `deep-{target_id[:8]}`) and persists a DREAD threat model on it; subsequent deep scans of the same target reuse it. `quick` / `standard` and other profiles synthesise a fly-by model from the URL (~1 ms) for module-priority biasing without persistence. Either way, `Information Disclosure`-heavy targets run `scan_infrastructure` first while `Elevation of Privilege`-heavy ones lead with `scan_authz`. `ThreatModelAgent` runs in the swarm Phase 2 as a "lens" agent — emits a structured threat-coverage summary. Markdown report includes a `## Threat model` section. Web UI at `/engagements/[id]/threat-model`. `Scan.summary.threat_model_source ∈ {"engagement", "auto_engagement", "fly_by"}` records which path generated the bias. See the [threat-modeling docs](apps/docs/pages/features/threat-model.mdx).
- **End-to-end observability (OpenTelemetry → Postgres)** — opt-in (`PENCHEFF_OBSERVABILITY_ENABLED=true`, default off) traces / logs / metrics / tamper-evident audit trail across FastAPI + Celery + the MCP plugin + every external tool subprocess (nmap, sqlmap, nikto, hydra, nuclei, ffuf) + LLM agent turns + HTTP fan-out. Day-partitioned `otel_spans` / `otel_logs` / `otel_metrics` tables in your existing Postgres; hourly Celery beat does `DROP PARTITION` for 7-day retention (configurable via `PENCHEFF_OBSERVABILITY_RETENTION_DAYS`). The custom Postgres exporter uses raw psycopg2 to bypass SQLAlchemy auto-instrumentation and break the recursion cycle. Audit log carries a sha256 hash chain (`row_hash = sha256(prev_hash || canonical_json(row))`) serialised by `pg_advisory_xact_lock`; `GET /observability/audit/verify` walks the chain and reports tamper. LLM cost rolls up from `gen_ai.completion` spans (OpenTelemetry GenAI semantic conventions). Plugin ships traces over OTLP/HTTP when authenticated against `EngagementIngestToken`, otherwise writes JSONL locally to `~/.pencheff/logs/`. Web UI at `/observability/{slo,audit,cost}` and `/observability/traces/[scanId]` for per-scan waterfall. See the [observability docs](apps/docs/pages/features/observability.mdx).
- **Markdown viewer** — finding descriptions, executive summaries, and threat-model output render as proper Markdown (GFM tables, fenced code with syntax highlighting, mermaid diagrams) instead of plain text with literal `##` and `|` characters.
- **Real-time multi-analyst collaboration** — `WS /ws/engagements/{id}` channel via Redis pub/sub. Presence avatars, finding-status broadcast, repeater-tab live edits.
- **Branded reports + delta re-test** — per-workspace branding (logo, colors, opening letter, methodology, footer); `Report.kind = "delta"` renders new / fixed / regressed sections between two scans. Markdown export for consultancies that maintain deliverables in Git.
- **Visual dashboards on every scan + target + repo** (Recharts) — five surfaces over data already in Postgres. `/scans/{id}/dashboard` for one assessment (severity donut, CVSS histogram, OWASP coverage, top-risk list, endpoint treemap); the same route renders an LLM-specific composition for `kind="llm"` targets (verdict funnel, OWASP-LLM-Top-10 attack-success heatmap, strategy + technique breakdown, judge-confidence histogram, token + latency profile). Per-target trend section embedded on `/targets/{id}` (grade trajectory, severity stack, MTTR, scan-pair deltas). Per-repo trend at `/repos/{id}/dashboard` and per-repo-scan dashboard at `/repos/scans/{id}/dashboard` (file-hotspot treemap, scanner-effort bar, top CVE table with installed → fixed delta, fix-status pie). Workspace-level executive dashboard at `/dashboard/executive` (heatmap, 90-day trend, top repos, KEV exposure, fix conversion). See the [dashboards docs](apps/docs/pages/features/dashboards.mdx).
- **Email notifications via Resend** — three opt-in flows powered by the existing `services/email.py` wrapper. (1) **Scan-completion email**: at commission time, pick recipients from a workspace-member dropdown or type any email; the runner enqueues a Celery task on `done` / `failed` and emails the dashboard link with grade + severity strip. (2) **Per-target weekly digest**: `Target.weekly_digest_emails` configurable on the target edit page, dispatched Mondays 09:00 UTC by the `weekly-digest` Celery beat job — 7-day window of completed scans with grade per row, link to the target dashboard. (3) **Per-workspace weekly digest**: `Workspace.weekly_digest_emails` on the org-settings page sends a Monday rollup covering every target's latest grade. All three short-circuit cleanly when `RESEND_API_KEY` is unset. Set `RESEND_API_KEY`, `EMAIL_FROM`, and `EMAIL_APP_URL` to enable. See the [email-notifications docs](apps/docs/pages/features/email-notifications.mdx).
- **GitHub Action** (see [apps/github-action/README.md](apps/github-action/README.md)) — composite action that wraps `pencheff scan`, uploads the report as a workflow artifact, and posts a Markdown summary on the PR diff.

## Live CVE data on every scan

Every SCA scan pulls live CVE data — there is no manual refresh step.
Pencheff combines four authoritative sources at scan time:

| Source        | What it adds                                                                                  | Default TTL | Tunable env var              |
| ------------- | --------------------------------------------------------------------------------------------- | ----------- | ---------------------------- |
| **OSV.dev**   | Per-package vuln list (covers NVD CVEs + GitHub Security Advisories)                          | 24 h        | `PENCHEFF_OSV_TTL_HOURS`     |
| **NVD 2.0**   | Per-CVE enrichment: CWE list, CPE URIs, NVD-issued CVSS v3.1, canonical advisory URL          | 14 d        | `PENCHEFF_NVD_TTL_DAYS`      |
| **EPSS**      | Daily exploit-prediction score (0.0 – 1.0) and percentile                                     | 24 h        | `PENCHEFF_FEED_TTL_HOURS`    |
| **CISA KEV**  | Known-exploited flag + federal remediation deadline                                           | 24 h        | `PENCHEFF_FEED_TTL_HOURS`    |

Set any TTL to `0` to force a live fetch on every single scan. Set
`NVD_API_KEY` to raise NVD's rate limit from 5/30 s to 50/30 s.

The freshness layer **fails open**: a network failure during refresh
falls back to the stale cached row rather than dropping findings.

### Structured fields on every SCA finding

Every SCA finding carries the prioritisation inputs as structured
metadata so autofix, dashboard, and prioritisation read them without
parsing description text:

```json
{
  "advisory_id": "CVE-2024-1234",
  "ecosystem": "npm",
  "package": "lodash",
  "current_version": "4.17.20",
  "fix_version": "4.17.21",
  "epss": 0.42,
  "epss_percentile": 0.95,
  "kev": true,
  "kev_short_desc": "Active exploitation in the wild",
  "kev_due_date": "2024-02-01",
  "cwe_ids": ["CWE-1321"],
  "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
  "nvd_cvss_score": 8.6,
  "nvd_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
}
```

The canonical NVD URL is also promoted to position 0 of `references`
so DOCX / PR-comment / finding-card renderers link to NVD before OSV.

See the [SCA docs](apps/docs/pages/features/sca.mdx) for the full list
of supported manifests, reachability annotation, and license policy.

## Repository scanning

Repos are first-class targets. Connect once, scan on every push, get
SAST + SCA + IaC + secrets findings in the same unified queue as DAST.

### Connection paths

| Path | Best for | What you get |
| --- | --- | --- |
| **Pencheff GitHub App** (recommended) | Private repos, continuous scanning | Push webhooks, scoped per-repo permissions, Dependabot alert ingest, no token rotation, fix-PRs (Pro) |
| **Personal Access Token** | Single private repo, no GH App | One repo per token, manual re-scan |
| **Public URL** | Public repos | Anonymous clone, manual re-scan |

Every connected repo auto-mirrors as a `Target` row with `kind: "repo"`,
so it shows up in the dashboard, the integrations target multi-select,
and `GET /targets`.

### Six scanners run on every repo scan

Every match is normalised into a shared `RepoFinding` row so the UI
and the API don't care which engine produced it.

| Scanner | What it finds | Default behaviour |
| --- | --- | --- |
| **Semgrep** (SAST) | Multi-language pattern rules across an explicit OSS pack list (`p/owasp-top-ten`, `p/security-audit`, `p/cwe-top-25`, `p/secrets`, `p/jwt`, `p/django`, `p/flask`, `p/express`, `p/nodejs`, `p/golang`, `p/r2c-security-audit`) | Pinned packs only — no `--config=auto`, no Semgrep Pro rules. Override via `PENCHEFF_SEMGREP_PACKS`. |
| **Bandit** (SAST, Python) | Python-specific issues (hard-coded passwords, weak crypto, shell injection, deserialization) | Subprocess-only, Apache 2.0 |
| **gosec** (SAST, Go) | Go-specific issues (G-rules — sql injection, unsafe rand, weak crypto) | Subprocess-only, Apache 2.0 |
| **Brakeman** (SAST, Rails) | Rails-specific issues (mass assignment, SSL config, command injection in Rails idioms) | Subprocess-only, MIT — auto-skipped on non-Rails Ruby trees |
| **ESLint-security** (SAST, JS/TS) | JS / TS rules (`detect-object-injection`, `detect-eval-with-expression`, `detect-non-literal-regexp`, `detect-unsafe-regex`, …) | Pinned flat config, ignores any `.eslintrc` in the target tree |
| **Trivy** (SCA + IaC + secrets + container) | Dependency CVEs, IaC misconfigs (Terraform, K8s, CloudFormation, Helm), embedded secrets, container image issues | Runs in `fs` mode against the cloned tree; pulls live OSV/NVD/EPSS/KEV data |
| **Checkov** (IaC) | 1,000+ policy rules for Terraform, K8s, ARM, Bicep, OpenAPI | Configurable severity threshold |
| **OSV-Scanner / pip-audit / npm-audit** (SCA) | Per-package vuln list reconciled with the SCA freshness layer | Falls back to native parsers when CLIs absent |
| **Detect-Secrets / Gitleaks** (secrets) | Hardcoded API keys, tokens, private keys | Plugin baseline + entropy thresholds |

> **CodeQL was removed in v0.7** — its CLI is not licensed for
> commercial use on third-party code, and Pencheff scans customer
> code. The SAST role is now filled by the Semgrep + Bandit + gosec
> + Brakeman + ESLint-security pack listed above, all permissively
> licensed and runnable as subprocesses without per-customer license
> negotiation.

### Cross-scanner correlation

A correlation service emits cross-references when two scanners flag the
same root cause (shared CWE / shared CVE / route-token semantic match)
so the unified findings stream collapses duplicates instead of stacking
them.

### Triggers

- **Webhooks** — `push` events from connected GitHub Apps re-scan the
  affected repo automatically.
- **Manual** — `POST /repos/{id}/scan` from CLI / API / dashboard.
- **CI/CD** — the [pencheff-scan GitHub Action](apps/github-action/README.md)
  wraps the scan and posts a Markdown summary on the PR diff.
- **Dependabot ingest** — when the GitHub App is installed, Dependabot
  alerts are pulled in and reconciled against new SCA findings.

See the [repo-scanning docs](apps/docs/pages/repos/connect.mdx) and the
[scanner reference](apps/docs/pages/repos/scanners.mdx) for the full
configuration surface.

## Threat modeling (STRIDE / DREAD)

Every scan that runs against a URL gets a threat model — automatically.
The dispatcher follows three rules in order:

| Caller supplies… | Profile | What happens |
| --- | --- | --- |
| explicit container id with a model attached | any | The attached model is used as-is. `summary.threat_model_source = "engagement"`. |
| explicit container id without a model | any | Fly-by DREAD model from the URL. **Not persisted** — used for biasing only. `summary.threat_model_source = "fly_by"`. |
| nothing | `deep` | A target-pinned container is found-or-created, a DREAD model is generated and **persisted** on it. Repeat deep scans of the same target reuse the same container, accumulating findings. `summary.threat_model_source = "auto_engagement"`. |
| nothing | `quick`, `standard`, etc. | Fly-by DREAD model from the URL. **Not persisted**. `summary.threat_model_source = "fly_by"`. |

### Module priority bias

The chosen model drives `module_priority_bias` — the highest-scoring
STRIDE category reorders the scan profile's module list:

| STRIDE category | Modules biased toward |
| --- | --- |
| Spoofing | `scan_auth`, `scan_oauth`, `scan_mfa_bypass` |
| Tampering | `scan_injection`, `scan_client_side`, `scan_api` |
| Repudiation | `scan_authz`, `scan_infrastructure` |
| Information Disclosure | `scan_infrastructure`, `scan_api`, `scan_advanced`, `scan_subdomain_takeover` |
| Denial of Service | `scan_advanced`, `scan_infrastructure` |
| Elevation of Privilege | `scan_authz`, `scan_oauth`, `scan_business_logic` |

The bias **reorders** the profile's module list — it never replaces
modules. A scan with an `Information Disclosure`-heavy threat model
runs `scan_infrastructure` before `scan_injection`; the same profile
on an `Elevation of Privilege`-heavy model runs `scan_authz` first.
The chosen bias is stamped onto `Scan.summary.threat_model_bias` at
creation time so the dashboard can display *why* a particular module
fired first.

### Viewing the threat model from the assessment page

Every scan with a persisted model surfaces a **§ Threat model** section
on its assessment page (`/scans/<id>`) with a one-click link to the
full STRIDE / DREAD render at `/scans/<id>/threat-model` — DREAD score
table sorted by priority, category-score grid, mitigations per threat.
The link only appears when the model is persisted; fly-by scans show
the bias on the scan summary but have no durable model to link to.

### ThreatModelAgent in the swarm

A new `BreakerSpec` — `ThreatModelAgent` — runs in parallel with the
attack breakers during the swarm's Phase 2. Its job is **not** to fire
scanners; it reads the recon snapshot and other breakers' findings and
produces an INFO-severity finding summarising:

- Which STRIDE categories have the most evidence in this scan.
- Which threats from the engagement's threat model are now confirmed
  vs. still hypothetical.
- Recommended hardening priorities specific to this target.

The agent has no exclusive scan tools — it relies on the shared
`get_findings` and `test_endpoint` tools so it stays a "lens", not a
"probe". This avoids double-firing scanners that other breakers already
own.

### Report inclusion

The Markdown report renders a `## Threat model` section between the
executive summary and the findings table when the scan has a persisted
model. Operators get the threat model and the findings side-by-side in
a single deliverable.

See the [threat-modeling docs](apps/docs/pages/features/threat-model.mdx)
for the full output shape, CLI parity (`pencheff threatmodel
--method stride|dread`), and editing endpoints.

## Compliance mapping (per-scan)

Every Pencheff scan — URL, Repo, or LLM — carries a compliance
rollup that fans every active finding out across the frameworks
that match the target's asset class. Same shape, same UI, same
report appendix; only the source table and the framework set
change.

| Target kind | Frameworks emitted |
| --- | --- |
| URL (DAST) | OWASP Top 10 · PCI-DSS 4.0 · NIST 800-53 Rev 5 · SOC 2 · ISO 27001:2022 · HIPAA |
| Repo (SAST · SCA · IaC · secrets) | Same six. RepoFinding rows infer a category from scanner + rule_id. |
| LLM (red team) | OWASP LLM Top 10 (2025) · MITRE ATLAS · NIST AI Risk Management Framework · EU AI Act · GDPR · ISO/IEC 42001:2023 |

### Endpoints

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| `GET` | `/scans/{id}/compliance` | `scans:read` | Per-scan rollup for a URL or LLM scan |
| `GET` | `/repos/scans/{id}/compliance` | `repos:read` | Per-scan rollup for a repository scan |

Both endpoints return the **identical** JSON envelope so the same
web component, JSON exporter, and report appendix can consume any
scan id without branching by target kind. Output shape is documented
in [`services/compliance.py`](apps/api/pencheff_api/services/compliance.py)
and on the [compliance-mapping docs page](apps/docs/pages/features/compliance-mapping.mdx).

### Web UI

Every completed scan exposes a **§ Compliance mapping** card on its
assessment page (`/scans/{id}` and `/repos/scans/{id}`) with a button
to the dedicated render at `/scans/{id}/compliance` (URL / LLM) or
`/repos/scans/{id}/compliance` (repo). The page mirrors the
threat-model layout: a horizontal framework picker, a control table
with severity ribbons, and a per-finding mapping table for auditors
who want the forward direction (`finding → controls`) instead of
the reverse.

### Report inclusion

The DOCX / Markdown / JSON / CSV exporter renders the rollup into a
**Compliance** appendix that sits between the executive summary and
the findings register. JSON / CSV exports also carry a `compliance`
key on every finding so a downstream pipeline can ingest mappings
without re-running the categoriser.

See the [compliance-mapping docs](apps/docs/pages/features/compliance-mapping.mdx)
for the full output shape, the per-target framework set, and the
mapping algorithm.

## SBOM generation

Pencheff produces **SPDX 2.3** and **CycloneDX 1.5** Software Bills of
Materials from any repository using the same manifest parsers that back
SCA — so the SBOM is **consistent with the findings list by construction**,
not regenerated from a different parser.

### What's covered

| Ecosystem | Manifest |
| --- | --- |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml` |
| Node.js | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` |
| Java / Kotlin | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| Go | `go.sum`, `go.mod` |
| Ruby | `Gemfile.lock` |
| Rust | `Cargo.lock` |
| .NET | `packages.lock.json`, `*.csproj` |
| PHP | `composer.lock` |
| OS packages | dpkg / rpm / apk inside container scans |

Each component carries `name`, `version`, `purl` (Package URL),
license (SPDX expression where derivable), and supplier when the
manifest exposes one.

### How to generate

**Web UI:** open any repository page and click **Generate SBOM**. The
SBOM generates from the latest commit on the default branch and renders
in both **Table** and **JSON** views. Re-running replaces the previous
SBOM. Download as JSON when you need to ship to a customer or a
compliance attestation.

**MCP tool:**

```text
generate_sbom(session_id=sid, path='./', fmt='both', output_dir='./sbom-out/')
→ {
    source: 'native-parsers',
    component_count: 147,
    formats_generated: ['cyclonedx', 'spdx']
  }
```

**Python API:**

```python
from pathlib import Path
from pencheff.modules.sca.sbom_generator import generate_sbom

result = generate_sbom(Path('.'), fmt='both')
# result['formats']['cyclonedx']  — CycloneDX 1.5 dict
# result['formats']['spdx']       — SPDX 2.3 dict
```

### What it ties into

- **SCA finding cards** link straight to the SBOM component row, so an
  auditor can pivot from "this CVE is in your build" to "here's the
  exact SBOM line item, with PURL and supplier".
- **Compliance reports** (NIST 800-53, SOC 2, ISO 27001:2022) cite the
  generated SBOM as the source-of-record for SR-3 / SC-12 / A.5.21
  attestations.
- **GitHub Action** uploads the latest SBOM as a workflow artifact
  alongside the findings report.

See the [SBOM docs](apps/docs/pages/features/sbom.mdx) for the supported
manifests, generator internals, and the `GET /sboms/{id}` API.

## LLM Red Team

Pencheff treats an LLM endpoint as a third kind of asset alongside URL
(DAST) and Repo (SAST/SCA). Register a chat-completions endpoint once,
fire a curated suite of black-box adversarial probes at it, get OWASP
LLM Top 10 (2025) findings in the same unified queue as everything else.

### What it covers

| ID | Module | Coverage |
| --- | --- | --- |
| **LLM01** | Prompt Injection | Direct override · DAN-style role-play · suffix injection · encoded (b64/hex/ROT13/Morse) · multilingual · instruction-hierarchy bypass |
| **LLM02** | Sensitive Information Disclosure | PII echo · "repeat above" · coercive paraphrase · synthetic training-data recall |
| **LLM03** | Supply Chain | Model-card disclosure · version probing · third-party reference leakage |
| **LLM04** | Data and Model Poisoning | Indirect-injection style RAG-context simulation · adversarial training-time markers |
| **LLM05** | Improper Output Handling | XSS via markdown · `<script>` emission · iframe injection · ANSI hidden-text · SQL injection payload generation |
| **LLM06** | Excessive Agency | Tool / function-call abuse · privilege escalation framing |
| **LLM07** | System Prompt Leakage | Direct extraction · completion shotgun · fake debug mode · role inversion |
| **LLM08** | Vector and Embedding Weaknesses | Adversarial query crafting · context confusion |
| **LLM09** | Misinformation | Custom policy-driven probes · optional KB-grounded factuality grader |
| **LLM10** | Unbounded Consumption | Token-bomb baits · recursive amplification · ZWSP flooding · latency / token / cost threshold findings |

Compliance mappings on every finding: **OWASP LLM Top 10** · **MITRE
ATLAS** · **NIST AI RMF** · **EU AI Act** · **GDPR** · **ISO/IEC
42001:2023**.

### What runs on every scan (auto-on)

The runner walks LLM01 → LLM10. Each module's pipeline:

1. Load the per-module YAML payload library
2. Add the matching slice of every tier-4 add-on plugin pack —
   **bias** (age/disability/gender/race), **rag** (poisoning /
   exfiltration / source-attribution), **mcp** (tool-poisoning /
   name-collision / untrusted-server-prompt / resource-exfil),
   **coding-agent** (automation poisoning, delayed CI exfil,
   generated vulnerabilities, sandbox escape, secret handling,
   terminal output injection, steganographic exfil, verifier
   sabotage, and more — 11 sub-techniques)
3. Add the matching dataset cases — **DoNotAnswer** · **HarmBench** ·
   **BeaverTails** · **CyberSecEval** · **ToxicChat** · **Aegis** ·
   **UnsafeBench** (text proxies) · **XSTest** (over-refusal —
   verdict semantics inverted). All eight load by default; opt out
   of the tier-4 trio with `datasets_disable_default: true`.
4. Apply iterative attacks — **TAP**, **GOAT**, and **Hydra** mark
   every base case so the dispatcher routes them to the matching
   attacker-driven loop. Always-on when an attacker LLM is
   configured on the target. PAIR / static remain opt-in.
5. Round-robin cap at `max_payloads` (quick=25 / standard=75 /
   deep=250)
6. Dispatch with bounded concurrency + shared rate limiter
7. Verdict pipeline: regex → embedding → judge → factuality
8. Aggregate by `(category, technique)` — one Finding per technique
   with ≤ 5 evidence rows
9. Persist to DB at `module_done`

After the 10 modules, the scan is graded with the LLM-specific
severity curve, compliance-mapped against the six frameworks above,
rendered to the requested output formats, and a per-failed-category
runtime-guardrail recommendation set is surfaced for the Sentry
proxy.

### Profiles

| Profile | `max_payloads` | Wall time | Hard budget |
| --- | --- | --- | --- |
| `quick` | 25 | ~5 min | 10 min |
| `standard` | 75 | ~15 min | 30 min |
| `deep` | 250 | ~60–90 min | **2 hours** |

**Runtime guardrails** (Sentry proxy): scan finds the failure → UI
shows the recommended toggle → Sentry blocks the same shape inline
on every production request. Eight presets:
- `balanced` / `strict` / `minimal` / `all` — operational defaults
- `gdpr-aligned` — GDPR Art. 5 / 22 / 32 mappings (PII, BIAS, RAG)
- `iso-42001-aligned` — Annex A V&V (BIAS, CODING_AGENT) + A.10.3 supplier (MCP)
- `ai-act-high-risk` — EU AI Act Art. 13/14/15 (transparency, oversight, accuracy)
- `bias-aware-production` — BIAS + LLM09 factuality + RAG source-attribution

The four tier-4 detectors (`BIAS`, `RAG`, `MCP`, `CODING_AGENT`)
support an optional **LLM-judge fallback** for accuracy-sensitive
categories. Judge faults fail closed.

### Provider transports

| Provider | Transport | Auth |
| --- | --- | --- |
| `openai-chat` | HTTPS chat completions | Bearer / custom headers |
| `custom` | HTTPS with user-supplied request body template + response JSONPath | Headers |
| `executable` | Local command, JSON on stdin/stdout | OS-level |
| `websocket` | Single-message or multi-message WebSocket | Headers |
| `bedrock` | InvokeModel | AWS SigV4 (boto3) |
| `vertex` | `:generateContent` | Google ADC token (`google-auth`) |
| `azure-openai` | Chat completions | Entra OAuth (`azure-identity`) or `api-key` |
| `browser` | Playwright drives a chat UI | Headers + cookies |

Cloud-native auth re-signs / refreshes tokens per request without
touching the credential blob. Optional extras pull the right SDK:
`pip install pencheff[bedrock]` / `[vertex]` / `[azure]`.

### Attack surface beyond the OWASP Top 10

- **21 strategy transforms** — base64, hex, ROT13, Morse, leetspeak,
  homoglyph, jailbreak, authoritative-markup, citation, best-of-n, ASCII
  smuggling, emoji smuggling, image-markdown, audio / video transcript,
  CamelCase, pig-latin, `crescendo` (multi-turn).
- **Composite stacking** — chain transforms left-to-right
  (`jailbreak+base64`, `citation+ascii-smuggling`, etc.).
- **Multilingual variants** — Spanish, Mandarin, Hindi, Arabic, …;
  non-English locales typically have weaker safeguards.
- **Multi-turn Crescendo** — a real 5-turn TestCase that builds context
  turn-by-turn; intermediate-turn refusals can short-circuit
  escalation when a judge is configured.
- **Iterative search (PAIR)** — Prompt Automatic Iterative
  Refinement; an attacker LLM rewrites prompts up to `pair_iterations`
  times until VULNERABLE.
- **Attacker-LLM synthesis** — generates novel TestCases against your
  discovered profile (purpose, limitations, tools, user_context) once
  per scan, cached by profile hash.
- **Built-in datasets** — DoNotAnswer · HarmBench · BeaverTails ·
  CyberSecEval · Toxic-Chat. External datasets via `file://` or HTTPS.
- **Guardrail probes** — PII, secrets (AWS / GitHub / Stripe shapes),
  unsafe-code, tool-authz, plus active bypass variants when
  `guardrail_bypass: true`.

### Verdict pipeline (zero false positives)

For each probe the engine evaluates verdicts in order — REFUSED beats
every promotion path; AMBIGUOUS emits no Finding:

1. **Regex** — `success_indicators` ∧ ¬`refusal_patterns` →
   VULNERABLE. Refusal beats success.
2. **Embedding similarity** (optional) — when a TestCase declares
   `success_embeddings: [...]` and an embedder is configured, an
   AMBIGUOUS verdict can be promoted by cosine match.
3. **LLM-as-judge** (optional) — still-AMBIGUOUS verdicts go to a
   judge model. Judge confidence ≥ `min_confidence` to override.
4. **Factuality** (LLM09 only) — KB-grounded contradiction check.

### LLM-as-judge providers

| Provider | Notes |
| --- | --- |
| `openai-chat` | Any OpenAI-compatible chat endpoint. JSON-protocol baked into the system prompt. |
| `executable` | Local command receives JSON on stdin, returns JSON on stdout. Air-gapped friendly. |
| `llama-guard` | Llama Guard 3 (8B). Parses `safe`/`unsafe S1..S14`; maps S-codes onto OWASP LLM categories. |
| `granite-guardian` | IBM Granite Guardian 3.x. Yes/No protocol with optional risk dimension. |
| `openai-moderation` | OpenAI `/moderations` API. Threshold-graded; cheap; **recommended for reasoning-model targets** because it scores visible output, not `<think>` traces. |

### Cost & rate controls

A token-bucket rate limiter is **shared across every probe targeting
the same endpoint**, so 10 OWASP modules dispatching concurrently
respect a single per-key cap. 429 responses honour the upstream
`Retry-After` header automatically.

```yaml
max_rps: 0.3                 # explicit; overrides max_rpm
max_rpm: 18                  # OpenRouter free tier ≈ 20 RPM
concurrency: 3
retries: 3
budget:
  max_calls: 2000
  max_cost_usd: 5.0
  input_cost_per_1k: 0.0     # set non-zero for paid models
  output_cost_per_1k: 0.0
thresholds:
  max_latency_ms: 30000      # emits LLM10 finding when exceeded
  max_tokens_per_call: 4000  # emits LLM10 finding when exceeded
```

### Profiles

| Profile | `max_payloads` | Wall time @ 18 RPM |
| --- | --- | --- |
| `quick` | 25 | ~2 min |
| `standard` | 75 | ~5 min |
| `deep` | 250 | ~15–60 min (depending on retries / judge / attacker) |

Round-robin across techniques means a `quick` profile never starves
any single technique class.

### Reporting + integrations

- **Markdown / HTML / CSV / JSON / JUnit XML / Prometheus** report
  formats; HTML is self-contained (embedded CSS, no JS) so it's email-able.
- **Share-by-link** — `POST /scans/{id}/share?ttl_seconds=604800`
  returns a Fernet-encrypted token; public `GET /share/llm/{token}`
  renders without auth (token expiry is the only revocation).
- **A/B comparison & regression detection** — `GET /scans/{a}/compare/{b}`
  returns a structured diff (regressions, fixes, common failures); the
  web UI exposes the same diff at `/scans/compare?a=…&b=…`. Gate PRs on
  safety regressions, A/B different model versions on the same suite.
- **Grafana dashboard** — canonical dashboard at
  [`docs/grafana/pencheff-llm-redteam.json`](docs/grafana/pencheff-llm-redteam.json):
  total failures, per-OWASP-LLM breakdown, per-strategy table, severity
  donut, latency p50/p95/p99, regression rate, cost trend.
- **OWASP-LLM-aware integrations** — Slack / webhook / Jira payloads
  automatically include a per-OWASP-LLM breakdown and the top failed
  techniques when `target.kind == "llm"`.

### CLI

```bash
pencheff llm-redteam \
  --target https://openrouter.ai/api/v1/chat/completions \
  --model 'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free' \
  --header "Authorization=Bearer sk-or-v1-…" \
  --strategies 'base64,jailbreak,crescendo,leetspeak' \
  --datasets 'donotanswer,harmbench' \
  --guardrails 'pii,secrets,unsafe-code,tool-authz' \
  --judge-provider openai-moderation \
  --judge-endpoint https://api.openai.com/v1/moderations \
  --max-rps 0.3 \
  --max-cost-usd 5 \
  --output-format html \
  --output-file report.html \
  --fail-on high
```

### Ethical framing

A finding here means *"the model produced output of class X when
asked"* — not *"here is the harmful generation verbatim."* Evidence
captures sanitized snippets (≤512 chars) and PII-shaped tokens
(emails, SSNs, cards, phone numbers, common API key patterns) are
redacted before they reach Findings. Full responses go to the scan
log only when explicitly opted in.

### Plugin SDK

Strategy transforms, judge providers, and chat providers are all
extensible. Drop a Python file under
`~/.pencheff/custom_llm_strategies/`, `~/.pencheff/custom_llm_judges/`,
or `~/.pencheff/custom_llm_providers/`, set
`PENCHEFF_ENABLE_CUSTOM_MODULES=1`, and Pencheff discovers them at
scan time.

See the [LLM Red Team docs](apps/docs/pages/features/llm-redteam.mdx)
for the full strategy catalogue, dataset shape, judge config knobs,
and the `scan_llm_red_team` MCP tool reference.

## Observability

Off by default. Flip one env var (`PENCHEFF_OBSERVABILITY_ENABLED=true`),
run `alembic upgrade head`, restart, and every scan + every API request
+ every subprocess + every LLM call lands in your existing Postgres
with day-partitioned 7-day retention.

| Env var                                      | Default            | Purpose                                                                    |
| -------------------------------------------- | ------------------ | -------------------------------------------------------------------------- |
| `PENCHEFF_OBSERVABILITY_ENABLED`             | `false`            | Master kill-switch. Vanilla deploys pay zero overhead.                     |
| `PENCHEFF_OBSERVABILITY_SAMPLE_RATIO`        | `1.0`              | Head sampler. ParentBased so children always follow root.                  |
| `PENCHEFF_OBSERVABILITY_RETENTION_DAYS`      | `7`                | DROP PARTITION horizon for spans / logs / metrics.                         |
| `PENCHEFF_AUDIT_RETENTION_DAYS`              | `7`                | Independent knob (compliance often wants 90+ here).                        |
| `PENCHEFF_OBSERVABILITY_SERVICE_NAME`        | `pencheff-api`     | Resource attribute on every signal.                                        |
| `PENCHEFF_OBSERVABILITY_OTLP_URL`            | unset              | Plugin: where to ship OTLP traces. Empty = local JSONL only.               |
| `PENCHEFF_OBSERVABILITY_OTLP_TOKEN`          | unset              | Plugin: bearer token, must match an `EngagementIngestToken`.               |
| `PENCHEFF_OBSERVABILITY_LOCAL_DIR`           | `~/.pencheff/logs` | Plugin: local file-exporter target directory.                              |

Migrations applied: `0041_otel_partitioned_tables`,
`0042_audit_log_hash_chain`.

Dashboards live under `/observability` in the web app:

- `/observability/slo` — error rate, p50/p95/p99 latency, queued + active scans
- `/observability/audit` — append-only mutation log with a one-click hash-chain verifier
- `/observability/cost` — LLM token spend grouped by model
- `/observability/traces/[scanId]` — per-scan waterfall

For full architecture, the redaction model, plugin shipping setup, and
trace-correlation details see [the observability docs](apps/docs/pages/features/observability.mdx)
and the [API reference](apps/docs/pages/reference/observability.mdx).

## Installation

### From Source

```bash
git clone https://github.com/BalaSriharsha-Ch/pencheff.git
cd pencheff
```

Connect any MCP-compatible client by adding to its `.mcp.json` (or equivalent
config):

```json
{
  "mcpServers": {
    "pencheff": {
      "command": "uv",
      "args": ["run", "--project", "./plugins/pencheff", "python", "-m", "pencheff"]
    }
  }
}
```

### Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) for dependency management
- Any MCP-compatible client (Cursor, Continue, Cline, Zed, custom MCP host, …) — or use the standalone CLI

## Quick Start

Use the built-in skill for a full automated pentest:

```
/pencheff:pentest https://example.com username: admin, password: test123
```

Or use the agent directly:

```
@pencheff Run a full pentest against https://api.example.com with API key: sk-abc123
```

Or call individual tools for targeted testing:

```
Use pentest_init to start a session against https://example.com, then run scan_injection on the /api/login endpoint.
```

### Quickstart by target kind

The shortest one-page path per target kind:

| Quickstart | What you ship at the end |
| --- | --- |
| [URL scan (DAST)](apps/docs/pages/quickstart/url-scan.mdx) | Verified findings + DOCX in 5–40 min |
| [LLM red team](apps/docs/pages/quickstart/llm-redteam.mdx) | OWASP LLM Top 10 (2025) coverage + judge |
| [Repo scan](apps/docs/pages/quickstart/repo-scan.mdx) | SAST · SCA · IaC · secrets, six scanners in parallel |
| [SBOM](apps/docs/pages/quickstart/sbom.mdx) | CycloneDX 1.5 + SPDX 2.3 from any repo |
| [Compliance mapping](apps/docs/pages/quickstart/compliance.mdx) | Per-scan rollup across 6 + 4 frameworks |

### Tutorials (end-to-end)

Long-form walkthroughs that finish with a runnable artefact:

- [Web app pentest](apps/docs/pages/tutorials/web-app-pentest.mdx) — auth, exclusions, customer-ready DOCX
- [SPA + authenticated crawl](apps/docs/pages/tutorials/spa-authenticated.mdx) — Playwright login macro + deep scan
- [API + OpenAPI seed](apps/docs/pages/tutorials/api-pentest.mdx) — spec-driven scan with two credentials
- [LLM red team walkthrough](apps/docs/pages/tutorials/llm-redteam-walkthrough.mdx) — judge + per-OWASP-LLM evidence
- [LLM A/B regression gate](apps/docs/pages/tutorials/llm-ab-regression.mdx) — gate model upgrades on safety regressions
- [Monorepo repo scan](apps/docs/pages/tutorials/monorepo-repo-scan.mdx) — language detection, exclude paths, per-team routing
- [SCA + supply chain](apps/docs/pages/tutorials/sca-supply-chain.mdx) — live OSV / NVD / EPSS / KEV + reachability
- [IaC + cloud hardening](apps/docs/pages/tutorials/iac-cloud-hardening.mdx) — Trivy IaC + Checkov + suppression trail
- [SBOM as evidence](apps/docs/pages/tutorials/sbom-evidence.mdx) — release-tag SBOMs for attestations
- [Audit-ready compliance bundle](apps/docs/pages/tutorials/audit-ready-bundle.mdx) — DOCX + JSON + CSV + SBOM zip
- [CI gate (PR-blocking)](apps/docs/pages/tutorials/ci-gate.mdx) — fail-on regressions on every PR

## CLI Usage

Pencheff ships a standalone CLI for headless scans and CI/CD pipelines.
After `pip install pencheff` the package puts a `pencheff` executable
on your `PATH` — the canonical entry point, exactly like `aws` or
`kubectl`:

```bash
$ pip install pencheff
$ which pencheff
/usr/local/bin/pencheff
$ pencheff --version
pencheff 0.7.0
$ pencheff --help
```

The legacy `python -m pencheff …` form still works (the package keeps a
valid `__main__` module), but the bare `pencheff` command is the
documented form throughout this README and the docs site.

```bash
# Run a standard scan and save the report as JSON
pencheff scan --target https://example.com --format json --output ./reports

# Run a fast CI/CD-optimized scan; exit non-zero if high or critical found
pencheff scan --target https://example.com --profile quick --fail-on high

# Authenticated scan with credentials
pencheff scan --target https://example.com --profile deep \
  --username admin --password secret --save-history

# List saved scan history
pencheff history

# Compare two scans to find new/fixed/regressed findings
pencheff compare <session_id_a> <session_id_b>

# Lightweight Pencheff TCP/UDP port map for assets you are authorized to test
pencheff map --target 10.0.0.10 --ports top-100 --format table
pencheff map --target 10.0.0.0/24 --ports 22,80,443 --format json
pencheff map --target 10.0.0.10 --all-ports --format table
pencheff map --target 10.0.0.10 --all-ports -A --format json
pencheff map --target 10.0.0.10 --all-ports -sU -T4 --format xml

# Non-destructive first-party SQL injection assessment
pencheff sqli --url "https://app.example.com/item?id=1" --format table
pencheff sqli --url "https://app.example.com/login" --method POST \
  --data "username=alice&password=test" --param username --format json
pencheff sqli -r request.txt --profile deep --tamper space2comment \
  --traffic-log .pencheff/sqli-evidence.jsonl --format json
pencheff sqli --burp-xml burp-export.xml --risk 2 --level 4

# Non-destructive first-party web server exposure assessment
pencheff webscan --target https://app.example.com --profile standard
pencheff webscan --target https://app.example.com --profile deep \
  --path /custom-status --traffic-log .pencheff/webscan-evidence.jsonl --format json
pencheff webscan --targets-file targets.txt --tuning apps --tuning files \
  --check-db team-web-checks.json --suppressions webscan-suppressions.json --format html
pencheff webscan --update-checks

# Non-destructive first-party template detection
pencheff pulse --target https://app.example.com --profile standard
pencheff pulse --targets-file targets.txt --tag exposure --format jsonl
pencheff pulse --target https://app.example.com -t team-templates/ \
  --template-id exposed-env-file --format html
pencheff pulse --target https://app.example.com -t pulse-safe-http.yaml \
  --cache-dir .pencheff/pulse-cache --stats-file .pencheff/pulse-stats.json --resume
pencheff pulse --target https://app.example.com --ignore-file .pulse-ignore \
  --require-signed --trusted-author security-team --headless
```

`pencheff map` supports Pencheff-native discovery flags: `-sV` for safe
service/version detection, `-O` for passive OS guesses, `--script-scan` and
`--vuln-scan` for built-in low-impact checks, `--traceroute` for system
traceroute when available, `-sU` for a small UDP probe set, `-T0` through `-T5`
for timing profiles, XML/JSON/CSV/table output, and `-A` to bundle those checks.
`-sS` is accepted as a low-noise TCP connect mode; Pencheff does not perform raw
SYN stealth/evasion scans. The Pencheff pentest workflow's `recon_active` stage
uses full TCP port discovery by default.

`pencheff sqli` is a safe SQL injection assessor for authorized targets. It
supports error-signature, boolean-differential, capped time-delay, UNION-shape,
and safe stacked-query checks; request-file, bulk-file, Burp XML, same-origin
crawl import; cookies, headers, proxy, CSRF token refresh, anti-cache nonces;
profiles, level/risk tuning, tamper transforms, JSONL evidence, and cache/resume.
It does not dump database contents, enumerate schemas, read/write files, create
UDFs, or attempt shell access.

`pencheff webscan` is a safe web server exposure assessor. It checks security
headers, cookies, informational headers, HTTP methods, common exposed files,
default/admin paths, backup artifacts, directory listings, diagnostic pages,
and disclosure patterns. It uses a local JSON check database with matcher
expressions such as `CODE:200&&BODY:Swagger UI`, supports extra check packs,
multi-target files, tuning tags, HTML/XML/CSV/JSON/table reports, auth profiles,
suppressions, JSONL evidence, and a first-party `--update-checks` command. The
normal `scan_infrastructure` workflow runs this first-party engine through the
`web_server` module.

`pencheff pulse` is a safe template scanner. Templates are
first-party JSON/YAML checks and a Pulse-compatible safe HTTP subset, including
raw HTTP requests, request chaining, named extractors, variables, helper
functions, status/word/regex/header/size/simple-DSL matchers, and bounded
query/body/header fuzzing. It also supports passive DNS/TCP/TLS detection,
optional Playwright headless DOM checks, `.pulse-ignore`, signature/trusted
author metadata, CVSS/CWE/CPE-style classification fields, user template update
channels, cache/resume, stats files, target files, auth profiles, JSONL/JSON/CSV/XML/HTML/table output,
and workflow ingestion through the `scan_pulse` stage. Pulse intentionally
does not execute arbitrary code templates or poll OAST callbacks; `--interactsh-url`
is a safe placeholder for templates that need a callback token.

### Scan Profiles

The dashboard exposes three tiers. Older specialised profile names are
still accepted by `POST /scans` for backward compatibility but get
coerced to one of these three at the runner — see the fold-in column.

| Profile | Description | Folds in |
|---------|-------------|----------|
| `quick` | Top-severity probes only. CI/CD-friendly fail-fast on critical/high. | `cicd` |
| `standard` | OWASP Top 10 + active scanner. REST/GraphQL/API surface. ASM/SCA/IaC checks. Deterministic bug-bounty pipeline. CVE correlation. | `api-only`, `asm`, `sca`, `iac` |
| `deep` | Every module + Pulse + chains. Full swarm (Tier 2 · all 7 phases · top-1000 ports · subdomain fan-out ≤100). Deterministic orchestrator + MITRE ATT&CK narrative. PCI / SOC 2 / ISO 27001 / NIST / HIPAA. | `engage`, `compliance`, `compliance-full`, `supply-chain`, `network-va`, `hackme`, `continuous` |

## CI/CD Integrations

Pencheff ships first-class CI/CD integrations for GitHub Actions, GitLab CI, and Azure DevOps.

### GitHub Actions

The included workflow at `.github/workflows/pencheff-scan.yml` provides:

- Automatic scan on push/PR to `main`/`master`
- Nightly full scan (02:00 UTC)
- Manual dispatch with configurable target, profile, and fail-on severity
- Artifact upload of JSON/CSV reports
- Automatic GitHub Issue creation on critical/high findings
- PR comment with finding summary table

See [apps/github-action/README.md](apps/github-action/README.md) for the composite action reference.

```yaml
# Manual trigger
gh workflow run pencheff-scan.yml \
  -f target_url=https://staging.example.com \
  -f profile=quick \
  -f fail_on=high
```

### GitLab CI

See [apps/gitlab-ci/README.md](apps/gitlab-ci/README.md). Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/BalaSriharsha-Ch/pencheff/main/apps/gitlab-ci/.gitlab-ci.yml'

variables:
  PENCHEFF_TARGET: "https://your-app.example.com"
  PENCHEFF_FAIL_ON: "high"
  PENCHEFF_API_TOKEN: $PENCHEFF_API_TOKEN
```

### Azure DevOps

See [apps/azure-devops/README.md](apps/azure-devops/README.md). Reference the template in your `azure-pipelines.yml`:

```yaml
extends:
  template: apps/azure-devops/azure-pipelines.yml@pencheff
  parameters:
    target: 'https://your-app.example.com'
    failOn: 'high'
```

## MCP Tools (52)

### Session Management (3)

| Tool | Description |
|------|-------------|
| `pentest_init` | Initialize session with target URL, credentials, scope, depth, and scan profile |
| `pentest_status` | Get progress — completed modules, finding counts, intelligent next-step recommendations |
| `pentest_configure` | Update credentials, scope, or depth mid-session |

### Reconnaissance (3)

| Tool | Description |
|------|-------------|
| `recon_passive` | DNS enumeration, WHOIS, certificate transparency, subdomain discovery, technology fingerprinting |
| `recon_active` | TCP port scanning (top-100/top-1000), web crawling (Playwright SPA crawl when available, HTTP fallback), service fingerprinting, endpoint discovery |
| `recon_api_discovery` | OpenAPI/Swagger spec detection, GraphQL introspection, API route enumeration from JavaScript/sitemap/robots.txt |

### Vulnerability Scanning (11)

| Tool | Description |
|------|-------------|
| `scan_injection` | 10 injection types: SQLi (error/blind/time-based), NoSQLi, command injection, SSTI, XXE, SSRF (with OAST blind detection), LDAP injection, second-order injection, open redirect, HTTP header injection |
| `scan_auth` | Session management flaws, JWT attacks (none algorithm, claim tampering, RS256→HS256 confusion), brute force resistance, password policy |
| `scan_authz` | IDOR, horizontal/vertical privilege escalation, RBAC bypass (requires multiple credential sets for best results) |
| `scan_client_side` | XSS (reflected/stored/DOM-based), CSRF token analysis, clickjacking, DOM XSS (static sink analysis + dynamic Playwright-based detection) |
| `scan_infrastructure` | SSL/TLS configuration, security headers (CSP, HSTS, X-Frame-Options, etc.), CORS misconfigurations, HTTP method enumeration |
| `scan_api` | REST parameter fuzzing, GraphQL depth/batch attacks, mass assignment / object injection testing |
| `scan_cloud` | S3 bucket enumeration/permissions, cloud metadata service access (AWS/GCP/Azure) |
| `scan_waf` | WAF detection and fingerprinting (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5, Fortinet, Sucuri, Barracuda, Wordfence), bypass testing |
| `scan_advanced` | HTTP request smuggling (CL.TE, TE.CL, TE.TE with 12 obfuscation variants), web cache poisoning/deception, insecure deserialization (Java/Python/PHP/.NET/YAML), prototype pollution, DNS rebinding |
| `scan_websocket` | CSWSH, WebSocket auth bypass, message injection (SQLi/XSS/CMDi via WebSocket), insecure transport detection |
| `scan_subdomain_takeover` | Dangling CNAME detection for 20+ services with HTTP response signature matching |

### Authentication & Authorization Deep Dive (2)

| Tool | Description |
|------|-------------|
| `scan_oauth` | OAuth/OIDC testing: redirect_uri manipulation (13+ bypass techniques), state parameter validation, token leakage via Referer, scope escalation |
| `scan_mfa_bypass` | 2FA/MFA bypass: direct endpoint access, OTP brute force, backup code abuse, race condition on code validation |

### Specialized Scanning (2)

| Tool | Description |
|------|-------------|
| `scan_file_handling` | File upload bypass (extension, MIME type, magic bytes), path traversal with encoding bypasses |
| `scan_business_logic` | Rate limiting adequacy, race conditions (concurrent requests), workflow bypass, state manipulation |

### Active Directory / Internal Network (1)

| Tool | Description |
|------|-------------|
| `scan_active_directory` | Full AD enumeration: BloodHound relationship graph (attack paths to Domain Admin), Certipy ESC1–ESC8 certificate template abuse, CrackMapExec SMB/share enumeration, Impacket secretsdump. Selectable via `modules` param. |

### Mobile Application Security (1)

| Tool | Description |
|------|-------------|
| `scan_mobile_app` | Static + dynamic analysis of Android APK / iOS IPA: MobSF REST API (full static scan), apktool decompile, Android manifest exported-component check, secrets grep across decompiled output. |

### Attack Surface Monitoring (1)

| Tool | Description |
|------|-------------|
| `scan_asm` | Continuous ASM for an organisation: passive subdomain discovery (subfinder + crt.sh), certificate expiry monitoring, change detection against last-known inventory, and asset inventory upsert. |

### Intelligence Tools (2)

| Tool | Description |
|------|-------------|
| `exploit_chain_suggest` | Analyzes all findings against 14 chain rules to identify multi-step attack paths. Returns ranked chains with combined CVSS and exploitation narratives |
| `payload_generate` | Generates context-aware payloads optimized for the target's tech stack and WAF. Supports 13 attack types with framework-specific mutations and WAF bypass encodings |

### Browser & Authentication (4)

| Tool | Description |
|------|-------------|
| `browser_crawl` | SPA crawling via Playwright (Chromium headless) — intercepts network requests, discovers routes via `framenavigated`, evaluates DOM links/forms, extracts API endpoints from inline JavaScript |
| `scan_dom_xss` | DOM XSS detection: static script sink analysis (always runs) + dynamic Playwright-based payload injection via URL fragments/params (7 DOM XSS payloads: img onerror, svg onload, iframe onload, details ontoggle) |
| `authenticated_crawl` | Playwright crawl using active session credentials — injects cookies and Authorization headers for post-login endpoint discovery |
| `record_login_macro` | Interactive login recording via headed Playwright browser — tracks navigation events and network requests, extracts cookies/localStorage tokens, seeds endpoints from captured traffic |

### OAST (Out-of-Band Testing) (3)

| Tool | Description |
|------|-------------|
| `oast_init` | Initialize OAST session — auto-detects backend: interactsh-client if installed, `OAST_HOST` env var, or placeholder mode |
| `oast_new_url` | Generate a unique labeled callback URL for blind vulnerability detection (HTTP protocol) |
| `oast_poll` | Poll for received callbacks — returns probe hits with source IP, protocol, and raw request data |

### API Specification Import (1)

| Tool | Description |
|------|-------------|
| `import_api_spec` | Import OpenAPI 3.x, Swagger 2.0, or Postman v2.1 collection — resolves `$ref` references, generates body examples, seeds all endpoints into the session for scanning |

### Finding Lifecycle (2)

| Tool | Description |
|------|-------------|
| `suppress_finding` | Suppress a finding with a reason: `accepted_risk`, `wont_fix`, `false_positive`, `duplicate`, or `out_of_scope`. Suppressed findings are excluded from reports and counts by default |
| `unsuppress_finding` | Remove suppression — finding returns to active state |

### Scan History & Delta (4)

| Tool | Description |
|------|-------------|
| `save_scan` | Persist current session findings to `~/.pencheff/history/` as JSON |
| `list_scan_history` | List saved scans, optionally filtered by target URL |
| `compare_scans` | Compare two saved sessions — returns new findings, fixed findings, persisted findings, and severity regressions |
| `list_scan_profiles` | List all available scan profiles with module lists and configuration |

### Scoring (1)

| Tool | Description |
|------|-------------|
| `calculate_cvss40` | Calculate CVSS v4.0 base score from a vector string — returns numeric score and severity label |

### External Tool Execution (1)

| Tool | Description |
|------|-------------|
| `run_security_tool` | Execute allowlisted external security tools when they are installed and licensed for your environment. Returns stdout/stderr with intelligent next-step recommendations |

### Manual / Targeted Testing (3)

| Tool | Description |
|------|-------------|
| `test_endpoint` | Custom HTTP request with specific payloads against a single endpoint. Accepts `body` as string, dict, or list (auto-serialized). Supports `PENCHEFF` marker substitution |
| `test_chain` | Multi-step attack sequence with JSONPath variable extraction and substitution between steps |
| `analyze_response` | Analyze an HTTP response for information disclosure, error messages, sensitive data patterns (AWS keys, JWTs, emails), and missing security headers |

### Reporting & Export (5)

| Tool | Description |
|------|-------------|
| `get_findings` | Retrieve findings filtered by severity, category, or OWASP category; toggle suppressed finding visibility |
| `generate_report` | Full pentest report — executive summary, technical details, CVSS scores, 6-framework compliance mapping (Markdown/JSON) |
| `export_report` | Export to **Word (.docx)**, **CSV**, and **JSON** simultaneously. Includes verification status, suppression state, and all 6 compliance frameworks. Saved to `~/pencheff-reports/<session_id>/` |
| `verify_finding` | Set verification status: `true_positive`, `false_positive`, `true_negative`, `false_negative`, or `unverified` |
| `check_dependencies` | Verify Python packages and all 116 system tools; reports capability gaps with install instructions |

### Ticketing Export (2)

| Tool | Description |
|------|-------------|
| `export_to_github` | Create GitHub Issues from findings via `gh` CLI — severity labels, OWASP category labels, full evidence and compliance mapping in issue body. Supports `dry_run` preview |
| `export_to_jira` | Create Jira tickets via REST API v3 — Atlassian Document Format (ADF) descriptions, priority mapping, severity labels. Reads `JIRA_URL`, `JIRA_TOKEN`, `JIRA_EMAIL`, `JIRA_PROJECT` env vars |

## Attack Modules (53)

### Reconnaissance (5 modules)

| Module | File | Techniques |
|--------|------|------------|
| DNS Enumeration | `recon/dns_enum.py` | A/AAAA/MX/TXT/NS/CNAME records, AXFR zone transfer, SPF/DMARC analysis |
| Subdomain Discovery | `recon/subdomain.py` | Certificate transparency logs, DNS brute force |
| Technology Fingerprint | `recon/tech_fingerprint.py` | Headers, cookies, HTML patterns, JavaScript framework detection |
| Port Scanner | `recon/port_scan.py` | TCP connect scan (top-100/top-1000), banner grabbing, service identification |
| Subdomain Takeover | `recon/subdomain_takeover.py` | Dangling CNAME detection for 20+ services, NS delegation takeover check |

### Web Infrastructure (7 modules)

| Module | File | Techniques |
|--------|------|------------|
| Web Crawler | `web/crawler.py` | Recursive HTTP spidering, endpoint discovery, parameter extraction |
| Browser Crawler | `web/browser_crawler.py` | Playwright Chromium headless — network request interception, SPA route discovery via `framenavigated`, DOM link/form extraction, inline JS API pattern matching |
| Web Server Scan | `web/server_scan.py` | First-party `webscan` engine: headers, cookies, HTTP methods, exposed files, default pages, directory listings, diagnostics, backup artifacts |
| SSL/TLS | `web/ssl_tls.py` | Protocol version check, weak cipher detection, certificate analysis |
| Security Headers | `web/headers.py` | 7+ header checks (HSTS, CSP, X-Frame-Options, etc.), cookie flag analysis |
| CORS | `web/cors.py` | Wildcard origin, reflected origin, null origin, subdomain bypass, credential leak |
| HTTP Methods | `web/http_methods.py` | PUT/DELETE/TRACE/CONNECT enumeration, method override testing |

### Injection (10 modules)

| Module | File | Techniques |
|--------|------|------------|
| SQL Injection | `injection/sqli.py` | First-party `sqlprobe` engine: error, blind boolean, capped time, UNION-shape, safe stacked probes, request/Burp/bulk/crawl import, tamper/profile/cache/evidence support |
| NoSQL Injection | `injection/nosqli.py` | MongoDB operator injection ($gt, $ne, $regex, $where), JavaScript injection |
| Command Injection | `injection/cmdi.py` | Pipe, semicolon, backtick, $() with output-based and time-based detection |
| SSTI | `injection/ssti.py` | Jinja2, Twig, Freemarker, ERB, Mako template detection and exploitation |
| XXE | `injection/xxe.py` | Classic external entity, blind XXE, parameter entities, billion laughs detection |
| SSRF | `injection/ssrf.py` | Cloud metadata (AWS/GCP/Azure), internal scanning, IP encoding bypasses (octal, hex, IPv6), OAST blind detection via interactsh-client |
| LDAP Injection | `injection/ldap.py` | Filter injection, authentication bypass, blind boolean LDAP |
| Second-Order Injection | `injection/second_order.py` | Stored SQLi/XSS/SSTI via two-phase inject-then-trigger with canary markers |
| Open Redirect | `injection/open_redirect.py` | 25+ redirect parameter names, 12 bypass techniques (protocol-relative, encoding, backslash, null byte) |
| Header Injection | `injection/header_injection.py` | CRLF injection, HTTP response splitting, host header poisoning for password reset attacks |

### Authentication (7 modules)

| Module | File | Techniques |
|--------|------|------------|
| Session Management | `auth/session_mgmt.py` | Session timeout, fixation, hijacking, concurrent session testing |
| JWT Attacks | `auth/jwt_attacks.py` | None algorithm, claim tampering, key confusion (RS256→HS256), expiration checks |
| Brute Force | `auth/brute_force.py` | Account enumeration, lockout policy detection, rate limit testing |
| Password Policy | `auth/password_policy.py` | Complexity requirements, common password acceptance |
| OAuth/OIDC | `auth/oauth_attacks.py` | redirect_uri bypass (13+ techniques), state parameter validation, token leakage, scope escalation, PKCE bypass |
| MFA Bypass | `auth/mfa_bypass.py` | Direct endpoint access, OTP brute force, backup code abuse, race condition on validation |
| Login Macro | `auth/login_macro.py` | Playwright headed browser for interactive login recording; auto-login fallback with fill/click/wait steps; extracts cookies and localStorage tokens; seeds discovered endpoints from captured network traffic |

### Authorization (3 modules)

| Module | File | Techniques |
|--------|------|------------|
| IDOR | `authz/idor.py` | Numeric ID manipulation, UUID enumeration, cross-user access testing |
| Privilege Escalation | `authz/privilege_esc.py` | Vertical/horizontal escalation via parameter and path manipulation |
| RBAC Bypass | `authz/rbac_bypass.py` | Role injection, forced browsing, path normalization bypass |

### Client-Side (4 modules)

| Module | File | Techniques |
|--------|------|------------|
| XSS | `client_side/xss.py` | Reflected, stored indicators, DOM-based, context-aware detection, encoding bypasses |
| DOM XSS | `client_side/dom_xss.py` | Static: regex extraction of `<script>` blocks, source→sink proximity analysis. Dynamic (Playwright): 7 payload types injected via URL fragment and query params — img onerror, svg onload, iframe onload, details ontoggle |
| CSRF | `client_side/csrf.py` | Token absence/weakness, SameSite bypass, custom header bypass |
| Clickjacking | `client_side/clickjacking.py` | X-Frame-Options testing, CSP frame-ancestors analysis |

### API Security (4 modules)

| Module | File | Techniques |
|--------|------|------------|
| REST Discovery | `api/rest_discovery.py` | OpenAPI/Swagger detection (15+ common paths), GraphQL introspection, full endpoint seeding via `parse_api_spec` with `$ref` resolution and body examples |
| GraphQL | `api/graphql.py` | Introspection dump, query depth limits, batch query limits, field suggestion |
| API Fuzzer | `api/api_fuzzer.py` | Parameter type fuzzing, boundary values, method enumeration |
| Mass Assignment | `api/mass_assignment.py` | Privilege property injection (role, admin, is_staff), framework-specific payloads (Rails, Django, Node.js, Laravel) |

### Business Logic (3 modules)

| Module | File | Techniques |
|--------|------|------------|
| Rate Limiting | `logic/rate_limiting.py` | Rapid request burst testing, rate limit header analysis |
| Race Conditions | `logic/race_condition.py` | Concurrent request testing for double-spend, TOCTOU |
| Workflow Bypass | `logic/workflow_bypass.py` | Multi-step process skip, state manipulation |

### Cloud (2 modules)

| Module | File | Techniques |
|--------|------|------------|
| S3 Enumeration | `cloud/s3_enum.py` | Bucket naming patterns, public listing, permission testing |
| Cloud Metadata | `cloud/metadata.py` | IMDSv1/v2 access via SSRF, credential theft |

### File Handling (2 modules)

| Module | File | Techniques |
|--------|------|------------|
| File Upload | `file_handling/upload.py` | Extension bypass (double ext, null byte), MIME type confusion, magic byte injection |
| Path Traversal | `file_handling/path_traversal.py` | LFI with encoding bypasses (double URL encoding, UTF-8, null byte) |

### Advanced (7 modules)

| Module | File | Techniques |
|--------|------|------------|
| WAF Detection | `advanced/waf_detection.py` | Fingerprinting for 10 WAF vendors via response signature matching, encoding/obfuscation bypass testing |
| HTTP Smuggling | `advanced/http_smuggling.py` | CL.TE, TE.CL desync via raw sockets, TE.TE with 12 header obfuscation variants, CRLF request splitting |
| Cache Poisoning | `advanced/cache_poisoning.py` | Unkeyed header injection (10 headers), cache deception via path suffix, fat GET parameter cloaking |
| Deserialization | `advanced/deserialization.py` | Java (magic bytes, ysoserial endpoints), Python pickle, PHP unserialize, .NET ViewState, YAML constructor injection |
| Prototype Pollution | `advanced/prototype_pollution.py` | Server-side JSON body pollution (`__proto__`, `constructor.prototype`), client-side URL parameter pollution, gadget detection |
| DNS Rebinding | `advanced/dns_rebinding.py` | Host header validation assessment, IP binding check |
| WebSocket Security | `advanced/websocket_security.py` | CSWSH (origin validation), auth bypass, message injection, insecure transport, auto-discovery from JavaScript |

## Payload Library (326 payloads across 17 files)

| File | Payloads | Description |
|------|----------|-------------|
| `sqli.txt` | 20 | Error-based, UNION, time-based, blind boolean SQLi |
| `xss.txt` | 18 | Reflected XSS, encoding bypasses, event handlers, javascript: protocol |
| `ssti.txt` | 10 | Jinja2, Twig, Mako, ERB, Freemarker template payloads |
| `path_traversal.txt` | 16 | ../../../, encoding variants, Windows paths, null byte |
| `xxe.txt` | 18 | External entity, blind OOB, parameter entity, CDATA exfil, PHP/Java-specific |
| `nosqli.txt` | 13 | MongoDB operators ($gt, $ne, $regex, $where), URL-encoded variants |
| `cmdi.txt` | 24 | Pipe, semicolon, backtick, $(), blind via sleep/ping, argument injection |
| `ssrf.txt` | 23 | Cloud metadata (AWS/GCP/Azure/DO), IP encoding (octal, hex, IPv6), protocol tricks |
| `waf_bypass.txt` | 38 | Double encoding, Unicode, case mutation, nested tags, comment injection, null byte |
| `oauth.txt` | 20 | redirect_uri bypass (subdomain, encoding, fragment, protocol-relative, backslash) |
| `deserialization.txt` | 19 | Java gadget indicators, Python pickle, PHP objects, YAML constructors, Node.js |
| `smuggling.txt` | 27 | CL.TE/TE.CL probes, 12 TE obfuscation variants, CRLF sequences, H2 smuggling |
| `prototype_pollution.txt` | 15 | `__proto__` JSON injection, constructor.prototype, URL parameter variants |
| `websocket.txt` | 15 | XSS/SQLi/CMDi via WebSocket, oversized messages, admin channel subscribe |
| `ldap.txt` | 15 | Filter injection (*, )(, \00), auth bypass, attribute enumeration |
| `open_redirect.txt` | 25 | Protocol-relative, double encoding, null byte, @-bypass, backslash, data: URI |
| `header_injection.txt` | 10 | CRLF injection (%0d%0a), response splitting, Set-Cookie injection |

## Architecture

```
plugins/pencheff/
├── .mcp.json                        # MCP server launch config
├── .github/workflows/
│   └── pencheff-scan.yml            # GitHub Actions CI/CD workflow
└── pencheff/
    ├── __main__.py                  # CLI entry: serve | scan | history | compare
    ├── server.py                    # FastMCP server — 52 tools, 1 prompt
    ├── config.py                    # Constants, 6 compliance maps, 6 scan profiles
    ├── core/
    │   ├── session.py               # PentestSession state (endpoints, subdomains, tech
    │   │                            #   stack, WebSocket/OAuth endpoints, WAF info, chains)
    │   ├── credentials.py           # MaskedSecret, CredentialSet, CredentialStore
    │   ├── findings.py              # Finding model, CVSS scoring, deduplication,
    │   │                            #   SuppressReason enum, FindingsDB with lifecycle
    │   ├── http_client.py           # httpx wrapper: HTTP/1.1, HTTP/2, WebSocket, raw
    │   │                            #   sockets, credential injection, rate limiting
    │   ├── openapi_import.py        # OpenAPI 3.x / Swagger 2.0 / Postman v2.1 parser;
    │   │                            #   $ref resolution, body example generation
    │   ├── oast.py                  # OAST probe manager — interactsh-client, custom
    │   │                            #   OAST_HOST, or placeholder mode
    │   ├── scan_history.py          # Delta scanning — save/list/compare sessions;
    │   │                            #   fingerprint-based new/fixed/regressed tracking
    │   ├── ticketing.py             # GitHub Issues (gh CLI) + Jira REST API v3 export
    │   ├── payload_loader.py        # Centralized payload file loader
    │   ├── tool_runner.py           # Safe subprocess execution (no shell=True)
    │   └── dependency_manager.py   # Python/system tool availability (116 tools);
    │                                #   Playwright capability check
    ├── modules/
    │   ├── base.py                  # BaseTestModule ABC
    │   ├── recon/                   # 5 modules: DNS, subdomains, tech fingerprint,
    │   │                            #   port scan, subdomain takeover
    │   ├── web/                     # 6 modules: crawler, browser_crawler (Playwright),
    │   │                            #   SSL/TLS, headers, CORS, HTTP methods
    │   ├── injection/               # 10 modules: SQLi, NoSQLi, CMDi, SSTI, XXE,
    │   │                            #   SSRF (OAST-enabled), LDAP, second-order,
    │   │                            #   open redirect, header injection
    │   ├── auth/                    # 7 modules: session mgmt, JWT, brute force,
    │   │                            #   password policy, OAuth/OIDC, MFA bypass,
    │   │                            #   login_macro (Playwright)
    │   ├── authz/                   # 3 modules: IDOR, privilege escalation, RBAC bypass
    │   ├── client_side/             # 4 modules: XSS, DOM XSS (Playwright), CSRF,
    │   │                            #   clickjacking
    │   ├── api/                     # 4 modules: REST discovery (OpenAPI import),
    │   │                            #   GraphQL, API fuzzer, mass assignment
    │   ├── logic/                   # 3 modules: rate limiting, race conditions,
    │   │                            #   workflow bypass
    │   ├── cloud/                   # 2 modules: S3 enum, metadata service
    │   ├── file_handling/           # 2 modules: upload bypass, path traversal
    │   ├── advanced/                # 7 modules: WAF detection, HTTP smuggling,
    │   │                            #   cache poisoning, deserialization, prototype
    │   │                            #   pollution, DNS rebinding, WebSocket security
    │   ├── ad/                      # 4 modules: BloodHound, Certipy, CrackMapExec,
    │   │                            #   Impacket — AD attack path enumeration
    │   ├── mobile/                  # 5 modules: MobSF, apktool, manifest check,
    │   │                            #   jadx, secrets — Android/iOS static analysis
    │   └── asm/                     # 4 modules: continuous_discovery, cert_watch,
    │                                #   change_detection, asset_inventory — ASM
    ├── reporting/
    │   ├── cvss.py                  # CVSS v3.1 + CVSS v4.0 base score calculators
    │   ├── compliance.py            # 6-framework compliance summary (OWASP, PCI-DSS,
    │   │                            #   NIST, SOC 2, ISO 27001, HIPAA)
    │   ├── renderer.py              # Markdown and JSON report rendering
    │   └── exporter.py             # Word (.docx), CSV, JSON file export
    └── payloads/                    # 17 payload files, 326 total payloads
```

## How It Works

### Adaptive Intelligence

Every tool returns a structured response:

```json
{
  "findings": [...],
  "findings_summary": { "critical": 1, "high": 3, "medium": 5, "low": 2, "info": 4 },
  "next_steps": [
    "WAF detected: Cloudflare. Use payload_generate to create WAF-aware payloads.",
    "3 bypass techniques succeeded — use these for injection scans.",
    "Run scan_injection and scan_advanced with WAF-aware strategy."
  ]
}
```

The Pencheff engine reads these `next_steps` and decides what to test next. This feedback loop means Pencheff adapts to each target instead of running the same static checks every time.

### Exploitation-First Methodology

Pencheff doesn't just scan — it **hacks**. The agent follows 7 core rules:

1. **Verify, don't just scan** — After every scan tool, use `test_endpoint` or focused first-party probes to verify findings with harmless PoC payloads.
2. **Eliminate false positives** — Re-test with different payloads, confirm manually. An elite report has 5 verified criticals, not 50 unverified potentials.
3. **Chain everything** — Every finding is a building block. SSRF + cloud metadata = credential theft. XSS + weak sessions = account takeover. Use `exploit_chain_suggest` and `test_chain`.
4. **Go deep safely** — Don't stop at the first layer; prove impact with non-destructive evidence and avoid accessing secrets or executing destructive actions.
5. **Adapt to defenses** — WAF detected? Generate bypass payloads. Rate limited? Slow down and rotate.
6. **Use first-party engines first** — Use Pencheff map/recon_active for ports, Pencheff webscan/scan_infrastructure for web server exposure, Pencheff sqli/scan_injection for SQLi, and Pulse/scan_pulse for template scanning. Use auxiliary tools only where they add value.
7. **Manual hacking between scans** — Use `test_endpoint` to probe interesting behavior. Don't wait for a scan tool.

### Testing Phases (10)

The built-in `pentest_methodology` prompt guides the Pencheff engine through a comprehensive 10-phase assessment:

1. **Preparation** — Initialize session with `pentest_init`, verify tools, run Pencheff recon_active
2. **Reconnaissance** — Map full attack surface: DNS, subdomains, ports, tech stack, APIs. Use `subfinder`, `amass`, `whatweb`
3. **Infrastructure** — web server exposure, SSL/TLS, security headers, CORS, HTTP methods. Use `pencheff webscan`, `sslscan`, `testssl`
4. **Authentication** — Session management, JWT vulnerabilities, brute force resistance. Use `hydra` for credential testing
5. **WAF Detection** — Fingerprint WAF with `scan_waf` and `wafw00f` before injection testing
6. **Injection Warfare** — 10 injection types across all discovered endpoints. Use `scan_injection` and `pencheff sqli` for SQLi confirmation, verify every finding with `test_endpoint`
7. **Advanced Attacks** — HTTP smuggling, cache poisoning, deserialization, prototype pollution. Use `scan_pulse` for template-based detection
8. **API, Business Logic & Specialized** — GraphQL, mass assignment, race conditions, cloud, file handling, OAuth, MFA bypass, WebSocket, subdomain takeover
9. **Exploit Chain Analysis** — Automatic chain detection with `exploit_chain_suggest` + manual verification with `test_chain`
10. **Reporting** — CVSS-scored findings with 6-framework compliance mapping; export to Word/CSV/JSON; create GitHub Issues or Jira tickets

### OpenAPI / Swagger / Postman Import

`import_api_spec` parses API specification files and seeds all endpoints directly into the session, enabling full coverage without crawling:

```
# Import from a local file or URL
import_api_spec(session_id, content="<spec content>", base_url="https://api.example.com", hint="auto")
```

- **OpenAPI 3.x**: full `$ref` resolution, request body example generation, parameter typing
- **Swagger 2.0**: body parameter extraction, basePath resolution
- **Postman v2.1**: recursive folder traversal, variable substitution in URLs
- Returns `spec_type`, `title`, `version`, `endpoint_count`, and all endpoint details

### OAST — Blind Vulnerability Detection

Out-of-Band Application Security Testing detects vulnerabilities that produce no visible response change:

```
oast_init(session_id)         # registers with interactsh-client backend
oast_new_url(session_id, "ssrf-probe-1")  # → http://<probe_id>.oast.fun
# inject into target payload
oast_poll(session_id)         # returns any callbacks received
```

Backend priority:
1. **interactsh-client** (ProjectDiscovery) — if installed via `go install`
2. **`OAST_HOST` env var** — custom collaborator server
3. **Placeholder mode** — generates valid-looking URLs for payload construction; won't receive real callbacks

The SSRF module automatically generates and injects OAST HTTP and DNS callbacks alongside standard payloads.

### Delta Scanning

Track vulnerability lifecycle across scan sessions:

```
save_scan(session_id)                          # saves to ~/.pencheff/history/
compare_scans(session_id_a, session_id_b)      # baseline vs current
```

Compare output includes:
- **new_findings** — in current scan but not baseline (regressions)
- **fixed_findings** — in baseline but not current (resolved)
- **persisted** — present in both
- **regressions** — same finding but higher severity in current scan

Fingerprint: `endpoint|parameter|category|title`

### Finding Suppression Lifecycle

Manage noise and acknowledged risks without deleting findings:

| Reason | Meaning |
|--------|---------|
| `accepted_risk` | Known risk, business decision to accept |
| `wont_fix` | Acknowledged but not in remediation scope |
| `false_positive` | Scanner error — not actually vulnerable |
| `duplicate` | Same vulnerability already tracked elsewhere |
| `out_of_scope` | Valid finding but outside the agreed test scope |

Suppressed findings are excluded from `count`, reports, and exports by default. They persist with `suppressed_at` timestamp, reason, and notes. `unsuppress_finding` fully restores them.

### CVSS Scoring

Pencheff calculates scores for both versions:

**CVSS v3.1** — Full base score calculator using the official formula (Impact + Exploitability sub-scores, scope modifier). Every finding ships with a pre-calculated v3.1 vector and score.

**CVSS v4.0** — Base score calculator supporting the v4.0 metric groups:
- Attack Vector (AV), Attack Complexity (AC), Attack Requirements (AT)
- Privileges Required (PR), User Interaction (UI)
- Vulnerable System (VC/VI/VA), Subsequent System (SC/SI/SA)
- Uses the official EQ lookup table approach for scoring

```
calculate_cvss40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
# → { "score": 9.0, "severity": "Critical", "vector": "..." }
```

### Exploit Chain Analysis

The `exploit_chain_suggest` tool evaluates all findings against 14 chain rules:

| Chain | Components | Impact |
|-------|------------|--------|
| SSRF + Cloud Metadata | SSRF → metadata service → IAM credentials | Full cloud account compromise |
| XSS + Weak Sessions | XSS → session theft → account takeover | User compromise |
| Open Redirect + OAuth | Redirect → redirect_uri bypass → token theft | OAuth token theft |
| SQLi + Credential Reuse | SQLi → credential dump → admin login | Full application compromise |
| File Upload + Traversal | Upload bypass → path traversal → web shell | Remote code execution |
| HTTP Smuggling + Cache | Desync → cache poisoning → mass XSS | All users compromised |
| Prototype Pollution + XSS | `__proto__` pollution → gadget chain → stored XSS | Persistent XSS |
| Deserialization | Serialized object → gadget chain → RCE | Remote code execution |
| MFA Bypass + Auth | Skip 2FA → full authenticated access | Authentication bypass |
| Mass Assignment + Authz | Property injection → role escalation → admin | Privilege escalation |

### Compliance Mapping

Every finding automatically maps to all 6 frameworks based on vulnerability category:

| Framework | Controls |
|-----------|---------|
| **OWASP Top 10 2021** | A01–A10 category with full name |
| **PCI-DSS 4.0** | Requirements 2.2, 4.1, 6.2, 6.5.x, 6.6, 7.x, 8.x |
| **NIST 800-53** | AC, AU, CM, IA, SC, SI control families |
| **SOC 2** | Trust Services Criteria: CC6.x, CC7.x, A1.x |
| **ISO 27001:2022** | Annex A controls: A.5.x, A.8.x |
| **HIPAA Security Rule** | Safeguards: 164.308, 164.312 |

Reports include per-framework coverage summaries showing which OWASP categories and categories were tested.

### Verification Status

Every finding carries a `verification_status` field:

| Status | Meaning |
|--------|---------|
| `unverified` | Default — scan detected it, not yet manually verified |
| `true_positive` | Confirmed exploitable via `test_endpoint` |
| `false_positive` | Debunked — scan flagged it but manual testing shows it's safe |
| `true_negative` | Confirmed absent — tested and verified not present |
| `false_negative` | Missed by scanner — found via manual testing after scan reported clean |

Use `verify_finding` to set the status. All export formats include this field.

### Report Export Formats

The `export_report` tool saves findings to three formats simultaneously:

| Format | File | Use Case |
|--------|------|----------|
| **Word (.docx)** | `pencheff_report_<timestamp>.docx` | Professional report for stakeholders — formatted tables, severity colors, compliance mapping, remediation roadmap |
| **CSV** | `pencheff_findings_<timestamp>.csv` | Import into Jira, Linear, or spreadsheets — one row per finding with all fields including suppression and compliance |
| **JSON** | `pencheff_findings_<timestamp>.json` | Programmatic analysis, CI/CD integration, data pipelines |

All files saved to `~/pencheff-reports/<session_id>/` by default.

CSV columns include: `id`, `title`, `severity`, `cvss_score`, `cvss_vector`, `category`, `owasp`, `endpoint`, `parameter`, `cwe`, `verification_status`, `suppressed`, `suppress_reason`, `suppress_notes`, `pci_dss`, `nist`, `soc2`, `iso27001`, `hipaa`, `description`, `remediation`.

JSON export includes: all findings with full evidence, `suppressed_findings` list, and compliance summaries for all 6 frameworks.

### Ticketing Integration

**GitHub Issues** (requires `gh` CLI):
```
export_to_github(session_id, repo="myorg/myapp", severities=["critical","high"])
```
Each issue includes: severity label, `owasp:<category>` label, `security` label, full evidence, compliance mapping table, remediation steps.

**Jira** (requires `JIRA_URL`, `JIRA_TOKEN`, `JIRA_EMAIL` env vars):
```
export_to_jira(session_id, project_key="SEC", severities=["critical","high","medium"])
```
Issues created as Bugs with: priority mapping (critical→Highest, high→High, etc.), `security-<severity>` + `pentest` + `pencheff` labels, ADF-formatted description with endpoint, CVSS, CWE, OWASP, remediation.

Both support `dry_run=True` for preview without creating issues.

### HTTP Client Capabilities

The core `PencheffHTTPClient` provides:

- **HTTP/1.1 and HTTP/2** — configurable per session
- **WebSocket support** — via `websockets` library for WebSocket security testing
- **Raw socket connections** — via `asyncio.open_connection` for HTTP smuggling (sends malformed HTTP that httpx would refuse)
- **Rate limiting** — configurable max requests per second
- **Credential injection** — automatic header injection (Bearer, Basic, API key, Cookie, custom headers)
- **SSL verification toggle** — disabled by default for testing self-signed certs
- **Connection pooling** — max 20 connections, 10 keepalive
- **Request audit logging** — every request logged with method, URL, status, module, and duration

## Test Depth

| Depth | Description |
|-------|-------------|
| `quick` | Fast scan — common vulnerabilities only, fewer payloads |
| `standard` | Balanced coverage and speed (default) |
| `deep` | Thorough testing — all payloads, extended port ranges, full crawl |

## Dependencies

### Python (all required, auto-installed)

- `mcp[cli]` — MCP protocol SDK
- `httpx[http2]` — Async HTTP client (HTTP/1.1 and HTTP/2)
- `pydantic` — Data validation
- `pyjwt` — JWT token analysis
- `cryptography` — SSL/TLS and crypto operations
- `jinja2` — Report template rendering
- `pyyaml` — YAML parsing (OpenAPI YAML specs)
- `dnspython` — DNS enumeration
- `beautifulsoup4` + `lxml` — HTML parsing
- `anyio` — Async runtime
- `python-docx` — Word document generation
- `boto3` — AWS S3 bucket testing
- `paramiko` — SSH testing
- `websockets` — WebSocket security testing
- `h2` — HTTP/2 support
- `playwright` — Browser crawler, DOM XSS detection, login macro recording, authenticated crawl

After installing, run once to download the Chromium browser binary:

```bash
playwright install chromium
```

The agent will run this automatically if Chromium is not yet installed.

### OAST (recommended)

```bash
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

Used by the SSRF module and OAST tools to detect blind out-of-band callbacks. Without it, OAST runs in placeholder mode — payloads are constructed but callbacks won't be received. Set `OAST_HOST` env var to use a custom collaborator server instead.

## External Security Tools (116)

All 116 tools are allowlisted for execution via `run_security_tool`. Pencheff runs them with safe subprocess execution (no `shell=True`, array arguments only). Use `check_dependencies` to see which are installed.

### Network Scanning (10)

| Tool | Description |
|------|-------------|
| `ipscan` | Angry IP Scanner — fast IP address and port scanning |
| `fping` | Fast ICMP ping to multiple hosts simultaneously |
| `unicornscan` | Asynchronous TCP/UDP scanner for large networks |
| `netcat` | Port scanning, file transfer, reverse shells, banner grabbing |
| `masscan` | Ultra-fast port scanning (100K+ ports/sec) |
| `naabu` | Fast port scanner (ProjectDiscovery) — SYN/CONNECT scanning |
| `nessus` | Tenable vulnerability scanner — comprehensive network assessment |
| `hping3` | Packet crafting and analysis — firewall testing, idle scanning |

### Vulnerability Scanning (5)

| Tool | Description |
|------|-------------|
| `openvas` | Open Vulnerability Assessment Scanner |
| `gvm-cli` | Greenbone Vulnerability Management CLI |
| `skipfish` | Web app security recon with interactive sitemap |
| `vega` | Web vulnerability scanner — SQLi, XSS, sensitive data |

### Password Cracking (9)

| Tool | Description |
|------|-------------|
| `john` | John the Ripper — 100s of hash types |
| `hashcat` | GPU-accelerated password recovery — 300+ hash types |
| `rcrack` | RainbowCrack — precomputed rainbow table attacks |
| `aircrack-ng` | WiFi security suite — WEP/WPA/WPA2 cracking |
| `hydra` | Network login brute-forcer — 50+ protocols |
| `medusa` | Parallel network login brute-forcer |
| `l0phtcrack` | Password auditing — dictionary, brute-force, rainbow tables |
| `cowpatty` | WPA2-PSK brute-force cracking |
| `ophcrack` | Windows password cracker using rainbow tables |

### Exploitation (10)

| Tool | Description |
|------|-------------|
| `msfconsole` | Metasploit Framework — exploit development, post-exploitation |
| `msfvenom` | Metasploit payload generator — shellcode, executables, scripts |
| `msfdb` | Metasploit database management |
| `setoolkit` | Social-Engineer Toolkit — phishing, credential harvesting |
| `beef-xss` | Browser Exploitation Framework — XSS targeting browser sessions |
| `armitage` | Graphical Metasploit frontend |
| `zap-cli` | OWASP ZAP CLI — automated web security scanning |
| `zaproxy` | OWASP Zed Attack Proxy |
| `commix` | Automated OS command injection exploiter |

### Packet Sniffing & Spoofing (9)

| Tool | Description |
|------|-------------|
| `tshark` | Wireshark CLI — deep packet inspection |
| `tcpdump` | Command-line packet analyzer |
| `ettercap` | MitM attack suite — ARP spoofing, DNS spoofing |
| `bettercap` | Network attack Swiss Army knife — WiFi, BLE, Ethernet MitM |
| `snort` | Intrusion detection/prevention system |
| `ngrep` | Network grep — pattern-matching packet analyzer |
| `nemesis` | Packet crafting and injection |
| `scapy` | Interactive packet manipulation |
| `dsniff` | Password sniffer — network auditing |

### Wireless Hacking (7)

| Tool | Description |
|------|-------------|
| `wifite` | Automated wireless auditing — WEP/WPA/WPS attacks |
| `kismet` | Wireless detector, sniffer, IDS — WiFi, Bluetooth, Zigbee, RF |
| `reaver` | WPS brute-force — recover WPA/WPA2 passphrases |
| `bully` | WPS brute-force (C-based) |
| `wifiphisher` | Rogue AP framework — WiFi phishing |
| `hostapd-wpe` | Rogue RADIUS server for WPA2-Enterprise attacks |
| `mdk4` | WiFi testing — beacon flooding, deauth, WDS confusion |

### Directory / Path Brute Force (6)

| Tool | Description |
|------|-------------|
| `ffuf` | Fast web fuzzer — directory brute force, parameter fuzzing, vhost discovery |
| `gobuster` | Directory/DNS/vhost brute-force — fast, Go-based |
| `dirb` | Web content scanner — recursive directory brute force |
| `wfuzz` | Web fuzzer — headers, POST data, URLs, authentication |
| `feroxbuster` | Recursive content discovery — smart wordlists, auto-filtering |
| `dirsearch` | Web path brute-forcer with recursive scanning |

### Web Application Hacking (5)

| Tool | Description |
|------|-------------|
| `whatweb` | Web technology fingerprinting — CMS, frameworks, servers |
| `wafw00f` | WAF fingerprinting — identifies 100+ WAF products |
| `wpscan` | WordPress vulnerability scanner — plugins, themes, users |
| `dalfox` | XSS scanner with DOM analysis and parameter mining |
| `xsstrike` | Advanced XSS detection — fuzzing, crawling, context analysis |

### Subdomain Enumeration (7)

| Tool | Description |
|------|-------------|
| `subfinder` | Passive subdomain discovery (ProjectDiscovery) — 30+ sources |
| `amass` | OWASP attack surface mapping — active/passive subdomain enumeration |
| `fierce` | DNS reconnaissance — subdomain brute-forcing |
| `dnsrecon` | DNS enumeration — zone transfers, brute force, cache snooping |
| `sublist3r` | Subdomain enumeration via search engines |
| `knockpy` | Subdomain scanner with takeover detection |
| `dnsenum` | DNS enumeration — subdomains, MX, NS, zone transfers |

### DNS Tools (3)

| Tool | Description |
|------|-------------|
| `dig` | DNS lookups with full record control |
| `whois` | Domain registration info — registrar, nameservers, dates |
| `host` | Simple DNS lookup — forward and reverse |

### SSL/TLS Testing (4)

| Tool | Description |
|------|-------------|
| `sslscan` | SSL/TLS scanner — cipher suites, protocols, certificate analysis |
| `testssl` | Comprehensive SSL/TLS testing — BEAST, POODLE, Heartbleed |
| `sslyze` | Fast SSL/TLS scanner — certificate validation, protocol support |
| `openssl` | SSL/TLS cryptography toolkit |

### OSINT / Social Engineering (9)

| Tool | Description |
|------|-------------|
| `theHarvester` | OSINT — emails, subdomains, IPs from public sources |
| `maltego` | OSINT and link analysis — 100s of data sources |
| `recon-ng` | Web reconnaissance framework — modular OSINT collection |
| `sherlock` | Username enumeration across 400+ social networks |
| `spiderfoot` | Automated OSINT collection — 200+ data sources |
| `gophish` | Phishing campaign toolkit |
| `king-phisher` | Phishing simulation — credential harvesting |
| `evilginx2` | MitM framework — session cookie theft, 2FA bypass |
| `social-engineer-toolkit` | SET — social engineering attack framework |

### Digital Forensics (8)

| Tool | Description |
|------|-------------|
| `autopsy` | Digital forensics platform — disk image analysis |
| `foremost` | File recovery/carving for forensic analysis |
| `scalpel` | Fast file carver — improved Foremost |
| `fls` | The Sleuth Kit — list files in disk images |
| `mmls` | The Sleuth Kit — partition layout display |
| `icat` | The Sleuth Kit — extract file content from images |
| `volatility` | Memory forensics framework — RAM analysis |
| `binwalk` | Firmware analysis — extract embedded files and code |

### Post-Exploitation / Credentials (10)

| Tool | Description |
|------|-------------|
| `mimikatz` | Windows credential extraction — pass-the-hash, pass-the-ticket |
| `crackmapexec` | Post-exploitation — SMB, LDAP, WinRM, MSSQL credential testing |
| `impacket-secretsdump` | Dump NTLM hashes, Kerberos tickets from DC |
| `impacket-psexec` | Remote command execution via SMB |
| `impacket-smbexec` | SMB-based remote execution |
| `impacket-wmiexec` | WMI-based remote execution |
| `responder` | LLMNR/NBT-NS/MDNS poisoner — credential capture on LAN |
| `enum4linux` | SMB/Windows enumeration — shares, users, groups, policies |
| `smbclient` | SMB client — connect to file shares |
| `pcredz` | Credential extraction from PCAP files — 20+ protocols |

### Web Proxy / API Testing (3)

| Tool | Description |
|------|-------------|
| `curl` | HTTP requests — full protocol control, auth, proxies |
| `wget` | HTTP downloader — recursive website mirroring |
| `httpx-toolkit` | HTTP probing (ProjectDiscovery) — tech detection, status codes |

### Static Analysis / Secret Scanning (4)

| Tool | Description |
|------|-------------|
| `semgrep` | Static analysis — 5000+ rules across 30+ languages |
| `bandit` | Python security analysis |
| `trufflehog` | Secret scanning — git repos, S3 buckets, filesystem |
| `git-dumper` | Extract git repositories from misconfigured web servers |

### Miscellaneous (4)

| Tool | Description |
|------|-------------|
| `interactsh-client` | OAST out-of-band callback detection (ProjectDiscovery) — blind SSRF/SQLi/XSS |
| `gau` | URL discovery from web archives — AlienVault, Wayback, CommonCrawl |
| `waybackurls` | Fetch URLs from Wayback Machine |
| `xsser` | Cross-site scripting framework — automated XSS exploitation |

## Benchmarks

Pencheff is measured against OWASP Juice Shop (ZAP baseline) with reproducible results:

| Metric | Pencheff (agent) | ZAP baseline |
|--------|----------------:|-------------:|
| Findings reported (after triage) | **22** | 10 alert classes |
| False positives suppressed | **31** (AI review) | 0 |
| Critical/High/Medium | 0 / 2 / 14 | 0 / 0 / 0 |
| Executive summary (CVSS + CWE) | ✅ | ❌ |

Full run log, per-finding evidence, and raw CSVs: [`bench/results/2026-04-18-summary.md`](bench/results/2026-04-18-summary.md)

To reproduce: `bash bench/run_all.sh all` (requires Juice Shop on port 3001, Docker).

## Pricing

Pencheff follows an open-core model.

| Tier | Cost | What's included |
|------|------|-----------------|
| **Free** | $0 | All 52+ MCP tools, all attack modules, full CLI, GitHub Actions / GitLab CI / Azure DevOps integrations, self-hosted deployment, SAST + DAST + SCA + IaC + secrets in one engagement |
| **Pro** | See [pencheff.com/pricing](https://pencheff.com/pricing) | Autonomous AI layer: per-finding AI triage walkthroughs, automated false-positive grading, executive-grade audit attestation, agent-driven adaptive scanning, fix proposals |

The deterministic security core — every scanner, every payload, every report format — will always be free. Pro adds the AI reasoning layer on top.

## Recommended Test Targets

For testing Pencheff, use intentionally vulnerable applications:

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — `docker run -p 3000:3000 bkimminich/juice-shop`
- [DVWA](https://github.com/digininja/DVWA) — `docker run -p 80:80 vulnerables/web-dvwa`
- [WebGoat](https://owasp.org/www-project-webgoat/) — `docker run -p 8080:8080 webgoat/webgoat`

**Never run penetration tests against systems you do not own or have explicit written authorization to test.**

## License

MIT — see [LICENSE](LICENSE). For third-party tools, models, dependencies,
and trademark notices, see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Brand assets

The Pencheff name and the "P" mark used in `apps/web/public/logo.png` and
`apps/docs/public/logo.png` are first-party Pencheff brand assets, distributed
under the MIT license alongside the rest of this repository.

## Author

**Bala Sriharsha** — [github.com/BalaSriharsha-Ch](https://github.com/BalaSriharsha-Ch)

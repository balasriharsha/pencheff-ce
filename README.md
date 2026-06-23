# Pencheff Community Edition

Open-source, self-hosted security scanning and penetration testing platform.

## What it is

Pencheff CE is a single-user, self-hostable security platform. There are no accounts, no login screen, no billing, and no multi-tenant concepts. You run it locally or on your own server; the dashboard is available immediately at `http://localhost:3000`.

- **No authentication required** — one implicit user, no sign-up or login flow.
- **No multi-tenancy** — single workspace, no orgs/teams management.
- **Full scan engine** — reconnaissance, vulnerability scanning, injection testing, exploit chain analysis, OAST callbacks, CVSS v4.0 scoring, compliance mapping (OWASP Top 10, PCI-DSS 4.0, NIST 800-53, SOC 2, ISO 27001, HIPAA).
- **MCP plugin** — 52 pentest tools available as an MCP server for AI-driven agents.
- **Reports** — export findings to Word, CSV, or JSON.
- **Optional AI features** — bring your own LLM key; without it, all scan and reporting features work normally.

## Quickstart

```bash
# 1. Copy the environment files
cp .env.example .env
cp apps/api/.env.example apps/api/.env   # if the api env file is missing

# 2. Build and start
docker compose up --build

# 3. Open the dashboard
open http://localhost:3000
```

The stack starts:

| Service  | Port | Description             |
| -------- | ---- | ----------------------- |
| web      | 3000 | Static Next.js frontend |
| api      | 8000 | FastAPI backend         |
| worker   | —    | Celery task worker      |
| postgres | 5432 | Database                |
| redis    | 6379 | Queue / cache           |

A smoke test is available at `scripts/smoke.sh` to verify the stack is healthy.

### Fernet key

`FERNET_KEY` in `apps/api/.env` auto-generates on first start if left blank. Set it explicitly if you want a stable key across container restarts.

## Configuration

All configuration is via environment variables in `.env` (root) and `apps/api/.env`.

### Optional: AI features

Set `LLM_API_KEY` (and optionally `LLM_BASE_URL` / `LLM_MODEL`) in `apps/api/.env` to enable AI-assisted triage, grading, and the autonomous scan stage. Without it, all scan and reporting features work; only the AI-specific paths are disabled. Check `GET /capabilities/ai` to see which AI features are active.

### Optional: Integrations

Integrations (Slack, Jira, webhooks, etc.) are off by default. Enable with:

```
INTEGRATIONS_ENABLED=true
```

### Optional: Observability

OpenTelemetry ingest is off by default. Enable with:

```
OBSERVABILITY_INGEST_ENABLED=true
```

## Architecture

```
docker compose
├── web      — Next.js static export, served on :3000
├── api      — FastAPI app on :8000 (REST + WebSocket + SSE)
├── worker   — Celery worker, shares the api image
├── postgres — primary data store
└── redis    — task queue and pub/sub
```

The web frontend proxies API calls through `/api` to the FastAPI backend. The worker picks up scan jobs and long-running tasks from the Redis queue.

## Community Edition scope

This is the open-source community edition. The following are intentionally absent:

- No login / authentication / SSO
- No multi-tenant orgs or workspaces
- No billing or plan metering
- No engagement workbench (multi-analyst, multi-day campaign tracking)

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

Third-party component notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

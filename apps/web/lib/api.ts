"use client";

const API = process.env.NEXT_PUBLIC_API_URL || "/api";

/**
 * Separate base URL for server-sent events. Next.js' built-in ``rewrites``
 * proxy buffers streaming responses, so SSE ticks get delivered in bursts
 * rather than live. When this env is set to the API host directly (e.g.
 * ``http://localhost:8000``) the browser opens the EventSource against the
 * API and streams arrive in real time. CORS is already configured on the
 * API side via ``ALLOWED_ORIGINS``.
 */
const STREAM_API = process.env.NEXT_PUBLIC_API_DIRECT_URL || API;

type ClerkSession = {
  getToken: (opts?: { template?: string }) => Promise<string | null>;
};
type ClerkGlobal = {
  loaded?: boolean;
  load?: () => Promise<void>;
  session?: ClerkSession | null;
};

/**
 * Retrieve the current Clerk session JWT (if any). Used as the Authorization
 * bearer for backend calls and as a query-param token for SSE streams.
 *
 * Tokens are memoized in-process for ~50s. Pages that fan out 3+ parallel
 * fetches (dashboard, /repos) used to round-trip Clerk's WebCrypto-backed
 * getToken() call once per fetch — typically 80–250ms each — which serialised
 * the page load. Sharing a single in-flight Promise lets concurrent callers
 * await the same Clerk lookup, and the resolved token is reused until just
 * before its 60s default lifetime.
 */
const TOKEN_TTL_MS = 50_000;
let cachedToken: { value: string | null; expiresAt: number } | null = null;
let inflight: Promise<string | null> | null = null;

async function getAuthToken(): Promise<string | null> {
  if (typeof window === "undefined") return null;
  const now = Date.now();
  if (cachedToken && cachedToken.expiresAt > now) {
    return cachedToken.value;
  }
  if (inflight) return inflight;

  inflight = (async () => {
    try {
      const clerk = (window as unknown as { Clerk?: ClerkGlobal }).Clerk;
      if (!clerk) return null;
      if (!clerk.loaded && clerk.load) {
        try {
          await clerk.load();
        } catch {
          return null;
        }
      }
      try {
        const tok = (await clerk.session?.getToken?.()) ?? null;
        cachedToken = { value: tok, expiresAt: Date.now() + TOKEN_TTL_MS };
        return tok;
      } catch {
        return null;
      }
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

/**
 * Drop any cached JWT — call this on sign-out or when the API returns 401
 * for the current session, so the next request forces a fresh token.
 */
export function clearAuthTokenCache(): void {
  cachedToken = null;
  inflight = null;
}

/**
 * Key used by the WorkspaceProvider to persist the currently-active
 * workspace. Read at request time so every ``api()`` call automatically
 * sends ``X-Workspace-Id`` without per-component plumbing.
 */
export const ACTIVE_WORKSPACE_STORAGE_KEY = "pencheff.activeWorkspaceId";
export const ACTIVE_ORG_STORAGE_KEY = "pencheff.activeOrgId";
// Last-used "Written authorization statement" — prefilled into the
// commission-scan modal so operators don't retype the engagement-letter
// boilerplate on every assessment. Per-device, captured on successful
// scan submit only (we don't persist abandoned drafts).
export const AUTHORIZATION_STATEMENT_STORAGE_KEY = "pencheff.lastAuthorizationStatement";

function getActiveWorkspaceId(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(ACTIVE_WORKSPACE_STORAGE_KEY);
  } catch {
    return null;
  }
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit & { json?: unknown; direct?: boolean } = {}
): Promise<T> {
  const { direct, json, ...fetchInit } = init;
  // Slow LLM-backed endpoints should bypass the Next.js rewrite proxy,
  // which buffers responses and drops idle sockets after ~30s with
  // ECONNRESET. Set ``direct: true`` to hit the API host over CORS
  // instead.
  const base = direct ? STREAM_API : API;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(fetchInit.headers as Record<string, string> | undefined),
  };
  const tok = await getAuthToken();
  if (tok) headers["Authorization"] = `Bearer ${tok}`;
  // Scope every request to the currently-active workspace. The backend
  // looks up the workspace via get_active_workspace() and reject any ID
  // the caller isn't a member of.
  const ws = getActiveWorkspaceId();
  if (ws && !headers["X-Workspace-Id"]) headers["X-Workspace-Id"] = ws;

  const res = await fetch(`${base}${path}`, {
    ...fetchInit,
    headers,
    body: json !== undefined ? JSON.stringify(json) : fetchInit.body,
  });

  if (res.status === 401) {
    // If Clerk says we're signed in, the 401 is a backend authorisation
    // problem, not a missing session — surface it rather than bouncing to
    // /login (which would just re-authenticate with Clerk and loop).
    // Either way, evict the cached JWT so the next call picks up a fresh
    // one (the previous token may have expired between cache and use).
    clearAuthTokenCache();
    const clerk = (window as unknown as { Clerk?: { session?: unknown } })
      .Clerk;
    if (!clerk?.session && typeof window !== "undefined") {
      window.location.href = "/login";
    }
    throw new Error("unauthorized");
  }
  if (!res.ok) throw await apiError(res);
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return (await res.json()) as T;
  return (await res.text()) as unknown as T;
}

/**
 * Error thrown for any non-2xx (except 401) response. Callers can read the
 * structured ``body`` and the HTTP ``status`` to handle specific failures
 * (e.g. 402 with ``detail.reason`` for PAYG confirmation prompts) without
 * having to grep the human-readable message.
 */
export class ApiError extends Error {
  status: number;
  body: { detail?: string | Record<string, unknown> } | null;
  constructor(status: number, message: string, body: ApiError["body"]) {
    super(message);
    this.status = status;
    this.body = body;
    this.name = "ApiError";
  }
}

async function apiError(res: Response): Promise<ApiError> {
  let body: ApiError["body"] = null;
  let msg = `${res.status} ${res.statusText}`;
  try {
    body = await res.json();
    const detail = body?.detail;
    if (detail) {
      if (typeof detail === "string") {
        msg = detail;
      } else if (typeof detail === "object") {
        const d = detail as { message?: unknown; reason?: unknown };
        if (typeof d.message === "string") msg = d.message;
        else if (typeof d.reason === "string") msg = d.reason;
        else msg = JSON.stringify(detail);
      }
    }
  } catch {}
  return new ApiError(res.status, msg, body);
}

/**
 * Build a streaming (SSE) URL with the Clerk session token embedded as a
 * query parameter — EventSource cannot set Authorization headers.
 */
export async function streamUrl(path: string): Promise<string> {
  const tok = (await getAuthToken()) ?? "";
  const ws = getActiveWorkspaceId();
  const sep = path.includes("?") ? "&" : "?";
  const base = `${STREAM_API}${path}${sep}token=${encodeURIComponent(tok)}`;
  return ws ? `${base}&workspace_id=${encodeURIComponent(ws)}` : base;
}

/**
 * Authenticated file download. A plain ``window.location.href`` navigation
 * can't attach the Clerk bearer token, so we fetch the bytes with auth and
 * stream them to the user via an object URL + anchor click.
 */
export async function downloadFile(path: string, suggestedName?: string): Promise<void> {
  const tok = await getAuthToken();
  const res = await fetch(`${API}${path}`, {
    headers: tok ? { Authorization: `Bearer ${tok}` } : {},
  });
  if (!res.ok) {
    throw await apiError(res);
  }
  const blob = await res.blob();
  const name =
    suggestedName ??
    parseFilenameFromContentDisposition(
      res.headers.get("content-disposition")
    ) ??
    path.split("/").pop() ??
    "download";

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Next tick so Safari / Firefox have time to begin the download.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function parseFilenameFromContentDisposition(value: string | null): string | null {
  if (!value) return null;
  const match = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(value);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1].replace(/"$/g, ""));
  } catch {
    return match[1];
  }
}

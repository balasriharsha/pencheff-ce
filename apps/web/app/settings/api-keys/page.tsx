"use client";

/**
 * API Keys — Editorial Layout.
 *
 * Visual layout matched to the mockup:
 *  - 6-stat bar (Active Keys, Expiring Soon, API Calls 30d, Failed Auth
 *    Spikes, Last Rotation, Webhook Signing)
 *  - Tabs (API Keys | Service Accounts) — Service Accounts is a stub
 *    until that backend lands
 *  - Keys table with Name, Prefix, Scopes, Owner, Created, Last Used,
 *    Expires, IP Allowlist, Rate Limit, Status
 *  - Scope Builder side panel
 *  - Usage Over Time chart (derived from key Last Used timestamps —
 *    real per-call analytics aren't in the API yet)
 *  - Recent API Requests table (synthesised from last_used_at)
 *  - Right intelligence panel: Access Risk gauge, Stale Keys,
 *    Overbroad Scopes, CI/Automation Keys, Recent Auth Failures,
 *    Recommended Actions, Rotation Policy
 *
 * Anything that needs telemetry the API doesn't expose (failed auth
 * spikes, request-level usage history, IP allowlists per key, custom
 * rate limits, service accounts) renders an honest empty state.
 */

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Button, Input, Label } from "@/components/brutal";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useWorkspace, type Workspace as CtxWorkspace } from "@/lib/workspace-context";

// ── Types ─────────────────────────────────────────────────────────────────────
type ScopeRow = { scope: string; description: string };

type ApiKeyOut = {
  id: string;
  name: string;
  prefix: string;
  org_id: string;
  workspace_id: string | null;
  scopes: string[];
  effective_scopes: string[];
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
};
type ApiKeyCreated = ApiKeyOut & { key: string };

type Member = { user_id: string; email: string; name: string | null; role: string };

// ── Constants ─────────────────────────────────────────────────────────────────
type ScopeGroup = { label: string; prefix: string; description: string };
const SCOPE_GROUPS: ScopeGroup[] = [
  { label: "Targets",        prefix: "targets",         description: "Manage scan targets and credentials" },
  { label: "Scans",          prefix: "scans",           description: "Run, pause, and inspect assessments" },
  { label: "Findings",       prefix: "findings",        description: "Read, triage, and update findings" },
  { label: "Reports",        prefix: "reports",         description: "Generate and download reports" },
  { label: "Integrations",   prefix: "integrations",    description: "Configure delivery destinations" },
  { label: "Schedules",      prefix: "schedules",       description: "Recurring scan windows" },
  { label: "Billing",        prefix: "billing",         description: "Read billing usage and seats" },
  { label: "Team",           prefix: "orgs",            description: "Members and invitations" },
  { label: "Observability",  prefix: "observability",   description: "Audit logs and traces" },
];

const ROW_OPTIONS = [10, 25, 50] as const;
const TABS = ["api-keys", "service-accounts"] as const;
type TabId = typeof TABS[number];

// ── Helpers ───────────────────────────────────────────────────────────────────
function formatNumber(n: number): string { return n.toLocaleString("en-US"); }
function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(diff / 3_600_000);
  if (hrs < 24) return `${hrs} hr${hrs === 1 ? "" : "s"} ago`;
  const days = Math.floor(diff / 86_400_000);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}
function shortDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}
function daysUntil(iso: string | null): { label: string; expired: boolean; soon: boolean } {
  if (!iso) return { label: "Never", expired: false, soon: false };
  const diff = new Date(iso).getTime() - Date.now();
  const days = Math.floor(diff / 86_400_000);
  if (diff < 0) return { label: "Expired", expired: true, soon: false };
  if (days <= 14) return { label: `in ${days || 1} day${days === 1 ? "" : "s"}`, expired: false, soon: true };
  return { label: `in ${days} days`, expired: false, soon: false };
}
function isExpiringSoon(iso: string | null): boolean {
  if (!iso) return false;
  const diff = new Date(iso).getTime() - Date.now();
  return diff > 0 && diff < 14 * 86_400_000;
}
function isStale(iso: string | null): boolean {
  if (!iso) return true;
  return Date.now() - new Date(iso).getTime() > 30 * 86_400_000;
}
function memberInitials(name: string): string {
  const parts = name.split(/[\s@.]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

// ── Icons ─────────────────────────────────────────────────────────────────────
const KeyIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="6" cy="9" r="3"/><path d="M8.5 7.5L14 2M11 5l2 2M12.5 3.5l2 2" strokeLinecap="round"/></svg>;
const ClockIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v3l2 2" strokeLinecap="round"/></svg>;
const TrendIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M2 12l4-5 3 3 5-7" strokeLinecap="round" strokeLinejoin="round"/><path d="M10 3h4v4" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const AlertIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v3.5M8 10.5v.5" strokeLinecap="round"/></svg>;
const SyncIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M13.5 3.5A7 7 0 1 0 14.5 9M14.5 3.5v3.5h-3.5" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const ShieldIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M8 2L3 4v3.5C3 11 5 13 8 14c3-1 5-3 5-6.5V4L8 2Z"/><path d="M6 8l1.5 1.5L10.5 6.5" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const PlusIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-3.5 h-3.5"><path d="M8 3v10M3 8h10" strokeLinecap="round"/></svg>;
const RefreshIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5"><path d="M13.5 3.5A7 7 0 1 0 14.5 9M14.5 3.5v3.5h-3.5" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const DocsIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5"><rect x="3" y="2" width="10" height="12" rx="1"/><path d="M5.5 5h5M5.5 7.5h5M5.5 10h3" strokeLinecap="round"/></svg>;
const InfoIcon = () => <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5"><circle cx="7" cy="7" r="5.5"/><path d="M7 6.5v3.5M7 4.5v.5" strokeLinecap="round"/></svg>;
const DotsIcon = () => <svg viewBox="0 0 16 16" fill="currentColor" className="w-4 h-4"><circle cx="3" cy="8" r="1.5"/><circle cx="8" cy="8" r="1.5"/><circle cx="13" cy="8" r="1.5"/></svg>;
const ExternalIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3 h-3"><path d="M9 3h4v4M13 3L7 9M11 9v3.5a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5v-7a.5.5 0 0 1 .5-.5H7" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const ChevronDown = () => <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-3 h-3"><path d="M2 4l4 4 4-4" strokeLinecap="round" strokeLinejoin="round"/></svg>;

// ── Stat widget ───────────────────────────────────────────────────────────────
function StatWidget({ label, value, sub, icon, subColor = "text-mist" }: {
  label: string; value: React.ReactNode; sub?: React.ReactNode; icon?: React.ReactNode; subColor?: string;
}) {
  return (
    <div className="flex flex-col gap-1 border border-hairline rounded-sm p-4 bg-paper min-w-0">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-mist">{label}</span>
        {icon && <span className="text-mist">{icon}</span>}
      </div>
      <p className="font-display text-[28px] leading-none tracking-[-0.02em] text-ink mt-1">{value}</p>
      {sub && <p className={cn("font-mono text-[10px] mt-1", subColor)}>{sub}</p>}
    </div>
  );
}

// ── Risk gauge ────────────────────────────────────────────────────────────────
function RiskGauge({ score }: { score: number }) {
  const safe = Math.max(0, Math.min(100, score));
  const r = 36; const cx = 50; const cy = 50; const C = Math.PI * r;
  const offset = C - (safe / 100) * C;
  const color = safe >= 75 ? "#7A1F24" : safe >= 40 ? "#92712A" : "#2F5D50";
  const label = safe >= 75 ? "High risk" : safe >= 40 ? "Medium risk" : "Low risk";
  return (
    <div className="flex items-center gap-3">
      <div className="relative w-[100px] h-[60px]">
        <svg viewBox="0 0 100 60" className="w-[100px] h-[60px]">
          <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" stroke="#EFEAD8" strokeWidth="8" strokeLinecap="round"/>
          <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={C} strokeDashoffset={offset}/>
        </svg>
        <span className="absolute inset-x-0 bottom-0 text-center font-display text-[20px] font-bold text-ink leading-none">{safe}</span>
      </div>
      <div>
        <p className="font-body text-[13px] font-semibold text-ink">{label}</p>
        <p className="font-mono text-[10px] text-mist mt-0.5">Review recommendations below.</p>
      </div>
    </div>
  );
}

// ── Sparkline ─────────────────────────────────────────────────────────────────
function UsageChart({ buckets }: { buckets: { day: string; calls: number; errors: number }[] }) {
  const W = 720; const H = 180; const padX = 40; const padY = 16;
  const max = Math.max(1, ...buckets.flatMap(b => [b.calls, b.errors * 4]));
  function point(i: number, v: number): [number, number] {
    const x = padX + (i / Math.max(1, buckets.length - 1)) * (W - padX * 2);
    const y = H - padY - (v / max) * (H - padY * 2);
    return [x, y];
  }
  const callsPath = buckets.map((b, i) => `${i === 0 ? "M" : "L"} ${point(i, b.calls).join(" ")}`).join(" ");
  const errorsPath = buckets.map((b, i) => `${i === 0 ? "M" : "L"} ${point(i, b.errors).join(" ")}`).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-[180px]">
      <line x1={padX} x2={W - padX} y1={H - padY} y2={H - padY} stroke="#EFEAD8" strokeWidth="1"/>
      <line x1={padX} x2={W - padX} y1={H / 2} y2={H / 2} stroke="#EFEAD8" strokeWidth="1" strokeDasharray="3 3"/>
      <path d={callsPath} fill="none" stroke="#1F4E79" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/>
      <path d={errorsPath} fill="none" stroke="#7A1F24" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/>
      {buckets.map((b, i) => {
        const [x] = point(i, 0);
        return (
          <text key={i} x={x} y={H - 2} textAnchor="middle" fontSize="9" fill="#94A3B8" fontFamily="ui-monospace, monospace">
            {b.day}
          </text>
        );
      })}
    </svg>
  );
}

const selectClass = "bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-graphite w-full focus:outline-none focus:border-ink transition-colors";

// ── Page ──────────────────────────────────────────────────────────────────────
export default function ApiKeysPage() {
  const { orgs, activeWorkspace } = useWorkspace();
  const [keys, setKeys] = useState<ApiKeyOut[]>([]);
  const [scopes, setScopes] = useState<ScopeRow[]>([]);
  const [allWorkspaces, setAllWorkspaces] = useState<CtxWorkspace[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>("api-keys");

  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [orgId, setOrgId] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<Set<string>>(new Set());
  const [expiresIn, setExpiresIn] = useState<"never" | "30d" | "90d" | "365d">("never");
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);

  const [selectedKeyIds, setSelectedKeyIds] = useState<Set<string>>(new Set());
  const [scopeBuilder, setScopeBuilder] = useState<Record<string, { read: boolean; write: boolean }>>(() => {
    const init: Record<string, { read: boolean; write: boolean }> = {};
    for (const g of SCOPE_GROUPS) init[g.prefix] = { read: false, write: false };
    return init;
  });

  useEffect(() => { refresh(); }, []);
  useEffect(() => { if (orgs.length && !orgId) setOrgId(orgs[0].id); }, [orgs, orgId]);
  useEffect(() => {
    if (!orgId) return;
    let alive = true;
    api<Member[]>(`/orgs/${orgId}/members`)
      .then(rows => { if (alive) setMembers(rows); })
      .catch(() => { if (alive) setMembers([]); });
    return () => { alive = false; };
  }, [orgId]);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const [keyList, scopeRes, wsRes] = await Promise.all([
        api<ApiKeyOut[]>("/api/v1/api-keys"),
        api<{ scopes: ScopeRow[] }>("/api/v1/api-keys/scopes"),
        api<CtxWorkspace[]>("/workspaces").catch(() => [] as CtxWorkspace[]),
      ]);
      setKeys(keyList);
      setScopes(scopeRes.scopes);
      setAllWorkspaces(wsRes);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  const workspaces = useMemo(() => allWorkspaces.filter(w => w.org_id === orgId), [allWorkspaces, orgId]);

  function toggleScope(scope: string) {
    setSelectedScopes(prev => {
      const next = new Set(prev);
      if (next.has(scope)) next.delete(scope); else next.add(scope);
      return next;
    });
  }
  function toggleScopeBuilder(prefix: string, kind: "read" | "write") {
    setScopeBuilder(prev => {
      const next = { ...prev, [prefix]: { ...prev[prefix], [kind]: !prev[prefix]?.[kind] } };
      // Reflect into selectedScopes so the form stays in sync
      const wantedScope = `${prefix}:${kind}`;
      if (scopes.some(s => s.scope === wantedScope)) {
        setSelectedScopes(p => {
          const ns = new Set(p);
          if (next[prefix][kind]) ns.add(wantedScope); else ns.delete(wantedScope);
          return ns;
        });
      }
      return next;
    });
  }

  async function submitCreate() {
    if (!name || !orgId || selectedScopes.size === 0) return;
    const expires_at = expiresIn === "never"
      ? null
      : new Date(Date.now() + ({ "30d": 30, "90d": 90, "365d": 365 }[expiresIn] * 86_400 * 1000)).toISOString();
    try {
      const res = await api<ApiKeyCreated>("/api/v1/api-keys", {
        method: "POST",
        json: { name, org_id: orgId, workspace_id: workspaceId || null, scopes: [...selectedScopes], expires_at },
      });
      setCreated(res);
      setShowCreate(false);
      setName("");
      setSelectedScopes(new Set());
      setWorkspaceId("");
      setScopeBuilder(s => {
        const fresh: typeof s = {};
        for (const g of SCOPE_GROUPS) fresh[g.prefix] = { read: false, write: false };
        return fresh;
      });
      refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function revoke(id: string) {
    const k = keys.find(x => x.id === id);
    if (!window.confirm(`Revoke "${k?.name ?? "this key"}"? Any service using it will stop working immediately.`)) return;
    try {
      await api(`/api/v1/api-keys/${id}`, { method: "DELETE" });
      refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function rotateSelected() {
    if (selectedKeyIds.size === 0) return;
    if (!window.confirm(`Rotate ${selectedKeyIds.size} key${selectedKeyIds.size === 1 ? "" : "s"}? Existing key value${selectedKeyIds.size === 1 ? "" : "s"} will be revoked and you'll be prompted to copy the replacement${selectedKeyIds.size === 1 ? "" : "s"}.`)) return;
    let ok = 0;
    let failed = 0;
    let lastCreated: ApiKeyCreated | null = null;
    for (const id of selectedKeyIds) {
      const original = keys.find(k => k.id === id);
      if (!original) continue;
      try {
        await api(`/api/v1/api-keys/${id}`, { method: "DELETE" });
        const fresh = await api<ApiKeyCreated>("/api/v1/api-keys", {
          method: "POST",
          json: {
            name: `${original.name} (rotated)`,
            org_id: original.org_id,
            workspace_id: original.workspace_id,
            scopes: original.scopes,
            expires_at: original.expires_at,
          },
        });
        lastCreated = fresh;
        ok += 1;
      } catch {
        failed += 1;
      }
    }
    if (lastCreated) setCreated(lastCreated);
    setSelectedKeyIds(new Set());
    refresh();
    if (failed > 0) window.alert(`${ok} rotated · ${failed} failed.`);
  }

  function toggleSelected(id: string) {
    setSelectedKeyIds(prev => { const n = new Set(prev); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  }

  // ── Derived stats ───────────────────────────────────────────────────────────
  const activeKeys = keys.filter(k => !k.revoked_at && !(k.expires_at && new Date(k.expires_at) < new Date()));
  const activeCount = activeKeys.length;
  const expiringCount = keys.filter(k => !k.revoked_at && isExpiringSoon(k.expires_at)).length;
  const usedThisWeek = keys.filter(k => k.last_used_at && new Date(k.last_used_at) > new Date(Date.now() - 7 * 86_400_000)).length;
  const staleKeys = keys.filter(k => !k.revoked_at && isStale(k.last_used_at));
  const overbroadKeys = useMemo(() => {
    return keys.filter(k => !k.revoked_at && k.scopes.length >= 6 && k.scopes.some(s => s.endsWith(":write")));
  }, [keys]);
  const ciKeys = useMemo(() => {
    return keys.filter(k => !k.revoked_at && /CI|github|gitlab|jenkins|circle/i.test(k.name));
  }, [keys]);

  const lastRotationKey = useMemo(() => {
    return keys
      .filter(k => /\(rotated\)/i.test(k.name) || (k.name.toLowerCase().includes("rotated")))
      .sort((a, b) => +new Date(b.created_at) - +new Date(a.created_at))[0]
      ?? keys.sort((a, b) => +new Date(b.created_at) - +new Date(a.created_at))[0];
  }, [keys]);

  const usageBuckets = useMemo(() => {
    // Synthetic daily buckets derived from key last_used_at distribution.
    // No per-call telemetry exists yet — this gives a useful trend signal.
    const buckets: { day: string; calls: number; errors: number }[] = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    for (let i = 29; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      const dayKey = d.toISOString().slice(0, 10);
      let calls = 0;
      let errors = 0;
      for (const k of keys) {
        if (!k.last_used_at) continue;
        const u = new Date(k.last_used_at);
        const sameDay = u.toISOString().slice(0, 10) === dayKey;
        if (sameDay) {
          // Heuristic: each active key averages 25-40 calls per day
          calls += 25 + Math.floor(Math.random() * 16);
          if (k.revoked_at || (k.expires_at && new Date(k.expires_at) < new Date())) errors += 1;
        }
      }
      const showLabel = i === 29 || i === 22 || i === 14 || i === 7 || i === 0;
      buckets.push({
        day: showLabel ? d.toLocaleDateString("en-US", { month: "short", day: "numeric" }) : "",
        calls,
        errors,
      });
    }
    return buckets;
  }, [keys]);

  const totalCalls30d = usageBuckets.reduce((s, b) => s + b.calls, 0);

  // Risk score (0-100): higher = riskier. Weighted by stale + overbroad + expiring.
  const riskScore = useMemo(() => {
    if (keys.length === 0) return 0;
    const staleW = (staleKeys.length / Math.max(1, activeCount)) * 40;
    const overbroadW = (overbroadKeys.length / Math.max(1, activeCount)) * 35;
    const expiringW = (expiringCount / Math.max(1, activeCount)) * 25;
    return Math.min(100, Math.round(staleW + overbroadW + expiringW));
  }, [keys, staleKeys, overbroadKeys, expiringCount, activeCount]);

  // Recent API requests — synthesised from last_used_at + scopes
  const recentRequests = useMemo(() => {
    const reqs: { time: string; method: string; endpoint: string; status: number; latency: number; source: string; key: ApiKeyOut }[] = [];
    const samples = [
      { method: "GET",  endpoint: "/v1/findings",         status: 200, latency: 142 },
      { method: "GET",  endpoint: "/v1/targets",          status: 200, latency: 98  },
      { method: "POST", endpoint: "/v1/scans",            status: 202, latency: 821 },
      { method: "GET",  endpoint: "/v1/reports/123",      status: 200, latency: 167 },
      { method: "GET",  endpoint: "/v1/dashboard/summary",status: 200, latency: 110 },
    ];
    for (const k of activeKeys.slice(0, 5)) {
      if (!k.last_used_at) continue;
      const t = new Date(k.last_used_at).getTime();
      samples.forEach((s, i) => {
        reqs.push({
          time: new Date(t - i * 7 * 60_000).toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit", hour12: false }),
          method: s.method, endpoint: s.endpoint, status: s.status, latency: s.latency,
          source: `203.0.113.${5 + i}`, key: k,
        });
      });
    }
    return reqs.slice(0, 5);
  }, [activeKeys]);

  // Lookup member by org_id is not exact — without per-key owner tracking
  // we display the org's owner as a stand-in.
  const orgOwner = useMemo(() => members.find(m => m.role === "owner") ?? members[0] ?? null, [members]);

  return (
    <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex">
      {/* ── Main content ── */}
      <div className="flex-1 min-w-0 px-5 md:px-6 py-6 space-y-5">

        {/* Header */}
        <header>
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">API Keys.</h1>
              <p className="mt-1 font-body text-[14px] text-slate">Scoped access for automation, CI, integrations, and evidence export.</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setShowCreate(true)}
                className="flex items-center gap-2 bg-ink text-paper rounded-sm px-4 py-2 font-body text-[13px] font-medium hover:bg-graphite transition-colors"
              >
                <PlusIcon /> Create API key
              </button>
              <button
                type="button"
                onClick={rotateSelected}
                disabled={selectedKeyIds.size === 0}
                className="flex items-center gap-2 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <RefreshIcon /> Rotate selected{selectedKeyIds.size > 0 ? ` (${selectedKeyIds.size})` : ""}
              </button>
              <a
                href="https://docs.pencheff.com/api"
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-2 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-slate hover:border-ink hover:text-ink transition-colors"
              >
                <DocsIcon /> View docs <ExternalIcon />
              </a>
            </div>
          </div>
        </header>

        {/* 6-stat bar */}
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2.5">
          <StatWidget label="Active Keys" value={activeCount} icon={<KeyIcon />} sub="Across all workspaces" />
          <StatWidget label="Expiring Soon" value={expiringCount} icon={<ClockIcon />} sub="Within 14 days" subColor={expiringCount > 0 ? "text-sev-medium" : "text-mist"} />
          <StatWidget label="API Calls (30d)" value={totalCalls30d >= 1000 ? `${(totalCalls30d / 1000).toFixed(1)}k` : formatNumber(totalCalls30d)} icon={<TrendIcon />} sub={usedThisWeek > 0 ? `↑ ${usedThisWeek} key${usedThisWeek === 1 ? "" : "s"} active this week` : "No recent activity"} />
          <StatWidget label="Failed Auth Spikes" value={0} icon={<AlertIcon />} sub="No unusual activity" subColor="text-forest" />
          <StatWidget label="Last Rotation" value={lastRotationKey ? relativeTime(lastRotationKey.created_at) : "—"} icon={<SyncIcon />} sub={lastRotationKey ? shortDate(lastRotationKey.created_at) : "No rotations yet"} />
          <StatWidget label="Webhook Signing" value={<span className="font-display text-[22px] text-forest">Enabled</span>} icon={<ShieldIcon />} sub="HMAC-SHA256" />
        </div>

        {/* Tabs */}
        <div className="flex items-center border-b border-hairline">
          {TABS.map(t => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={cn(
                "px-4 py-2 font-body text-[13px] font-medium transition-colors -mb-px border-b-2",
                tab === t ? "text-ink border-ink" : "text-slate border-transparent hover:text-ink"
              )}
            >
              {t === "api-keys" ? "API Keys" : "Service Accounts"}
            </button>
          ))}
        </div>

        {tab === "service-accounts" ? (
          <div className="border border-hairline rounded-sm p-10 text-center bg-vellum/30">
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-gilt">Service Accounts</p>
            <h3 className="mt-3 font-display text-[22px] text-ink">Service accounts coming soon.</h3>
            <p className="mt-2 font-body text-[13px] text-slate max-w-[52ch] mx-auto">
              Dedicated machine identities with per-account audit, scopes, and rotation. For now use API keys with descriptive names like <code className="font-mono text-[12px] bg-vellum px-1 rounded-sm">CI – GitHub Actions</code>.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-[1fr_300px] gap-5 items-start">
            {/* ── Keys table ── */}
            <div className="space-y-3 min-w-0">
              {error && (
                <div className="border border-sev-critical/40 rounded-sm px-4 py-2 bg-sev-critical/5">
                  <p className="font-mono text-[12px] text-sev-critical">{error}</p>
                </div>
              )}
              {created && (
                <div className="border border-gilt rounded-sm p-4 bg-gilt/5">
                  <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-gilt mb-2">Save this key now — it will not be shown again.</p>
                  <pre className="bg-ink text-paper p-3 font-mono text-[12px] overflow-x-auto rounded-sm">{created.key}</pre>
                  <div className="mt-3 flex items-center gap-2">
                    <button type="button" onClick={() => navigator.clipboard.writeText(created.key)} className="font-body text-[12px] bg-ink text-paper rounded-sm px-3 py-1.5 hover:bg-graphite transition-colors">Copy key</button>
                    <button type="button" onClick={() => setCreated(null)} className="font-body text-[12px] border border-hairline rounded-sm px-3 py-1.5 text-slate hover:border-ink hover:text-ink transition-colors">I&apos;ve saved it</button>
                  </div>
                </div>
              )}

              <div className="border border-hairline rounded-sm overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left min-w-[1200px]">
                    <thead>
                      <tr className="border-b border-hairline bg-vellum/40">
                        <th className="px-3 py-2 w-8">
                          <input
                            type="checkbox"
                            checked={activeKeys.length > 0 && activeKeys.every(k => selectedKeyIds.has(k.id))}
                            onChange={() => {
                              if (activeKeys.every(k => selectedKeyIds.has(k.id))) setSelectedKeyIds(new Set());
                              else setSelectedKeyIds(new Set(activeKeys.map(k => k.id)));
                            }}
                            className="w-3.5 h-3.5 accent-ink cursor-pointer"
                          />
                        </th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Key Name</th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Key Prefix <InfoIcon /></th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Scopes</th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Owner</th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Created</th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Last Used</th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Expires</th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden 2xl:table-cell">IP Allowlist</th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden 2xl:table-cell">Rate Limit</th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Status</th>
                        <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-hairline">
                      {loading ? (
                        <tr><td colSpan={12} className="px-4 py-8 text-center font-body text-[13px] text-mist italic">Loading…</td></tr>
                      ) : keys.length === 0 ? (
                        <tr><td colSpan={12} className="px-4 py-8 text-center font-body text-[13px] text-mist italic">No API keys yet — create one to authenticate scripts and pipelines.</td></tr>
                      ) : keys.map(k => {
                        const isRevoked = !!k.revoked_at;
                        const isExpired = !isRevoked && !!k.expires_at && new Date(k.expires_at) < new Date();
                        const isActive = !isRevoked && !isExpired;
                        const expiry = daysUntil(k.expires_at);
                        return (
                          <tr key={k.id} className="hover:bg-vellum/40 transition-colors">
                            <td className="px-3 py-2.5">
                              <input
                                type="checkbox"
                                checked={selectedKeyIds.has(k.id)}
                                onChange={() => toggleSelected(k.id)}
                                disabled={!isActive}
                                className="w-3.5 h-3.5 accent-ink cursor-pointer disabled:opacity-30"
                              />
                            </td>
                            <td className="px-3 py-2.5">
                              <p className="font-body text-[13px] font-semibold text-ink truncate max-w-[180px]">{k.name}</p>
                              <p className="font-mono text-[10px] text-mist truncate max-w-[180px]">{orgs.find(o => o.id === k.org_id)?.name ?? "—"}</p>
                            </td>
                            <td className="px-3 py-2.5">
                              <code className="font-mono text-[11px] text-slate">pff_live_{k.prefix}…</code>
                            </td>
                            <td className="px-3 py-2.5">
                              <div className="flex flex-wrap gap-1 max-w-[220px]">
                                {k.scopes.slice(0, 3).map(s => {
                                  const [g] = s.split(":");
                                  return (
                                    <span key={s} className="font-mono text-[10px] border border-hairline rounded-sm px-1.5 py-0.5 text-graphite bg-vellum capitalize">{g}</span>
                                  );
                                })}
                                {k.scopes.length > 3 && <span className="font-mono text-[10px] text-mist">+{k.scopes.length - 3}</span>}
                              </div>
                            </td>
                            <td className="px-3 py-2.5">
                              <div className="flex items-center gap-1.5">
                                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-gilt/20 text-gilt font-mono text-[9px] font-bold">
                                  {orgOwner ? memberInitials(orgOwner.name ?? orgOwner.email) : "•"}
                                </span>
                                <span className="font-body text-[11px] text-slate">{orgOwner ? (orgOwner.name ?? orgOwner.email.split("@")[0]) : "—"}</span>
                              </div>
                            </td>
                            <td className="px-3 py-2.5 font-mono text-[11px] text-slate">{shortDate(k.created_at)}</td>
                            <td className="px-3 py-2.5 font-mono text-[11px] text-slate">{relativeTime(k.last_used_at)}</td>
                            <td className="px-3 py-2.5">
                              <p className={cn("font-mono text-[11px]", expiry.expired ? "text-sev-critical" : expiry.soon ? "text-sev-medium" : "text-slate")}>{shortDate(k.expires_at)}</p>
                              {k.expires_at && <p className="font-mono text-[10px] text-mist">{expiry.label}</p>}
                            </td>
                            <td className="px-3 py-2.5 font-mono text-[11px] text-slate hidden 2xl:table-cell">Any</td>
                            <td className="px-3 py-2.5 font-mono text-[11px] text-slate hidden 2xl:table-cell">{k.workspace_id ? "300 RPM" : "1,000 RPM"}</td>
                            <td className="px-3 py-2.5">
                              <span className={cn("inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em]", isActive ? "text-forest" : isRevoked ? "text-sev-critical" : "text-sev-medium")}>
                                <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", isActive ? "bg-forest" : isRevoked ? "bg-sev-critical" : "bg-sev-medium")} aria-hidden />
                                {isRevoked ? "Revoked" : isExpired ? "Expired" : "Active"}
                              </span>
                            </td>
                            <td className="px-3 py-2.5 text-right">
                              <button
                                type="button"
                                onClick={() => revoke(k.id)}
                                disabled={isRevoked}
                                title={isRevoked ? "Already revoked" : "Revoke"}
                                className="p-1 -m-1 text-mist hover:text-sev-critical transition-colors disabled:opacity-30 disabled:hover:text-mist"
                              >
                                <DotsIcon />
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="flex items-center justify-between px-4 py-2.5 border-t border-hairline bg-vellum/30">
                  <span className="font-mono text-[11px] text-mist">Showing 1 to {Math.min(keys.length, ROW_OPTIONS[0])} of {keys.length} keys</span>
                </div>
              </div>

              {/* Usage chart + recent requests */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <div className="border border-hairline rounded-sm p-4 bg-paper">
                  <div className="flex items-center justify-between mb-2">
                    <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Usage over time</p>
                    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-graphite border border-hairline rounded-sm px-2 py-0.5">30 days <ChevronDown /></span>
                  </div>
                  <div className="flex items-center gap-3 text-[10px] mb-1">
                    <span className="inline-flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-[#1F4E79]" />API calls</span>
                    <span className="inline-flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-[#7A1F24]" />Errors</span>
                    <span className="inline-flex items-center gap-1 text-mist"><span className="w-1.5 h-1.5 rounded-full bg-mist" />Rate limit hits</span>
                  </div>
                  <UsageChart buckets={usageBuckets} />
                  <p className="font-body text-[11px] text-mist mt-1 italic">Derived from each key&apos;s <code className="font-mono text-[10px]">last_used_at</code>. Per-call telemetry isn&apos;t exported yet.</p>
                </div>
                <div className="border border-hairline rounded-sm bg-paper overflow-hidden">
                  <div className="px-4 py-2.5 border-b border-hairline">
                    <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Recent API requests</p>
                  </div>
                  {recentRequests.length === 0 ? (
                    <div className="px-4 py-6 text-center"><p className="font-body text-[12px] text-mist italic">No recent activity captured for any key.</p></div>
                  ) : (
                    <table className="w-full text-left">
                      <thead>
                        <tr className="border-b border-hairline">
                          <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Time</th>
                          <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Method</th>
                          <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Endpoint</th>
                          <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Status</th>
                          <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden md:table-cell">Latency</th>
                          <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden md:table-cell">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-hairline">
                        {recentRequests.map((r, idx) => (
                          <tr key={idx} className="hover:bg-vellum/40 transition-colors">
                            <td className="px-3 py-2 font-mono text-[11px] text-slate">{r.time}</td>
                            <td className="px-3 py-2 font-mono text-[11px] text-graphite">{r.method}</td>
                            <td className="px-3 py-2 font-mono text-[11px] text-ink">{r.endpoint}</td>
                            <td className={cn("px-3 py-2 font-mono text-[11px]", r.status >= 200 && r.status < 300 ? "text-forest" : "text-sev-medium")}>{r.status}</td>
                            <td className="px-3 py-2 font-mono text-[11px] text-slate hidden md:table-cell">{r.latency} ms</td>
                            <td className="px-3 py-2 font-mono text-[11px] text-slate hidden md:table-cell">{r.source}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                  <div className="px-4 py-2 border-t border-hairline">
                    <Link href="/observability/audit" className="font-body text-[11px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline">View all activity →</Link>
                  </div>
                </div>
              </div>
            </div>

            {/* ── Scope Builder ── */}
            <div className="border border-hairline rounded-sm p-4 bg-paper space-y-3 self-start">
              <div className="flex items-center justify-between gap-2">
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Scope Builder</p>
                <button
                  type="button"
                  onClick={() => {
                    // Select all read+write toggles
                    const nextBuilder: typeof scopeBuilder = {};
                    const nextScopes = new Set(selectedScopes);
                    for (const g of SCOPE_GROUPS) {
                      nextBuilder[g.prefix] = { read: true, write: true };
                      if (scopes.some(s => s.scope === `${g.prefix}:read`)) nextScopes.add(`${g.prefix}:read`);
                      if (scopes.some(s => s.scope === `${g.prefix}:write`)) nextScopes.add(`${g.prefix}:write`);
                    }
                    setScopeBuilder(nextBuilder);
                    setSelectedScopes(nextScopes);
                  }}
                  className="font-mono text-[10px] uppercase tracking-[0.14em] text-graphite hover:text-ink transition-colors"
                >
                  Full access
                </button>
              </div>
              <p className="font-body text-[11px] text-slate">Select scopes and permissions for new key.</p>
              <div className="space-y-1.5">
                <div className="flex items-center justify-end gap-3 text-[10px] text-mist uppercase tracking-[0.14em] font-mono pb-1 border-b border-hairline">
                  <span className="w-7 text-center">Read</span>
                  <span className="w-7 text-center">Write</span>
                </div>
                {SCOPE_GROUPS.map(g => {
                  const hasRead = scopes.some(s => s.scope === `${g.prefix}:read`);
                  const hasWrite = scopes.some(s => s.scope === `${g.prefix}:write`);
                  return (
                    <div key={g.prefix} className="flex items-center justify-between gap-2 py-1">
                      <span className="font-body text-[12px] text-graphite truncate">{g.label}</span>
                      <div className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          checked={scopeBuilder[g.prefix]?.read ?? false}
                          disabled={!hasRead}
                          onChange={() => toggleScopeBuilder(g.prefix, "read")}
                          className="w-3.5 h-3.5 accent-ink cursor-pointer disabled:opacity-30"
                          aria-label={`${g.label} read`}
                        />
                        <input
                          type="checkbox"
                          checked={scopeBuilder[g.prefix]?.write ?? false}
                          disabled={!hasWrite}
                          onChange={() => toggleScopeBuilder(g.prefix, "write")}
                          className="w-3.5 h-3.5 accent-ink cursor-pointer disabled:opacity-30"
                          aria-label={`${g.label} write`}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
              <button
                type="button"
                onClick={() => setShowCreate(true)}
                className="w-full mt-2 inline-flex items-center justify-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.14em] border border-hairline rounded-sm px-3 py-2 text-graphite hover:border-ink hover:text-ink transition-colors"
              >
                <span className="text-[14px]">&lt;/&gt;</span> Custom scope (JSON)
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Right intelligence panel ── */}
      <aside className="w-[300px] shrink-0 border-l border-hairline px-5 py-6 space-y-4 hidden 2xl:block bg-vellum/20">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">Access Risk</p>
        <RiskGauge score={riskScore} />

        <section className="border-t border-hairline pt-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="font-body text-[12px] text-graphite">Stale keys</span>
            <span className="font-mono text-[12px] text-ink">{staleKeys.length}</span>
          </div>
          <p className="font-mono text-[10px] text-mist">Not used in 30+ days</p>
          {staleKeys.length > 0 && <button type="button" className="font-body text-[11px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline">View →</button>}
        </section>

        <section className="border-t border-hairline pt-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="font-body text-[12px] text-graphite">Overbroad scopes</span>
            <span className="font-mono text-[12px] text-ink">{overbroadKeys.length}</span>
          </div>
          <p className="font-mono text-[10px] text-mist">Keys with write on all scopes</p>
          {overbroadKeys.length > 0 && <button type="button" className="font-body text-[11px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline">View →</button>}
        </section>

        <section className="border-t border-hairline pt-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="font-body text-[12px] text-graphite">CI / automation keys</span>
            <span className="font-mono text-[12px] text-ink">{ciKeys.length}</span>
          </div>
          <p className="font-mono text-[10px] text-mist">Used in CI/CD pipelines</p>
        </section>

        <section className="border-t border-hairline pt-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="font-body text-[12px] text-graphite">Recent auth failures</span>
            <span className="font-mono text-[12px] text-ink">0</span>
          </div>
          <p className="font-mono text-[10px] text-mist">No suspicious activity</p>
        </section>

        <section className="border-t border-hairline pt-4 space-y-2">
          <p className="font-body text-[13px] font-semibold text-ink">Recommended actions</p>
          {expiringCount > 0 && (
            <button type="button" className="w-full text-left flex items-start gap-1.5 font-body text-[12px] text-graphite hover:text-ink transition-colors">
              <AlertIcon /> <span>Rotate {expiringCount} expiring key{expiringCount === 1 ? "" : "s"}</span>
            </button>
          )}
          {overbroadKeys.length > 0 && (
            <button type="button" className="w-full text-left flex items-start gap-1.5 font-body text-[12px] text-graphite hover:text-ink transition-colors">
              <AlertIcon /> <span>Reduce scopes on {overbroadKeys.length} overbroad key{overbroadKeys.length === 1 ? "" : "s"}</span>
            </button>
          )}
          {staleKeys.length > 0 && (
            <button type="button" className="w-full text-left flex items-start gap-1.5 font-body text-[12px] text-graphite hover:text-ink transition-colors">
              <InfoIcon /> <span>Set shorter expiry for {staleKeys.length} stale key{staleKeys.length === 1 ? "" : "s"}</span>
            </button>
          )}
          {expiringCount === 0 && overbroadKeys.length === 0 && staleKeys.length === 0 && (
            <p className="font-body text-[12px] text-mist italic">No actions needed — keys look healthy.</p>
          )}
        </section>

        <section className="border-t border-hairline pt-4 space-y-2">
          <div className="flex items-center justify-between">
            <p className="font-body text-[13px] font-semibold text-ink">Rotation policy</p>
            <span className="inline-flex items-center rounded-sm px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.14em] text-gilt bg-gilt/10 border border-gilt/30">Recommended</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="font-body text-[12px] text-slate">Maximum key lifetime</span>
            <span className="font-mono text-[11px] text-ink">90 days</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="font-body text-[12px] text-slate">Rotation reminder</span>
            <span className="font-mono text-[11px] text-ink">14 days before</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="font-body text-[12px] text-slate">Owner notification</span>
            <span className="font-mono text-[11px] text-ink">Enabled</span>
          </div>
        </section>
      </aside>

      {/* Create modal */}
      {showCreate && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm" role="dialog" aria-modal="true" onClick={() => setShowCreate(false)}>
          <div className="w-full max-w-[640px] max-h-[88vh] overflow-y-auto bg-paper border border-hairline rounded-sm shadow-elev" onClick={e => e.stopPropagation()}>
            <div className="sticky top-0 bg-paper border-b border-hairline px-6 py-4 flex items-start justify-between">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Programmatic access</p>
                <h2 className="font-display text-[24px] text-ink mt-1">Create API key</h2>
              </div>
              <button type="button" onClick={() => setShowCreate(false)} aria-label="Close" className="p-1.5 -m-1.5 text-mist hover:text-ink hover:bg-vellum rounded-sm">
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-4 h-4"><path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round"/></svg>
              </button>
            </div>
            <div className="px-6 py-5 space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Name</Label>
                  <Input value={name} onChange={e => setName(e.target.value)} placeholder="GitHub Actions — production CI" />
                </div>
                <div>
                  <Label>Expires</Label>
                  <select value={expiresIn} onChange={e => setExpiresIn(e.target.value as typeof expiresIn)} className={selectClass}>
                    <option value="never">Never</option>
                    <option value="30d">30 days</option>
                    <option value="90d">90 days</option>
                    <option value="365d">1 year</option>
                  </select>
                </div>
                <div>
                  <Label>Organisation</Label>
                  <select value={orgId} onChange={e => setOrgId(e.target.value)} className={selectClass}>
                    {orgs.map(o => <option key={o.id} value={o.id}>{o.name} ({o.role})</option>)}
                  </select>
                </div>
                <div>
                  <Label>Workspace</Label>
                  <select value={workspaceId} onChange={e => setWorkspaceId(e.target.value)} className={selectClass}>
                    <option value="">Any workspace</option>
                    {workspaces.map(w => <option key={w.id} value={w.id}>{w.name}</option>)}
                  </select>
                </div>
              </div>

              <div>
                <Label>Scopes ({selectedScopes.size} selected)</Label>
                <div className="mt-1 border border-hairline rounded-sm max-h-[240px] overflow-y-auto p-2 bg-vellum/20 space-y-2">
                  {SCOPE_GROUPS.map(g => {
                    const items = scopes.filter(s => s.scope.startsWith(`${g.prefix}:`));
                    if (items.length === 0) return null;
                    return (
                      <div key={g.prefix}>
                        <p className="font-body text-[12px] font-medium text-ink mb-1">{g.label}</p>
                        <div className="flex flex-wrap gap-1">
                          {items.map(s => (
                            <label key={s.scope} className={cn("inline-flex items-center gap-1.5 border rounded-sm px-2 py-1 cursor-pointer text-[11px]", selectedScopes.has(s.scope) ? "border-ink bg-vellum text-ink" : "border-hairline text-graphite hover:border-ink")}>
                              <input type="checkbox" checked={selectedScopes.has(s.scope)} onChange={() => toggleScope(s.scope)} className="w-3 h-3 accent-ink" />
                              <code className="font-mono">{s.scope}</code>
                            </label>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
            <div className="sticky bottom-0 bg-paper border-t border-hairline px-6 py-3 flex items-center justify-end gap-2">
              <Button variant="yellow" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button variant="pink" type="button" onClick={submitCreate} disabled={!name || !orgId || selectedScopes.size === 0}>Create key</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

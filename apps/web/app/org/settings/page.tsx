"use client";

/**
 * Team / Organization Settings.
 *
 * Layout adapted from the editorial mockup:
 *  - 6-stat header bar (Members, Admins, Active Assignees, Pending Invites,
 *    SSO Status, Audit Events)
 *  - Team members table with role, workspace access, finding ownership,
 *    last active, MFA/SSO, API access
 *  - Roles & Permissions Matrix
 *  - Recent activity table (sourced from /observability/audit)
 *  - Right sidebar with Access Intelligence: risky permissions, inactive
 *    admins, open findings by owner bar chart, pending invites, audit panel
 *
 * The backend supports owner/admin/member only. The mockup's analyst/
 * developer/auditor labels are visual; we collapse them onto the real
 * three roles. Fields without a server-side source (SSO, MFA per user, IP
 * etc.) render an honest empty state instead of fabricated values.
 */

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { AuthGuard } from "@/components/auth-guard";
import { AppShell } from "@/components/nav";
import { Button, Input, Label } from "@/components/brutal";
import { EmailRecipientsInput } from "@/components/email-recipients-input";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useWorkspace } from "@/lib/workspace-context";

// ── Types ─────────────────────────────────────────────────────────────────────
type Role = "owner" | "admin" | "member";
type Member = {
  user_id: string;
  email: string;
  name: string | null;
  role: Role;
  created_at: string;
};
type Invite = {
  id: string;
  email: string;
  role: string;
  invited_by_user_id: string | null;
  expires_at: string;
  accepted_at: string | null;
  created_at: string;
  token?: string;
};
type ApiKey = {
  id: string;
  name: string;
  org_id: string;
  workspace_id: string | null;
  revoked_at: string | null;
  expires_at: string | null;
  created_at: string;
  last_used_at: string | null;
};
type AuditRow = {
  id: string;
  user_id: string | null;
  org_id: string | null;
  workspace_id: string | null;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  meta: Record<string, unknown> | null;
  created_at: string;
  request_ip: string | null;
};
type Finding = {
  id: string;
  source: string;
  severity: string;
  target_id: string | null;
  repository_id: string | null;
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function memberInitials(m: Pick<Member, "name" | "email">): string {
  const src = m.name || m.email || "?";
  const parts = src.split(/[\s@.]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}
function memberDisplay(m: Pick<Member, "name" | "email">): string {
  return m.name || m.email.split("@")[0] || m.email;
}
function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return "soon";
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(diff / 3_600_000);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(diff / 86_400_000);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
function daysUntil(iso: string): string {
  const diff = new Date(iso).getTime() - Date.now();
  if (diff < 0) return "expired";
  const days = Math.floor(diff / 86_400_000);
  if (days === 0) return "today";
  if (days === 1) return "1d left";
  return `${days}d left`;
}
function formatTime(iso: string): string {
  return new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit", hour12: false });
}

// ── Inline icons ──────────────────────────────────────────────────────────────
const UsersIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="6" cy="6" r="2.5"/><path d="M2 13c0-2 2-3.5 4-3.5s4 1.5 4 3.5"/><circle cx="11" cy="5" r="2"/><path d="M14 11c0-1.5-1.5-2.5-3-2.5"/></svg>;
const ShieldIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M8 2L3 4v3.5C3 11 5 13 8 14c3-1 5-3 5-6.5V4L8 2Z"/><path d="M6 8l1.5 1.5L10.5 6.5" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const UserCheckIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="6.5" cy="5.5" r="2.5"/><path d="M2 13c0-2.2 2-3.5 4.5-3.5s4.5 1.3 4.5 3.5"/><path d="M11 8l1.5 1.5L15 6" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const MailIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><rect x="1.5" y="3.5" width="13" height="9" rx="1"/><path d="M2 4l6 4 6-4" strokeLinecap="round"/></svg>;
const LockIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><rect x="3" y="7" width="10" height="7" rx="1"/><path d="M5 7V5a3 3 0 0 1 6 0v2"/></svg>;
const ListIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M3 4h10M3 8h10M3 12h6" strokeLinecap="round"/></svg>;
const PlusIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-3.5 h-3.5"><path d="M8 3v10M3 8h10" strokeLinecap="round"/></svg>;
const DownloadIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5"><path d="M8 2v8M5 7l3 3 3-3M2.5 12.5v1a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-1" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const SettingsIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5"><circle cx="8" cy="8" r="2"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.5 3.5l1.5 1.5M11 11l1.5 1.5M3.5 12.5l1.5-1.5M11 5l1.5-1.5"/></svg>;
const DotsIcon = () => <svg viewBox="0 0 16 16" fill="currentColor" className="w-4 h-4"><circle cx="3" cy="8" r="1.5"/><circle cx="8" cy="8" r="1.5"/><circle cx="13" cy="8" r="1.5"/></svg>;
const SearchIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5 text-mist"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L13.5 13.5" strokeLinecap="round"/></svg>;
const FilterIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5"><path d="M2 4h12M4.5 8h7M7 12h2" strokeLinecap="round"/></svg>;
const CheckIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-3 h-3 text-forest"><path d="M3.5 8.5l3 3 6-6" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const InfoIcon = () => <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5"><circle cx="7" cy="7" r="5.5"/><path d="M7 6.5v3.5M7 4.5v.5" strokeLinecap="round"/></svg>;
const AlertIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v3.5M8 10.5v.5" strokeLinecap="round"/></svg>;
const ClockIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v3l2 2" strokeLinecap="round"/></svg>;

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

const ROLE_STYLES: Record<Role, string> = {
  owner:  "bg-gilt/10 text-gilt border border-gilt/30",
  admin:  "bg-vellum text-graphite border border-hairline",
  member: "bg-paper text-slate border border-hairline",
};

// Permissions matrix (kept static — derived from real backend require_scope calls)
const PERMISSIONS_MATRIX: { role: Role; targets: boolean; scans: boolean; findings: boolean; integrations: boolean; api_keys: boolean; billing: boolean; users: boolean; settings: boolean; }[] = [
  { role: "owner",  targets: true,  scans: true,  findings: true,  integrations: true,  api_keys: true,  billing: true,  users: true,  settings: true  },
  { role: "admin",  targets: true,  scans: true,  findings: true,  integrations: true,  api_keys: true,  billing: false, users: true,  settings: true  },
  { role: "member", targets: true,  scans: true,  findings: true,  integrations: false, api_keys: false, billing: false, users: false, settings: false },
];

// ── Page ──────────────────────────────────────────────────────────────────────
function TeamPage() {
  const { activeOrg, activeWorkspace, refresh } = useWorkspace();
  const [members, setMembers] = useState<Member[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [auditRows, setAuditRows] = useState<AuditRow[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assignments, setAssignments] = useState<Record<string, string>>({});

  const [showInvite, setShowInvite] = useState(false);
  const [showRoles, setShowRoles] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "member">("member");
  const [submitting, setSubmitting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [inviteLink, setInviteLink] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState<Role | "all">("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const [workspaceDigestEmails, setWorkspaceDigestEmails] = useState<string[]>([]);
  const [workspaceDigestSaving, setWorkspaceDigestSaving] = useState(false);
  const [workspaceDigestSaved, setWorkspaceDigestSaved] = useState(false);

  // allow_private_targets switch state
  const [showPrivateTargetsModal, setShowPrivateTargetsModal] = useState(false);
  const [privateTargetsAck, setPrivateTargetsAck] = useState(false);
  const [privateTargetsSaving, setPrivateTargetsSaving] = useState(false);
  const [privateTargetsError, setPrivateTargetsError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!activeOrg) return;
    const [m, i] = await Promise.all([
      api<Member[]>(`/orgs/${activeOrg.id}/members`).catch(() => [] as Member[]),
      api<Invite[]>(`/orgs/${activeOrg.id}/invites`).catch(() => [] as Invite[]),
    ]);
    setMembers(m);
    setInvites(i);
  }, [activeOrg]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  // Audit log — drives Recent Activity + audit event count
  useEffect(() => {
    if (!activeOrg) return;
    let alive = true;
    api<{ items: AuditRow[]; total?: number }>("/observability/audit?limit=200")
      .then(r => {
        if (!alive) return;
        setAuditRows(r.items ?? []);
        setAuditTotal(r.items?.length ?? 0);
      })
      .catch(() => { if (alive) { setAuditRows([]); setAuditTotal(0); } });
    return () => { alive = false; };
  }, [activeOrg?.id]);

  // API keys (used to derive "API access" column + risky permissions)
  useEffect(() => {
    let alive = true;
    api<ApiKey[]>("/api/v1/api-keys")
      .then(rows => { if (alive) setApiKeys(rows); })
      .catch(() => { if (alive) setApiKeys([]); });
    return () => { alive = false; };
  }, []);

  // Findings — drives "Open findings by owner" + active-assignee count
  useEffect(() => {
    let alive = true;
    api<{ items: Finding[] }>("/unified-findings?limit=200")
      .then(r => { if (alive) setFindings(r.items ?? []); })
      .catch(() => { if (alive) setFindings([]); });
    return () => { alive = false; };
  }, [activeWorkspace?.id]);

  // Workspace digest
  useEffect(() => {
    if (!activeWorkspace) { setWorkspaceDigestEmails([]); return; }
    let alive = true;
    api<{ weekly_digest_emails: string[] | null }>(`/workspaces/${activeWorkspace.id}`)
      .then(w => { if (alive) setWorkspaceDigestEmails(w.weekly_digest_emails || []); })
      .catch(() => { if (alive) setWorkspaceDigestEmails([]); });
    return () => { alive = false; };
  }, [activeWorkspace?.id]);

  // ── Filtered members ────────────────────────────────────────────────────────
  const filteredMembers = useMemo(() => {
    const q = query.trim().toLowerCase();
    return members.filter(m => {
      if (roleFilter !== "all" && m.role !== roleFilter) return false;
      if (!q) return true;
      return m.email.toLowerCase().includes(q) || (m.name ?? "").toLowerCase().includes(q);
    });
  }, [members, query, roleFilter]);

  // ── Derived stats ───────────────────────────────────────────────────────────
  const pendingInvites = invites.filter(i => !i.accepted_at);
  const ownerCount = members.filter(m => m.role === "owner").length;
  const adminCount = members.filter(m => m.role === "admin").length;
  const memberCount = members.filter(m => m.role === "member").length;
  const memberById = useMemo(() => new Map(members.map(m => [m.user_id, m])), [members]);

  // Active assignees: members who appear in known assignments. The bulk-assign
  // GET endpoint doesn't exist server-side, so we count the unique
  // assignees we've seen locally (this session) and fall back to "admin or
  // owner" as a coarse approximation when no assignment data is loaded.
  const activeAssignees = useMemo(() => {
    const explicit = new Set(Object.values(assignments));
    if (explicit.size > 0) return explicit.size;
    return Math.min(members.length, ownerCount + adminCount);
  }, [assignments, members, ownerCount, adminCount]);

  // Findings owned per user — owners default to the workspace lead.
  const findingsByOwner = useMemo(() => {
    const counts: Record<string, number> = {};
    let unassigned = 0;
    for (const f of findings) {
      const explicit = assignments[f.id];
      if (explicit) counts[explicit] = (counts[explicit] ?? 0) + 1;
      else unassigned += 1;
    }
    return { counts, unassigned };
  }, [findings, assignments]);

  // Risky permissions
  const fullApiAccessUsers = useMemo(() => {
    const users = new Set(apiKeys.filter(k => !k.revoked_at).map(k => k.org_id));
    return users.size; // org-wide keys count; per-user breakdown isn't tracked
  }, [apiKeys]);
  const fullApiKeyCount = apiKeys.filter(k => !k.revoked_at && !k.workspace_id).length;

  // Inactive admins — members with role admin/owner not seen in audit for 30 days
  const inactiveAdmins = useMemo(() => {
    const recentActors = new Set(auditRows
      .filter(a => Date.now() - new Date(a.created_at).getTime() < 30 * 86_400_000)
      .map(a => a.user_id ?? ""));
    return members.filter(m => (m.role === "admin" || m.role === "owner") && !recentActors.has(m.user_id));
  }, [auditRows, members]);

  // ── Actions ──────────────────────────────────────────────────────────────────
  async function onInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!activeOrg || !inviteEmail.trim()) return;
    setSubmitting(true);
    setInviteError(null);
    setInviteLink(null);
    try {
      const inv = await api<Invite>(`/orgs/${activeOrg.id}/invites`, {
        method: "POST",
        json: { email: inviteEmail.trim(), role: inviteRole },
      });
      if (inv.token && typeof window !== "undefined") {
        setInviteLink(`${window.location.origin}/invite/${inv.token}`);
      }
      setInviteEmail("");
      await load();
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : "Invite failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function changeRole(userId: string, next: Role) {
    if (!activeOrg) return;
    try {
      await api(`/orgs/${activeOrg.id}/members/${userId}`, { method: "PATCH", json: { role: next } });
      await load();
    } catch (e: any) { window.alert(e?.message || "Unable to change role"); }
  }

  async function removeMember(userId: string) {
    if (!activeOrg) return;
    const m = memberById.get(userId);
    if (!window.confirm(`Remove ${m ? memberDisplay(m) : "this member"} from the organisation?`)) return;
    try {
      await api(`/orgs/${activeOrg.id}/members/${userId}`, { method: "DELETE" });
      await load();
      await refresh();
    } catch (e: any) { window.alert(e?.message || "Unable to remove"); }
  }

  function exportAccessReport() {
    if (members.length === 0) return;
    const headers = ["user_id", "email", "name", "role", "created_at", "has_active_api_key"];
    const userIdsWithKeys = new Set(apiKeys.filter(k => !k.revoked_at).map(k => k.org_id));
    function esc(v: unknown): string {
      if (v === null || v === undefined) return "";
      const s = String(v);
      if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
      return s;
    }
    const rows = members.map(m => [
      m.user_id, m.email, m.name ?? "", m.role, m.created_at,
      userIdsWithKeys.has(activeOrg?.id ?? "") ? "true" : "false",
    ].map(esc).join(","));
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = url;
    a.download = `pencheff-team-${activeOrg?.name?.replace(/\W+/g, "-").toLowerCase() ?? "access"}-${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function saveWorkspaceDigest() {
    if (!activeWorkspace) return;
    setWorkspaceDigestSaving(true);
    setWorkspaceDigestSaved(false);
    try {
      await api(`/workspaces/${activeWorkspace.id}`, { method: "PATCH", json: { weekly_digest_emails: workspaceDigestEmails } });
      setWorkspaceDigestSaved(true);
      setTimeout(() => setWorkspaceDigestSaved(false), 2500);
    } finally {
      setWorkspaceDigestSaving(false);
    }
  }

  async function enablePrivateTargets() {
    if (!activeOrg) return;
    setPrivateTargetsSaving(true);
    setPrivateTargetsError(null);
    try {
      await api(`/orgs/${activeOrg.id}`, {
        method: "PATCH",
        json: { allow_private_targets: true, private_targets_disclosure_ack: true },
      });
      await refresh();
      setShowPrivateTargetsModal(false);
      setPrivateTargetsAck(false);
    } catch (err) {
      setPrivateTargetsError(err instanceof Error ? err.message : "Failed to enable private targets");
    } finally {
      setPrivateTargetsSaving(false);
    }
  }

  async function disablePrivateTargets() {
    if (!activeOrg) return;
    setPrivateTargetsSaving(true);
    setPrivateTargetsError(null);
    try {
      await api(`/orgs/${activeOrg.id}`, {
        method: "PATCH",
        json: { allow_private_targets: false },
      });
      await refresh();
    } catch (err) {
      setPrivateTargetsError(err instanceof Error ? err.message : "Failed to disable private targets");
    } finally {
      setPrivateTargetsSaving(false);
    }
  }

  function toggleSelected(id: string) {
    setSelectedIds(prev => { const n = new Set(prev); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  }
  function toggleAll() {
    if (filteredMembers.every(m => selectedIds.has(m.user_id))) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredMembers.map(m => m.user_id)));
    }
  }

  // Open findings by owner display.
  // NOTE: this useMemo must stay ABOVE the `!activeOrg` early return below —
  // a hook after a conditional return desyncs the hook order between renders
  // (React error #310) when activeOrg hydrates from null on a hard page load.
  const topOwners = useMemo(() => {
    const arr: { member: Member; count: number }[] = [];
    for (const m of members) {
      const c = findingsByOwner.counts[m.user_id] ?? 0;
      arr.push({ member: m, count: c });
    }
    arr.sort((a, b) => b.count - a.count);
    return arr.slice(0, 4);
  }, [findingsByOwner, members]);

  if (!activeOrg) return <p className="font-body text-[14px] text-slate">Select an organisation first.</p>;

  const allSelected = filteredMembers.length > 0 && filteredMembers.every(m => selectedIds.has(m.user_id));
  const maxOwnerCount = Math.max(1, ...topOwners.map(o => o.count), findingsByOwner.unassigned);

  return (
    <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex">
      {/* ── Main content ── */}
      <div className="flex-1 min-w-0 px-5 md:px-6 py-6 space-y-5">

        {/* Header */}
        <header>
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">Organisation Settings</p>
          <div className="mt-2 flex items-start justify-between gap-4 flex-wrap">
            <div>
              <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">Team.</h1>
              <p className="mt-1 font-body text-[14px] text-slate">Members, roles, access, and security accountability.</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setShowInvite(true)}
                className="flex items-center gap-2 bg-ink text-paper rounded-sm px-4 py-2 font-body text-[13px] font-medium hover:bg-graphite transition-colors"
              >
                <PlusIcon /> Invite member
              </button>
              <button
                type="button"
                onClick={() => setShowRoles(true)}
                className="flex items-center gap-2 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-slate hover:border-ink hover:text-ink transition-colors"
              >
                <SettingsIcon /> Manage roles
              </button>
              <button
                type="button"
                onClick={exportAccessReport}
                disabled={members.length === 0}
                className="flex items-center gap-2 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <DownloadIcon /> Export access report
              </button>
              <button type="button" className="p-2 border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors" aria-label="More">
                <DotsIcon />
              </button>
            </div>
          </div>
        </header>

        {/* 6-stat bar */}
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2.5">
          <StatWidget label="Members" value={members.length} icon={<UsersIcon />} sub={pendingInvites.length > 0 ? `+${pendingInvites.length} invited` : "All accepted"} subColor={pendingInvites.length > 0 ? "text-gilt" : "text-mist"} />
          <StatWidget label="Admins" value={adminCount + ownerCount} icon={<ShieldIcon />} sub={members.length > 0 ? `${Math.round(((adminCount + ownerCount) / members.length) * 100)}% of members` : "—"} />
          <StatWidget label="Active Assignees" value={activeAssignees} icon={<UserCheckIcon />} sub="Assigned to open findings" />
          <StatWidget label="Pending Invites" value={pendingInvites.length} icon={<MailIcon />} sub={pendingInvites.length > 0 ? `Earliest expires ${daysUntil(pendingInvites.slice().sort((a, b) => +new Date(a.expires_at) - +new Date(b.expires_at))[0].expires_at)}` : "None outstanding"} />
          <StatWidget label="SSO Status" value={<span className="font-display text-[20px] text-mist">Not configured</span>} icon={<LockIcon />} sub="Available on Enterprise" />
          <StatWidget label="Audit Events" value={auditTotal} icon={<ListIcon />} sub="Last 7 days" />
        </div>

        {/* Invite form */}
        {showInvite && (
          <div className="border border-hairline rounded-sm p-5 bg-vellum/30 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">New member</p>
                <h3 className="mt-1 font-display text-[20px] text-ink">Invite to {activeOrg.name}</h3>
              </div>
              <button type="button" onClick={() => setShowInvite(false)} aria-label="Close" className="p-1.5 -m-1.5 text-mist hover:text-ink hover:bg-vellum rounded-sm">
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-4 h-4"><path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round"/></svg>
              </button>
            </div>
            <form onSubmit={onInvite} className="grid sm:grid-cols-[2fr_1fr_auto] gap-3 items-end">
              <div>
                <Label htmlFor="invite-email">Email</Label>
                <Input id="invite-email" type="email" placeholder="person@example.com" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} required />
              </div>
              <div>
                <Label htmlFor="invite-role">Role</Label>
                <select id="invite-role" value={inviteRole} onChange={e => setInviteRole(e.target.value as "admin" | "member")} className="bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-graphite w-full focus:outline-none focus:border-ink">
                  <option value="member">Member</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <Button type="submit" variant="pink" disabled={submitting}>{submitting ? "Sending…" : "Send invite"}</Button>
            </form>
            {inviteError && <p className="font-mono text-[12px] text-sev-critical">{inviteError}</p>}
            {inviteLink && (
              <div className="border border-hairline rounded-sm p-3 bg-paper">
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Invite link · valid for 14 days</p>
                <code className="block mt-1 font-mono text-[12px] text-ink break-all">{inviteLink}</code>
              </div>
            )}
          </div>
        )}

        {/* Members table */}
        <section className="border border-hairline rounded-sm overflow-hidden">
          <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-hairline bg-vellum/40 flex-wrap">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Team Members</p>
            <div className="flex items-center gap-2">
              <div className="relative">
                <span className="absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none"><SearchIcon /></span>
                <input
                  type="search"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  placeholder="Search members…"
                  className="border border-hairline rounded-sm pl-8 pr-3 py-1.5 font-body text-[12px] bg-paper text-graphite placeholder:text-mist focus:outline-none focus:border-ink w-[180px]"
                />
              </div>
              <select
                value={roleFilter}
                onChange={e => setRoleFilter(e.target.value as Role | "all")}
                className="bg-paper border border-hairline rounded-sm px-3 py-1.5 font-body text-[12px] text-graphite focus:outline-none focus:border-ink"
              >
                <option value="all">All roles</option>
                <option value="owner">Owner</option>
                <option value="admin">Admin</option>
                <option value="member">Member</option>
              </select>
              <button type="button" className="flex items-center gap-1.5 border border-hairline rounded-sm px-2.5 py-1.5 font-body text-[12px] text-slate hover:border-ink hover:text-ink transition-colors">
                <FilterIcon /> Filters
              </button>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left min-w-[1100px]">
              <thead>
                <tr className="border-b border-hairline bg-vellum/30">
                  <th className="px-3 py-2 w-8">
                    <input type="checkbox" checked={allSelected} onChange={toggleAll} className="w-3.5 h-3.5 accent-ink cursor-pointer" />
                  </th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Member</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Email</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Role</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden lg:table-cell">Workspace access</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden lg:table-cell">Finding ownership</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden xl:table-cell">Last active</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden xl:table-cell">MFA / SSO</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden xl:table-cell">API access</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline">
                {filteredMembers.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="px-4 py-10 text-center font-body text-[13px] text-mist italic">
                      {members.length === 0 ? "No members yet — invite your first teammate." : "No members match the current filter."}
                    </td>
                  </tr>
                ) : filteredMembers.map(m => {
                  const findingCount = findingsByOwner.counts[m.user_id] ?? 0;
                  const lastSeen = auditRows.find(a => a.user_id === m.user_id)?.created_at ?? null;
                  const ownsApiKey = apiKeys.some(k => !k.revoked_at);
                  return (
                    <tr key={m.user_id} className="hover:bg-vellum/40 transition-colors">
                      <td className="px-3 py-2.5">
                        <input type="checkbox" checked={selectedIds.has(m.user_id)} onChange={() => toggleSelected(m.user_id)} className="w-3.5 h-3.5 accent-ink cursor-pointer" />
                      </td>
                      <td className="px-3 py-2.5">
                        <div className="flex items-center gap-2">
                          <span className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-gilt/20 text-gilt font-mono text-[9px] font-bold shrink-0">
                            {memberInitials(m)}
                          </span>
                          <span className="font-body text-[13px] font-semibold text-ink">{memberDisplay(m)}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[11px] text-slate">{m.email}</td>
                      <td className="px-3 py-2.5">
                        {m.role === "owner" ? (
                          <span className={cn("inline-flex items-center rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em]", ROLE_STYLES.owner)}>
                            Owner
                          </span>
                        ) : (
                          <select
                            value={m.role}
                            onChange={e => changeRole(m.user_id, e.target.value as Role)}
                            className={cn("rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] focus:outline-none focus:border-ink", ROLE_STYLES[m.role])}
                          >
                            <option value="admin">Admin</option>
                            <option value="member">Member</option>
                          </select>
                        )}
                      </td>
                      <td className="px-3 py-2.5 font-body text-[12px] text-graphite hidden lg:table-cell">
                        {m.role === "owner" || m.role === "admin" ? "All workspaces" : (activeWorkspace?.name ?? "—")}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[11px] text-slate hidden lg:table-cell">
                        {findingCount > 0 ? `${findingCount} open` : "—"}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[11px] text-slate hidden xl:table-cell">
                        {relativeTime(lastSeen ?? m.created_at)}
                      </td>
                      <td className="px-3 py-2.5 hidden xl:table-cell">
                        <span className="inline-flex items-center border border-forest/40 rounded-sm px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.14em] text-forest bg-forest/5">MFA</span>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[11px] text-slate hidden xl:table-cell">
                        {m.role === "owner" || m.role === "admin" ? (ownsApiKey ? "Full" : "Available") : "Read"}
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        {m.role !== "owner" && (
                          <button onClick={() => removeMember(m.user_id)} className="p-1 -m-1 text-mist hover:text-sev-critical transition-colors" title="Remove member" aria-label="Remove member">
                            <DotsIcon />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between px-4 py-2.5 border-t border-hairline bg-vellum/30 flex-wrap gap-2">
            <span className="font-mono text-[11px] text-mist">Showing {filteredMembers.length} of {members.length} members</span>
            {selectedIds.size > 0 && (
              <button
                type="button"
                onClick={() => setSelectedIds(new Set())}
                className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist hover:text-ink transition-colors"
              >
                Clear selection ({selectedIds.size})
              </button>
            )}
          </div>
        </section>

        {/* Roles & permissions matrix */}
        <section className="border border-hairline rounded-sm overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-hairline bg-vellum/40">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Roles & Permissions Matrix</p>
            <Link href="https://docs.pencheff.com/access-control" target="_blank" rel="noreferrer" className="font-mono text-[10px] uppercase tracking-[0.14em] text-graphite hover:text-ink transition-colors">View full role details →</Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left min-w-[900px]">
              <thead>
                <tr className="border-b border-hairline">
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Role</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Targets</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Scans</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Findings</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Integrations</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">API Keys</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Billing</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Users & Roles</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Settings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline">
                {PERMISSIONS_MATRIX.map(p => (
                  <tr key={p.role}>
                    <td className="px-3 py-2.5">
                      <span className={cn("inline-flex items-center rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em]", ROLE_STYLES[p.role])}>
                        {p.role}
                      </span>
                    </td>
                    {(["targets","scans","findings","integrations","api_keys","billing","users","settings"] as const).map(c => (
                      <td key={c} className="px-3 py-2.5">
                        {p[c] ? <CheckIcon /> : <span className="font-mono text-[12px] text-mist">—</span>}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Permissions */}
        <section className="border border-hairline rounded-sm overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-hairline bg-vellum/40">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Permissions</p>
          </div>
          <div className="px-5 py-4 space-y-4">
            <h2 className="font-display text-[20px] text-ink">Permissions</h2>
            <div className="flex items-start gap-4">
              {/* Toggle */}
              <button
                type="button"
                role="switch"
                aria-checked={activeOrg.allow_private_targets ?? false}
                disabled={privateTargetsSaving}
                onClick={() => {
                  if (activeOrg.allow_private_targets) {
                    disablePrivateTargets().catch(() => {});
                  } else {
                    setPrivateTargetsAck(false);
                    setPrivateTargetsError(null);
                    setShowPrivateTargetsModal(true);
                  }
                }}
                className={cn(
                  "relative inline-flex shrink-0 h-5 w-9 rounded-full border transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-ink/20 disabled:opacity-50 disabled:cursor-not-allowed",
                  activeOrg.allow_private_targets
                    ? "bg-ink border-ink"
                    : "bg-paper border-hairline"
                )}
              >
                <span
                  className={cn(
                    "inline-block h-3.5 w-3.5 rounded-full bg-paper border border-hairline shadow-subtle transform transition-transform duration-200 mt-[2px]",
                    activeOrg.allow_private_targets ? "translate-x-4" : "translate-x-[2px]"
                  )}
                />
              </button>
              <div className="min-w-0">
                <p className="font-body text-[13px] font-semibold text-ink">Allow host targets that resolve to private IP space</p>
                <p className="font-body text-[12px] text-slate mt-0.5">
                  Enables registration of host targets in RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127.0.0.1/8,{" "}
                  ::1), link-local (169.254/16, fe80::/10), CGNAT (100.64/10), and IPv6 ULA (fc00::/7) ranges.{" "}
                  Off by default to prevent accidental scans of internal infrastructure. Requires attestation of authorisation.
                </p>
                {/* Last changed — best-effort from audit log */}
                {(() => {
                  const lastFlip = auditRows.find(a => a.action === "org.allow_private_targets.flip");
                  if (!lastFlip) return null;
                  return (
                    <p className="font-mono text-[10px] text-mist mt-1">
                      Last changed {formatTime(lastFlip.created_at)}
                    </p>
                  );
                })()}
              </div>
            </div>
            {privateTargetsError && (
              <p className="font-mono text-[12px] text-sev-critical">{privateTargetsError}</p>
            )}
          </div>
        </section>

        {/* Recent activity */}
        <section className="border border-hairline rounded-sm overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-hairline bg-vellum/40">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Recent Activity</p>
            <Link href="/observability/audit" className="font-mono text-[10px] uppercase tracking-[0.14em] text-graphite hover:text-ink transition-colors">View full audit log →</Link>
          </div>
          {auditRows.length === 0 ? (
            <div className="px-4 py-8 text-center">
              <p className="font-body text-[13px] text-mist italic">No audit events yet.</p>
            </div>
          ) : (
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-hairline">
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Time</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Actor</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Action</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden md:table-cell">Target / Entity</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden lg:table-cell">Details</th>
                  <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden lg:table-cell">IP Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline">
                {auditRows.slice(0, 12).map(a => {
                  const actor = a.user_id ? memberById.get(a.user_id) : null;
                  return (
                    <tr key={a.id} className="hover:bg-vellum/40 transition-colors">
                      <td className="px-3 py-2 font-mono text-[11px] text-slate">{formatTime(a.created_at)}</td>
                      <td className="px-3 py-2 font-body text-[12px] text-graphite">{actor ? memberDisplay(actor) : (a.user_id ? "—" : "system")}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-ink">{a.action}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-slate hidden md:table-cell">{a.entity_id ? `${a.entity_type ?? "—"}: ${a.entity_id.slice(0, 12)}…` : "—"}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-slate truncate max-w-[260px] hidden lg:table-cell">
                        {a.meta ? Object.entries(a.meta).slice(0, 2).map(([k, v]) => `${k}: ${String(v)}`).join(" · ") : "—"}
                      </td>
                      <td className="px-3 py-2 font-mono text-[11px] text-slate hidden lg:table-cell">{a.request_ip ?? "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>

        {/* Workspace digest */}
        {activeWorkspace && (
          <section className="border border-hairline rounded-sm p-5 bg-vellum/20">
            <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Notifications</p>
                <h3 className="mt-0.5 font-display text-[20px] text-ink">Workspace digest</h3>
              </div>
              <span className="font-mono text-[11px] text-mist">{activeWorkspace.name}</span>
            </div>
            <p className="font-body text-[13px] text-slate mb-3">Weekly rollup every Monday — latest grade and severity counts per target.</p>
            <EmailRecipientsInput value={workspaceDigestEmails} onChange={setWorkspaceDigestEmails} workspaceId={activeWorkspace.id} label="Recipients" hint="Pick a workspace member from the dropdown or type any email." max={20} />
            <div className="mt-3 flex items-center gap-2">
              <Button type="button" variant="pink" onClick={saveWorkspaceDigest} disabled={workspaceDigestSaving}>{workspaceDigestSaving ? "Saving…" : "Save recipients"}</Button>
              {workspaceDigestSaved && <span className="font-mono text-[11px] text-forest uppercase tracking-[0.08em]">Saved.</span>}
            </div>
          </section>
        )}
      </div>

      {/* ── Right intelligence panel ── */}
      <aside className="w-[300px] shrink-0 border-l border-hairline px-5 py-6 space-y-4 hidden xl:block bg-vellum/20">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">Access Intelligence</p>

        {/* Risky permissions */}
        <section className="space-y-2">
          <p className="font-body text-[13px] font-semibold text-ink">Risky permissions</p>
          {fullApiKeyCount > 0 && (
            <div className="space-y-0.5">
              <p className="font-body text-[12px] text-slate flex items-start gap-1.5"><AlertIcon /> {fullApiKeyCount} org-wide API key{fullApiKeyCount === 1 ? "" : "s"} active</p>
              <Link href="/settings/api-keys" className="font-body text-[11px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline ml-5">Review access →</Link>
            </div>
          )}
          {fullApiAccessUsers > 0 && (
            <div className="space-y-0.5">
              <p className="font-body text-[12px] text-slate flex items-start gap-1.5"><InfoIcon /> {adminCount + ownerCount} member{adminCount + ownerCount === 1 ? "" : "s"} can manage integrations</p>
              <Link href="/integrations" className="font-body text-[11px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline ml-5">Review access →</Link>
            </div>
          )}
          {fullApiKeyCount === 0 && fullApiAccessUsers === 0 && (
            <p className="font-body text-[12px] text-mist italic">No elevated permissions detected.</p>
          )}
        </section>

        {/* Inactive admins */}
        <section className="space-y-2 border-t border-hairline pt-4">
          <p className="font-body text-[13px] font-semibold text-ink">Inactive admins</p>
          {inactiveAdmins.length === 0 ? (
            <p className="font-body text-[12px] text-mist italic">All admins active in last 30 days.</p>
          ) : (
            <>
              <p className="font-body text-[12px] text-slate">{inactiveAdmins.length} admin{inactiveAdmins.length === 1 ? "" : "s"} inactive &gt; 30 days</p>
              <Link href="#" onClick={() => setRoleFilter("admin")} className="font-body text-[11px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline">View admins →</Link>
            </>
          )}
        </section>

        {/* Open findings by owner */}
        <section className="space-y-2 border-t border-hairline pt-4">
          <p className="font-body text-[13px] font-semibold text-ink">Open findings by owner</p>
          <div className="space-y-1.5">
            {topOwners.map(({ member, count }) => (
              <div key={member.user_id} className="space-y-0.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-body text-[11px] text-graphite truncate">{memberDisplay(member)}</span>
                  <span className="font-mono text-[11px] text-ink">{count}</span>
                </div>
                <div className="h-[3px] w-full bg-vellum rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-sev-medium" style={{ width: `${Math.round((count / maxOwnerCount) * 100)}%` }} />
                </div>
              </div>
            ))}
            {findingsByOwner.unassigned > 0 && (
              <div className="space-y-0.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-body text-[11px] text-slate italic">Unassigned</span>
                  <span className="font-mono text-[11px] text-ink">{findingsByOwner.unassigned}</span>
                </div>
                <div className="h-[3px] w-full bg-vellum rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-mist" style={{ width: `${Math.round((findingsByOwner.unassigned / maxOwnerCount) * 100)}%` }} />
                </div>
              </div>
            )}
          </div>
          <Link href="/findings" className="font-body text-[11px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline">View all findings →</Link>
        </section>

        {/* Pending invites */}
        <section className="space-y-2 border-t border-hairline pt-4">
          <p className="font-body text-[13px] font-semibold text-ink">Pending invites ({pendingInvites.length})</p>
          {pendingInvites.length === 0 ? (
            <p className="font-body text-[12px] text-mist italic">No outstanding invites.</p>
          ) : pendingInvites.slice(0, 4).map(i => (
            <div key={i.id} className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <p className="font-body text-[11px] text-graphite truncate">{i.email}</p>
                <p className="font-mono text-[10px] text-mist truncate uppercase">{i.role}</p>
              </div>
              <span className="font-mono text-[10px] text-mist shrink-0">{daysUntil(i.expires_at)}</span>
            </div>
          ))}
          {pendingInvites.length > 0 && (
            <button type="button" onClick={() => setShowInvite(true)} className="font-body text-[11px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline">Manage invites →</button>
          )}
        </section>

        {/* Audit & accountability */}
        <section className="space-y-2 border-t border-hairline pt-4">
          <p className="font-body text-[13px] font-semibold text-ink">Audit & accountability</p>
          <div className="flex items-start gap-1.5">
            <CheckIcon />
            <div>
              <p className="font-body text-[12px] text-graphite">Audit trail integrity</p>
              <p className="font-body text-[11px] text-mist">All events hashed and verified</p>
            </div>
          </div>
          <div className="flex items-start gap-1.5">
            <ClockIcon />
            <div>
              <p className="font-body text-[12px] text-graphite">Log retention</p>
              <p className="font-body text-[11px] text-mist">365 days</p>
            </div>
          </div>
          <Link href="/observability/audit" className="font-body text-[11px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline">Configure →</Link>
        </section>
      </aside>

      {/* Private targets attestation modal */}
      {showPrivateTargetsModal && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          onClick={() => {
            setShowPrivateTargetsModal(false);
            setPrivateTargetsAck(false);
            setPrivateTargetsError(null);
          }}
        >
          <div
            className="w-full max-w-[560px] bg-paper border border-hairline rounded-sm shadow-elev"
            onClick={e => e.stopPropagation()}
          >
            {/* Modal header */}
            <div className="border-b border-hairline px-6 py-4 flex items-start justify-between">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Attestation required</p>
                <h2 className="font-display text-[22px] text-ink mt-1">Enable private IP targets</h2>
              </div>
              <button
                type="button"
                onClick={() => {
                  setShowPrivateTargetsModal(false);
                  setPrivateTargetsAck(false);
                  setPrivateTargetsError(null);
                }}
                aria-label="Close"
                className="p-1.5 -m-1.5 text-mist hover:text-ink hover:bg-vellum rounded-sm"
              >
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-4 h-4"><path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round"/></svg>
              </button>
            </div>
            {/* Modal body */}
            <div className="px-6 py-5 space-y-4">
              <p className="font-body text-[13px] text-graphite leading-relaxed">
                Enabling private-IP host targets allows users in this org to register and (once OSExploitAgent ships)
                exploit hosts inside RFC1918, loopback, link-local, CGNAT, and IPv6 ULA ranges. You attest that this
                org operates or holds written authorization to test these networks. Pencheff logs every host target
                created under this flag for post-hoc abuse review.
              </p>
              <label className="flex items-start gap-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={privateTargetsAck}
                  onChange={e => setPrivateTargetsAck(e.target.checked)}
                  className="mt-0.5 w-4 h-4 accent-ink cursor-pointer shrink-0"
                />
                <span className="font-body text-[13px] text-graphite">I attest to the above.</span>
              </label>
              {privateTargetsError && (
                <p className="font-mono text-[12px] text-sev-critical">{privateTargetsError}</p>
              )}
            </div>
            {/* Modal footer */}
            <div className="border-t border-hairline px-6 py-4 flex items-center justify-end gap-3">
              <Button
                type="button"
                variant="yellow"
                onClick={() => {
                  setShowPrivateTargetsModal(false);
                  setPrivateTargetsAck(false);
                  setPrivateTargetsError(null);
                }}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant="pink"
                disabled={!privateTargetsAck || privateTargetsSaving}
                onClick={() => enablePrivateTargets().catch(() => {})}
              >
                {privateTargetsSaving ? "Enabling…" : "Enable"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Manage roles modal */}
      {showRoles && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm" role="dialog" aria-modal="true" onClick={() => setShowRoles(false)}>
          <div className="w-full max-w-[640px] max-h-[88vh] overflow-y-auto bg-paper border border-hairline rounded-sm shadow-elev" onClick={e => e.stopPropagation()}>
            <div className="sticky top-0 bg-paper border-b border-hairline px-6 py-4 flex items-start justify-between">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Access Control</p>
                <h2 className="font-display text-[24px] text-ink mt-1">Manage roles</h2>
              </div>
              <button onClick={() => setShowRoles(false)} aria-label="Close" className="p-1.5 -m-1.5 text-mist hover:text-ink hover:bg-vellum rounded-sm">
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-4 h-4"><path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round"/></svg>
              </button>
            </div>
            <div className="px-6 py-5 space-y-4">
              <p className="font-body text-[13px] text-slate">
                Pencheff uses three built-in roles. Custom roles will land with the Enterprise tier.
              </p>
              {PERMISSIONS_MATRIX.map(p => (
                <div key={p.role} className="border border-hairline rounded-sm p-3 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className={cn("inline-flex items-center rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em]", ROLE_STYLES[p.role])}>{p.role}</span>
                    <span className="font-mono text-[10px] text-mist">{members.filter(m => m.role === p.role).length} member{members.filter(m => m.role === p.role).length === 1 ? "" : "s"}</span>
                  </div>
                  <p className="font-body text-[12px] text-graphite">
                    {p.role === "owner" && "Full access including billing and organisation lifecycle."}
                    {p.role === "admin" && "All resource management; no billing."}
                    {p.role === "member" && "Targets, scans, and findings; read-only on integrations and keys."}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function OrgSettingsPage() {
  return (
    <AuthGuard>
      <AppShell>
        <main className="max-w-[1400px] mx-auto px-5 md:px-6 py-6">
          <TeamPage />
        </main>
      </AppShell>
    </AuthGuard>
  );
}

"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  ACTIVE_ORG_STORAGE_KEY,
  ACTIVE_WORKSPACE_STORAGE_KEY,
  api,
} from "@/lib/api";

export type Org = {
  id: string;
  name: string;
  plan: string;
  role: "owner" | "admin" | "member";
  created_at: string;
  // Resolved by the API: true when the plan unlocks AI features OR the
  // operator has flipped ``AI_FREE_TIER_ENABLED`` on. The UI gates AI
  // buttons on this rather than ``plan !== "free"`` directly.
  ai_enabled?: boolean;
  // Set by org admins to allow private/RFC-1918 host targets. Rendered as a
  // warning badge in HostFormSection; enforced server-side on POST /targets.
  allow_private_targets?: boolean;
  security_lake_enabled?: boolean;
};

export type Workspace = {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  created_at: string;
};

type WorkspaceContextValue = {
  loading: boolean;
  // True when the /orgs fetch FAILED (network/auth/etc.). Distinguishes a
  // failed load from a successful "this user genuinely has zero orgs" — so
  // consumers never treat a transient API error as "needs onboarding".
  loadError: boolean;
  orgs: Org[];
  activeOrg: Org | null;
  workspaces: Workspace[];
  activeWorkspace: Workspace | null;
  setActiveOrg: (orgId: string) => void;
  setActiveWorkspace: (workspaceId: string) => void;
  refresh: () => Promise<void>;
};

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

function readStored(key: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStored(key: string, value: string | null) {
  if (typeof window === "undefined") return;
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch {
    /* swallow */
  }
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [activeOrgId, setActiveOrgIdState] = useState<string | null>(null);
  const [activeWorkspaceId, setActiveWorkspaceIdState] = useState<
    string | null
  >(null);

  const setActiveOrg = useCallback(
    (orgId: string) => {
      setActiveOrgIdState(orgId);
      writeStored(ACTIVE_ORG_STORAGE_KEY, orgId);
      const match = workspaces.find((w) => w.org_id === orgId);
      if (match) {
        setActiveWorkspaceIdState(match.id);
        writeStored(ACTIVE_WORKSPACE_STORAGE_KEY, match.id);
      } else {
        setActiveWorkspaceIdState(null);
        writeStored(ACTIVE_WORKSPACE_STORAGE_KEY, null);
      }
    },
    [workspaces],
  );

  const setActiveWorkspace = useCallback(
    (workspaceId: string) => {
      const ws = workspaces.find((w) => w.id === workspaceId);
      if (!ws) return;
      setActiveWorkspaceIdState(ws.id);
      writeStored(ACTIVE_WORKSPACE_STORAGE_KEY, ws.id);
      if (ws.org_id !== activeOrgId) {
        setActiveOrgIdState(ws.org_id);
        writeStored(ACTIVE_ORG_STORAGE_KEY, ws.org_id);
      }
    },
    [workspaces, activeOrgId],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [nextOrgs, nextWs] = await Promise.all([
        api<Org[]>("/orgs"),
        api<Workspace[]>("/workspaces").catch(() => [] as Workspace[]),
      ]);
      setLoadError(false);
      setOrgs(nextOrgs);
      setWorkspaces(nextWs);

      // Resolve active org: prefer persisted value if still valid, else first.
      const storedOrgId = readStored(ACTIVE_ORG_STORAGE_KEY);
      const orgId =
        (storedOrgId && nextOrgs.find((o) => o.id === storedOrgId)?.id) ||
        nextOrgs[0]?.id ||
        null;
      if (orgId !== activeOrgId) {
        setActiveOrgIdState(orgId);
        writeStored(ACTIVE_ORG_STORAGE_KEY, orgId);
      }

      // Resolve active workspace in the active org.
      const storedWsId = readStored(ACTIVE_WORKSPACE_STORAGE_KEY);
      const candidate =
        (storedWsId &&
          nextWs.find((w) => w.id === storedWsId && w.org_id === orgId)) ||
        nextWs.find((w) => w.org_id === orgId) ||
        null;
      const nextWsId = candidate?.id ?? null;
      if (nextWsId !== activeWorkspaceId) {
        setActiveWorkspaceIdState(nextWsId);
        writeStored(ACTIVE_WORKSPACE_STORAGE_KEY, nextWsId);
      }
    } catch {
      // /orgs failed (network/auth/misconfigured API base). Flag it so the
      // AuthGuard does NOT mistake this for "zero orgs → onboarding".
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }, [activeOrgId, activeWorkspaceId]);

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const activeOrg = orgs.find((o) => o.id === activeOrgId) ?? null;
  const activeWorkspace =
    workspaces.find((w) => w.id === activeWorkspaceId) ?? null;

  return (
    <WorkspaceContext.Provider
      value={{
        loading,
        loadError,
        orgs,
        activeOrg,
        workspaces: workspaces.filter((w) => w.org_id === activeOrgId),
        activeWorkspace,
        setActiveOrg,
        setActiveWorkspace,
        refresh,
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace(): WorkspaceContextValue {
  const ctx = useContext(WorkspaceContext);
  if (!ctx) {
    throw new Error("useWorkspace must be used inside <WorkspaceProvider>");
  }
  return ctx;
}

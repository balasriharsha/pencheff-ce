"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { AuthGuard } from "@/components/auth-guard";
import { AppShell } from "@/components/nav";
import { Button, Card, Input, Label } from "@/components/brutal";
import { api } from "@/lib/api";
import { useWorkspace, type Workspace } from "@/lib/workspace-context";

function NewWorkspaceForm() {
  const router = useRouter();
  const { activeOrg, refresh, setActiveWorkspace } = useWorkspace();
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!activeOrg || !name.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const ws = await api<Workspace>("/workspaces", {
        method: "POST",
        json: { org_id: activeOrg.id, name: name.trim() },
      });
      await refresh();
      setActiveWorkspace(ws.id);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed");
      setSubmitting(false);
    }
  }

  if (!activeOrg) {
    return <p className="text-slate">Select an organisation first.</p>;
  }

  return (
    <div className="max-w-lg">
      <p className="eyebrow">New workspace in {activeOrg.name}</p>
      <h1 className="mt-3 font-display text-[24px] md:text-[32px] leading-[1.1] text-ink">
        Create a workspace
      </h1>
      <p className="mt-3 text-[14px] text-slate leading-relaxed">
        Workspaces isolate targets, scans, and findings. Teams commonly use one
        per product, environment, or customer engagement. Your plan's workspace
        limit applies.
      </p>
      <Card className="mt-8">
        <form onSubmit={onSubmit} className="space-y-5">
          <div>
            <Label htmlFor="ws-name">Workspace name</Label>
            <Input
              id="ws-name"
              placeholder="Production"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              autoFocus
              maxLength={200}
            />
          </div>
          {error && (
            <p className="text-[13px] text-oxblood font-mono">{error}</p>
          )}
          <div className="flex gap-3">
            <Button
              type="submit"
              variant="pink"
              disabled={submitting}
              className="flex-1"
            >
              {submitting ? "Creating…" : "Create workspace"}
            </Button>
            <Button
              type="button"
              variant="yellow"
              onClick={() => router.back()}
              disabled={submitting}
            >
              Cancel
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

export default function NewWorkspacePage() {
  return (
    <AuthGuard>
      <AppShell>
        <main className="max-w-[1400px] mx-auto px-5 md:px-6 py-6">
          <NewWorkspaceForm />
        </main>
      </AppShell>
    </AuthGuard>
  );
}

"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useAuth } from "@clerk/react";
import { Button, Card, Input, Label } from "@/components/brutal";
import { api } from "@/lib/api";
import { useWorkspace, type Org } from "@/lib/workspace-context";

export default function OnboardingPage() {
  const { isLoaded, isSignedIn } = useAuth();
  const router = useRouter();
  const { orgs, loading, refresh, setActiveOrg, setActiveWorkspace } =
    useWorkspace();
  const [orgName, setOrgName] = useState("");
  const [workspaceName, setWorkspaceName] = useState("Default");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoaded) return;
    if (!isSignedIn) router.replace("/login");
  }, [isLoaded, isSignedIn, router]);

  // If the user already has an org, onboarding is done.
  useEffect(() => {
    if (!loading && orgs.length > 0) router.replace("/dashboard");
  }, [loading, orgs, router]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!orgName.trim() || !workspaceName.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const org = await api<Org>("/orgs", {
        method: "POST",
        json: {
          name: orgName.trim(),
          first_workspace_name: workspaceName.trim(),
        },
      });
      await refresh();
      setActiveOrg(org.id);
      // After refresh() the new workspace is in state; pick the first one
      // in the new org.
      const fresh = await api<
        { id: string; org_id: string }[]
      >(`/workspaces?org_id=${encodeURIComponent(org.id)}`);
      if (fresh[0]) setActiveWorkspace(fresh[0].id);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to create org");
      setSubmitting(false);
    }
  }

  if (!isLoaded || !isSignedIn) return null;

  return (
    <main className="min-h-screen bg-canvas flex items-center justify-center px-6 py-16">
      <div className="max-w-lg w-full">
        <p className="eyebrow">Welcome</p>
        <h1 className="mt-3 font-display text-[28px] md:text-[40px] leading-[1.1] text-ink tracking-[-0.01em]">
          Create your organisation
        </h1>
        <p className="mt-4 text-[15px] text-slate leading-relaxed">
          An organisation owns your billing and your team. Inside it, you'll
          create one or more <em>workspaces</em> — each containing its own
          targets, scans, and assets.
        </p>

        <Card className="mt-8">
          <form onSubmit={onSubmit} className="space-y-6">
            <div>
              <Label htmlFor="org-name">Organisation name</Label>
              <Input
                id="org-name"
                placeholder="Acme Inc."
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                autoFocus
                required
                maxLength={200}
              />
              <p className="mt-2 text-[12px] text-mist">
                This is the legal / business name that appears on invoices.
              </p>
            </div>

            <div>
              <Label htmlFor="workspace-name">First workspace</Label>
              <Input
                id="workspace-name"
                placeholder="Default"
                value={workspaceName}
                onChange={(e) => setWorkspaceName(e.target.value)}
                required
                maxLength={200}
              />
              <p className="mt-2 text-[12px] text-mist">
                Start simple — e.g. "Production" or "QA". You can add more
                workspaces later (limit depends on plan).
              </p>
            </div>

            {error && (
              <p className="text-[13px] text-oxblood font-mono">{error}</p>
            )}

            <Button
              type="submit"
              variant="pink"
              className="w-full"
              disabled={submitting}
            >
              {submitting ? "Creating…" : "Create organisation"}
            </Button>
          </form>
        </Card>
      </div>
    </main>
  );
}

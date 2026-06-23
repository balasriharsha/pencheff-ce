"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { useAuth } from "@clerk/react";
import { AppShell } from "@/components/nav";
import { Button, Card } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { api } from "@/lib/api";
import { useWorkspace } from "@/lib/workspace-context";

type InviteDetail = {
  id: string;
  email: string;
  role: string;
  expires_at: string;
  accepted_at: string | null;
};

type OrgOut = {
  id: string;
  name: string;
  plan: string;
};

export default function InviteAcceptPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const token = mounted ? pathSegment(pathname, 2) : "";
  const { isLoaded, isSignedIn } = useAuth();
  const router = useRouter();
  const { refresh, setActiveOrg } = useWorkspace();
  const [invite, setInvite] = useState<InviteDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!token) return;
    api<InviteDetail>(`/invites/${token}`)
      .then(setInvite)
      .catch((e) =>
        setError(e instanceof Error ? e.message : "invalid invite"),
      );
  }, [token]);

  async function onAccept() {
    if (!token) return;
    setSubmitting(true);
    setError(null);
    try {
      const org = await api<OrgOut>(`/invites/${token}/accept`, {
        method: "POST",
      });
      await refresh();
      setActiveOrg(org.id);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "accept failed");
      setSubmitting(false);
    }
  }

  const content = (
    <main className="max-w-[720px] mx-auto px-6 md:px-10 py-16">
      <p className="eyebrow">Invitation</p>
      <h1 className="mt-3 font-display text-[24px] md:text-[32px] leading-[1.1] text-ink">
        Join an organisation
      </h1>

      <Card className="mt-8">
        {error && (
          <p className="text-[13px] text-oxblood font-mono mb-4">{error}</p>
        )}
        {invite ? (
          <>
            <p className="text-[15px] text-graphite">
              You've been invited to join as <strong>{invite.role}</strong>. The
              invite is addressed to{" "}
              <span className="font-mono">{invite.email}</span>.
            </p>
            <p className="mt-3 text-[13px] text-mist">
              Expires {new Date(invite.expires_at).toLocaleString()}
            </p>
            <div className="mt-6 flex gap-3">
              {isLoaded && !isSignedIn && (
                <Button
                  variant="pink"
                  onClick={() =>
                    (window.location.href = `/login?redirect_url=${encodeURIComponent(
                      window.location.pathname,
                    )}`)
                  }
                >
                  Sign in to accept
                </Button>
              )}
              {isLoaded && isSignedIn && (
                <Button
                  variant="pink"
                  disabled={submitting || !!invite.accepted_at}
                  onClick={onAccept}
                >
                  {invite.accepted_at
                    ? "Already accepted"
                    : submitting
                      ? "Accepting…"
                      : "Accept invite"}
                </Button>
              )}
            </div>
          </>
        ) : !error ? (
          <InlineLoading label="Loading invite…" />
        ) : null}
      </Card>
    </main>
  );
  if (isSignedIn) return <AppShell>{content}</AppShell>;
  return content;
}

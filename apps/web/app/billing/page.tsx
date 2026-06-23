"use client";

import { useAuth, useClerk, useUser } from "@clerk/react";
import { Button } from "@/components/brutal";
import { PricingPlans } from "@/components/pricing-content";

const LOCAL_PLAN_LABEL: Record<string, string> = {
  free: "Free",
  pro: "Pro",
  team: "Team",
};

function currentLocalPlanId(has: ReturnType<typeof useAuth>["has"]): string {
  if (!has) return "free";
  if (has({ plan: "team" })) return "team";
  if (has({ plan: "pro" })) return "pro";
  return "free";
}

export default function BillingPage() {
  const { has, isLoaded } = useAuth();
  const { user } = useUser();
  const clerk = useClerk();

  const currentPlan = isLoaded ? currentLocalPlanId(has) : null;

  function manageSubscription() {
    // Clerk's UserProfile modal exposes a Billing / Subscription section
    // once billing is enabled on the instance; this is the canonical
    // stable way to let users change plans without leaving the app.
    clerk.openUserProfile();
  }

  return (
    <div className="space-y-16">
      {/* --- Header ------------------------------------------------- */}
      <header className="flex items-end justify-between flex-wrap gap-6">
        <div>
          <p className="eyebrow-gilt">Account</p>
          <h1 className="mt-4 font-display text-[40px] md:text-[48px] leading-[1.05] tracking-[-0.015em] text-ink">
            Billing
          </h1>
          {user && (
            <p className="mt-3 text-[14px] text-slate">
              Signed in as{" "}
              <span className="text-graphite font-medium">
                {user.primaryEmailAddress?.emailAddress ?? user.id}
              </span>
              {currentPlan && (
                <>
                  {" "}· current plan{" "}
                  <span className="inline-flex items-center gap-1 border border-hairline rounded-sm px-2 py-0.5 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate bg-vellum ml-1">
                    <span className="w-1 h-1 rounded-full bg-gilt" aria-hidden />
                    {LOCAL_PLAN_LABEL[currentPlan]}
                  </span>
                </>
              )}
            </p>
          )}
        </div>
        <Button variant="lime" onClick={manageSubscription}>
          Manage subscription
        </Button>
      </header>

      {/* --- Plan cards -------------------------------------------- */}
      <section>
        <div className="flex items-end justify-between flex-wrap gap-4 mb-6">
          <div>
            <p className="eyebrow">Subscriptions</p>
            <h2 className="mt-2 font-display text-[24px] text-ink">
              Tier &amp; entitlements
            </h2>
          </div>
          <span className="font-mono text-[12px] text-mist max-w-[46ch] text-right">
            Plans are managed by our billing partner. Switching opens a secure
            checkout.
          </span>
        </div>

        <PricingPlans
          currentPlanId={currentPlan}
          onSelect={() => manageSubscription()}
        />
      </section>

      {/* --- Self-hosted advisory --------------------------------- */}
      <section>
        <div className="advisory">
          <p className="eyebrow-gilt mb-3 text-[10px]">
            Self-hosted deployments
          </p>
          <p className="text-[14px] text-slate leading-[1.65] max-w-[62ch]">
            Pencheff may be self-hosted under an MIT licence. Billing is a
            no-op in that configuration — set the organisation&rsquo;s plan to{" "}
            <span className="font-mono text-graphite">self_hosted</span> in the
            database to unlock all limits.
          </p>
        </div>
      </section>
    </div>
  );
}

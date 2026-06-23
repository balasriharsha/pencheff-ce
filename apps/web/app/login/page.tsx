import Link from "next/link";
import "@/styles/landing.css";
import { LandingNav } from "@/components/landing-nav";
import { LandingEffects } from "@/components/landing-effects";
import { MarketingAuthPageShell } from "@/components/marketing-auth-shell";
import { authRouteMetadata } from "@/lib/seo";
import { SignInBox } from "@/components/sign-in-box";

export const metadata = authRouteMetadata(
  "Sign in",
  "Sign in to Pencheff to access assessments, findings, reports, workspaces, integrations, and security evidence.",
  "/login",
);

export default function LoginPage() {
  return (
    <div className="landing-root">
      <LandingEffects />
      <LandingNav />

      <MarketingAuthPageShell
        eyebrow="Secure sign-in"
        title="Welcome back."
        lede="Access your assessments, findings, reports, workspaces, integrations, and security evidence."
        proofTitle="Return to your security workspace"
        proofRows={[
          { text: "Resume running assessments and retests.", label: "Scans" },
          {
            text: "Review verified findings, evidence, and comments.",
            label: "Evidence",
          },
          {
            text: "Export executive, technical, and compliance reports.",
            label: "Reports",
          },
        ]}
        contextPanels={[
          {
            title: "Secure by default",
            body: "Authentication stays delegated to Clerk, with workspace access controlled after sign-in.",
          },
          {
            title: "Fast continuation",
            body: "Fallback redirect returns signed-in users to the dashboard.",
          },
        ]}
        switchNote={
          <>
            No account yet?{" "}
            <Link className="lp-auth-link" href="/signup">
              Open an account
            </Link>
            .
          </>
        }
      >
        <SignInBox />
      </MarketingAuthPageShell>
    </div>
  );
}

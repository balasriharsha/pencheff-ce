import Link from "next/link";
import "@/styles/landing.css";
import { LandingNav } from "@/components/landing-nav";
import { LandingEffects } from "@/components/landing-effects";
import { MarketingAuthPageShell } from "@/components/marketing-auth-shell";
import { authRouteMetadata } from "@/lib/seo";
import { SignUpBox } from "@/components/sign-up-box";

export const metadata = authRouteMetadata(
  "Open an Account",
  "Create a Pencheff account to run authorized security assessments and generate evidence-backed reports.",
  "/signup",
);

export default function SignupPage() {
  return (
    <div className="landing-root">
      <LandingEffects />
      <LandingNav />

      <MarketingAuthPageShell
        eyebrow="Open an account"
        title="Start with authorized assessments."
        lede="Create a Pencheff account to run authorized security assessments and generate evidence-backed reports."
        proofTitle="What happens after signup"
        proofRows={[
          {
            text: "Create a workspace and register your first target.",
            label: "Target",
          },
          {
            text: "Choose URL, repo, AI, API, cloud, or package scope.",
            label: "Scope",
          },
          {
            text: "Run the complimentary tier with no card required.",
            label: "Beta",
          },
        ]}
        contextPanels={[
          {
            title: "No card required",
            body: "Keep the current complimentary-tier message visible near account creation.",
          },
          {
            title: "Authorized only",
            body: "Set the expectation that testing must stay inside permitted security scope.",
          },
        ]}
        switchNote={
          <>
            Already registered?{" "}
            <Link className="lp-auth-link" href="/login">
              Sign in
            </Link>
            .
          </>
        }
      >
        <SignUpBox />
      </MarketingAuthPageShell>
    </div>
  );
}

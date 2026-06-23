"use client";

import Link from "next/link";
import { Button } from "@/components/brutal";
import { PRO_PRICE, PLAN_QUOTAS, inr, usd } from "@/lib/pricing";

type Plan = {
  id: string;
  name: string;
  eyebrow: string;
  price: string;
  cadence: string;
  highlighted?: boolean;
  comingSoon?: boolean;
  /** Renders the CTA as a "Contact us" mailto rather than an in-app
   * checkout button. Used by Team while pricing is bespoke. */
  contactSales?: boolean;
  tagline: string;
  bullets: string[];
  cta: string;
};

const TEAM_CONTACT_HREF =
  "mailto:balasriharsha.ch@gmail.com?subject=Pencheff%20Team%20enquiry";

/** Mirrors the landing-page tier copy. Free has every feature unlocked
 * during beta; Pro adds the autonomous remediation pipeline and is
 * announced as coming soon; Team is bespoke pricing — sales contact,
 * not Clerk checkout. */
const PLANS: Plan[] = [
  {
    id: "free",
    name: "Free",
    eyebrow: "Free forever",
    price: inr(0),
    cadence: "/mo · $0",
    highlighted: true,
    tagline:
      "The full platform, metered. Sign up, paste a URL or connect a repo, and run the pipeline — with a monthly allowance to see Pencheff in action.",
    bullets: [
      `${PLAN_QUOTAS.free.scans} security scans / month`,
      `${PLAN_QUOTAS.free.fixes} AI auto-fixes / month (${PLAN_QUOTAS.free.model} model)`,
      "Web DAST — full OWASP Top 10 coverage with manual-grade exploitation",
      "Repo scanning (GitHub URL or local folder) — Semgrep OSS + OSV advisories",
      "Secrets detection (gitleaks), YARA, Trivy IaC, Checkov",
      "SBOM generation (SPDX 2.3, CycloneDX 1.5) for dependency evidence bundles",
      "Threat models (STRIDE / DREAD) attached to engagements",
      "Compliance mapping (OWASP · PCI-DSS · SOC 2 · NIST · ISO 27001 · HIPAA)",
      "Formal DOCX & PDF reports, JSON & CSV export",
      "Per-finding re-examination, suppression, and workflow",
      "Role-based access (owner · admin · member)",
    ],
    cta: "Open an account",
  },
  {
    id: "pro",
    name: "Pro",
    eyebrow: "Most popular",
    price: inr(PRO_PRICE.inr),
    cadence: `/mo · ${usd(PRO_PRICE.usd)}`,
    highlighted: false,
    tagline:
      "Pencheff doesn't just find vulnerabilities — it fixes them. The Expert model, a generous monthly allowance, and verified pull requests.",
    bullets: [
      `${PLAN_QUOTAS.pro.scans} security scans / month`,
      `${PLAN_QUOTAS.pro.fixes} AI auto-fixes / month (${PLAN_QUOTAS.pro.model} model)`,
      "Automated remediation — opens a single PR that fixes every triaged finding",
      "DAST exploitation — proves impact with verified PoCs, not scanner noise",
      "SAST auto-patching — semantic, reviewer-friendly diffs grounded in scanner evidence",
      "AI Triage 2.0 — per-finding walkthroughs and grading",
      "Priority correspondence and a private Slack channel",
      "Everything in Free, scaled for production teams",
    ],
    cta: "Upgrade to Pro",
  },
  {
    id: "team",
    name: "Team",
    eyebrow: "For organisations",
    price: "Custom",
    cadence: "talk to us",
    contactSales: true,
    tagline:
      "When security is a shared responsibility. Unlimited workspaces, unlimited seats, dedicated support, and the full Pro feature set at general availability.",
    bullets: [
      "Unlimited workspaces, seats, and registered targets",
      "Branded reporting & custom compliance mappings",
      "Single sign-on (SAML / OIDC)",
      "Dedicated Slack correspondence channel",
      "Priority vulnerability response & onboarding",
      "Full automated remediation pipeline at general availability with SLAs",
      "Custom data residency & deployment options",
    ],
    cta: "Contact us",
  },
];

const FAQ: { q: string; a: string }[] = [
  {
    q: "What's included in Free?",
    a: "Free gives you 5 security scans and 3 AI auto-fixes every month, served by the Instant model — plus the full scanning surface (DAST, repo scanning, IaC, SBOM, threat models, compliance mapping, and reporting). No card required. Quotas reset on the 1st of each month.",
  },
  {
    q: "What ships in Pro?",
    a: "Pro is ₹499/month (about $5.99) and raises your allowance to 20 scans and 40 AI auto-fixes per month, served by the more capable Expert model. It also unlocks the full automated-remediation pipeline (a single PR that fixes every triaged finding), DAST exploitation with verified PoCs, and AI Triage 2.0.",
  },
  {
    q: "When do my limits reset?",
    a: "Scan and fix allowances reset on the 1st of every calendar month (UTC). Scans are counted per organisation, so adding workspaces doesn't change your monthly allowance.",
  },
  {
    q: "Is this authorised?",
    a: "Pencheff is for applications you own or have been granted written permission to assess. It is an instrument of assurance, not a means of unauthorised access. Please direct it only at systems within your mandate.",
  },
  {
    q: "What constitutes a single assessment?",
    a: "One complete engagement against a target — reconnaissance, infrastructure, injection, client-side, authentication, authorisation, advanced web, API, business logic, cloud, file handling, websocket, subdomain takeover, and exploit chaining. Re-examination of individual findings is unlimited.",
  },
  {
    q: "How long does an assessment take?",
    a: "Quick profile: 2–5 minutes. Standard: 10–25 minutes. Deep: 30–90 minutes, contingent on application breadth.",
  },
  {
    q: "May these reports be used for SOC 2, PCI, or ISO audits?",
    a: "Yes. DOCX and PDF reports include evidence-backed mapping to OWASP Top 10 (2021), PCI-DSS 4.0, NIST 800-53, SOC 2 (CC6/CC7), ISO 27001:2022, and HIPAA Security Rule — accepted by auditors as evidentiary material.",
  },
  {
    q: "Is self-hosting supported?",
    a: "Yes. Pencheff is distributed as a Docker Compose stack under an MIT licence. Refer to the repository documentation for installation.",
  },
  {
    q: "How are credentials handled?",
    a: "Credentials are encrypted at rest with Fernet (AES-128 in CBC mode with HMAC-SHA256). Removing a target removes its credentials immediately.",
  },
];

const COMPARE_ROWS: [string, string, string, string][] = [
  ["Security scans / month", "5", "20", "Unlimited"],
  ["AI auto-fixes / month", "3", "40", "Unlimited"],
  ["AI model", "Instant", "Expert", "Expert"],
  ["Web DAST (OWASP Top 10, exploitation-grade)", "·", "·", "·"],
  ["Repo scanning — Semgrep OSS + OSV advisories", "·", "·", "·"],
  ["IaC + container scanning (Trivy, Checkov)", "·", "·", "·"],
  ["Authenticated assessments (encrypted credentials)", "·", "·", "·"],
  ["Compliance mapping (OWASP · PCI · SOC 2 · NIST · ISO · HIPAA)", "·", "·", "·"],
  ["Formal DOCX & PDF reports", "·", "·", "Branded"],
  ["Per-finding re-examination, suppression & workflow", "·", "·", "·"],
  ["Automated remediation — fix-PR for every finding", "—", "·", "·"],
  ["DAST exploitation — verified PoCs", "—", "·", "·"],
  ["SAST Auto-Patching (semantic diffs)", "—", "·", "·"],
  ["Continuous scan-on-push loop", "—", "·", "·"],
  ["Single sign-on (SAML / OIDC)", "—", "—", "·"],
  ["Dedicated Slack channel & priority response", "—", "—", "·"],
  ["Custom data residency & deployment", "—", "—", "·"],
];

/** Map a local plan id ("free" / "pro" / "team") to the Clerk plan key. */
export const LOCAL_TO_CLERK_PLAN: Record<string, string> = {
  free: "free_user",
  pro: "pro",
  team: "team",
};

type PricingPlansProps = {
  /**
   * When provided (signed-in billing mode) the CTA becomes a button that calls
   * ``onSelect(planId)`` instead of a marketing link. The card matching
   * ``currentPlanId`` is rendered as the active subscription with a gilt
   * ribbon and a disabled "Current plan" button.
   */
  currentPlanId?: string | null;
  onSelect?: (planId: string) => void;
};

export function PricingPlans({ currentPlanId, onSelect }: PricingPlansProps = {}) {
  const billingMode = !!onSelect;

  return (
    <div className="grid md:grid-cols-3 gap-px bg-hairline border border-hairline rounded-md overflow-hidden">
      {PLANS.map((p) => {
        const isCurrent = billingMode && currentPlanId === p.id;
        // In marketing mode Beta is highlighted; in billing mode the active
        // subscription takes that role instead.
        const highlight = billingMode ? isCurrent : p.highlighted;
        const eyebrow = isCurrent
          ? "Current subscription"
          : p.eyebrow;

        let cta: React.ReactNode;
        if (p.comingSoon) {
          cta = (
            <Button
              variant="lime"
              className="w-full"
              disabled
              aria-disabled="true"
            >
              {p.cta}
            </Button>
          );
        } else if (p.contactSales) {
          // Team is bespoke pricing — open a sales email regardless of
          // marketing vs in-app billing mode. No Clerk checkout flow.
          cta = (
            <a href={TEAM_CONTACT_HREF} className="block">
              <Button
                variant={highlight ? "pink" : "lime"}
                className="w-full"
              >
                {p.cta}
              </Button>
            </a>
          );
        } else if (billingMode) {
          cta = (
            <Button
              variant={highlight ? "pink" : "lime"}
              className="w-full"
              disabled={isCurrent}
              onClick={() => onSelect!(p.id)}
            >
              {isCurrent ? "Current plan" : `Switch to ${p.name}`}
            </Button>
          );
        } else {
          cta = (
            <Link href={p.id === "free" ? "/signup" : `/signup?plan=${p.id}`}>
              <Button
                variant={highlight ? "pink" : "lime"}
                className="w-full"
              >
                {p.cta}
              </Button>
            </Link>
          );
        }

        return (
          <article
            key={p.id}
            className={`relative bg-paper p-10 flex flex-col ${
              highlight ? "shadow-report" : ""
            } ${p.comingSoon ? "opacity-80" : ""}`}
          >
            {highlight && <div className="gilt-ribbon" aria-hidden />}
            <p className={highlight ? "eyebrow-gilt" : "eyebrow"}>{eyebrow}</p>
            <h3 className="mt-4 font-display text-[30px] text-ink tracking-[-0.01em]">
              {p.name}
            </h3>
            <p className="mt-5 flex items-baseline gap-2">
              <span className="font-display text-[52px] text-ink leading-none">
                {p.price}
              </span>
              <span className="font-mono text-[12px] text-mist">{p.cadence}</span>
            </p>
            <p className="mt-5 text-[14px] italic text-slate">{p.tagline}</p>
            <hr className="rule mt-6" />
            <ul className="mt-6 space-y-3 text-[14px] text-graphite flex-1">
              {p.bullets.map((b) => (
                <li key={b} className="flex gap-3">
                  <span className="text-gilt select-none">·</span>
                  <span className="leading-[1.55]">{b}</span>
                </li>
              ))}
            </ul>
            <div className="mt-8">{cta}</div>
          </article>
        );
      })}
    </div>
  );
}

export function PricingDeliverables() {
  return (
    <div className="grid md:grid-cols-2 gap-px bg-hairline border border-hairline rounded-md overflow-hidden">
      <article className="bg-paper p-10">
        <p className="eyebrow">For engineering</p>
        <h3 className="mt-3 font-display text-[24px] text-ink">
          The technical dossier.
        </h3>
        <ul className="mt-6 space-y-3 text-[14px] text-graphite">
          <li className="flex gap-3">
            <span className="text-gilt">·</span>Request &amp; response evidence
            for every finding.
          </li>
          <li className="flex gap-3">
            <span className="text-gilt">·</span>CVSS 3.1 score and vector.
          </li>
          <li className="flex gap-3">
            <span className="text-gilt">·</span>CWE classification.
          </li>
          <li className="flex gap-3">
            <span className="text-gilt">·</span>Remediation guidance with
            illustrative code.
          </li>
          <li className="flex gap-3">
            <span className="text-gilt">·</span>On-demand re-examination to
            confirm a fix.
          </li>
        </ul>
      </article>
      <article className="bg-paper p-10">
        <p className="eyebrow">For audit &amp; executive</p>
        <h3 className="mt-3 font-display text-[24px] text-ink">
          The executive dossier.
        </h3>
        <ul className="mt-6 space-y-3 text-[14px] text-graphite">
          <li className="flex gap-3">
            <span className="text-gilt">·</span>Executive summary with letter
            grade and severity counts.
          </li>
          <li className="flex gap-3">
            <span className="text-gilt">·</span>Findings mapped to OWASP Top
            10 (2021) categories.
          </li>
          <li className="flex gap-3">
            <span className="text-gilt">·</span>SOC 2 CC6 / CC7 control mapping.
          </li>
          <li className="flex gap-3">
            <span className="text-gilt">·</span>PCI-DSS 4.0, NIST 800-53, ISO
            27001:2022, HIPAA mapping.
          </li>
          <li className="flex gap-3">
            <span className="text-gilt">·</span>Audit-ready DOCX and PDF.
          </li>
        </ul>
      </article>
    </div>
  );
}

export function PricingComparison() {
  return (
    <div className="overflow-x-auto border border-hairline rounded-md bg-paper">
      <table className="brutal-table min-w-[640px]">
        <thead>
          <tr>
            <th>Provision</th>
            <th className="text-center">
              <span className="inline-flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-gilt" aria-hidden />
                Free
              </span>
            </th>
            <th className="text-center">Pro</th>
            <th className="text-center text-mist">Team</th>
          </tr>
        </thead>
        <tbody>
          {COMPARE_ROWS.map(([label, a, b, c]) => (
            <tr key={label}>
              <td className="font-body text-[14px] text-graphite">{label}</td>
              <td className="text-center font-mono text-[13px] text-graphite">
                {a}
              </td>
              <td className="text-center font-mono text-[13px] text-slate">
                {b}
              </td>
              <td className="text-center font-mono text-[13px] text-slate">
                {c}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function PricingFAQ() {
  return (
    <dl className="grid md:grid-cols-2 gap-x-12 gap-y-10">
      {FAQ.map((f) => (
        <div key={f.q} className="border-t border-hairline pt-5">
          <dt className="font-display text-[19px] text-ink">{f.q}</dt>
          <dd className="mt-3 text-[14px] leading-[1.7] text-slate">{f.a}</dd>
        </div>
      ))}
    </dl>
  );
}

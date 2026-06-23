"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { UserButton, useAuth } from "@clerk/react";
import { LogoMark } from "@/components/logo";
import { ThemeToggle } from "@/components/theme-toggle";

const userButtonAppearance = {
  elements: {
    avatarBox: {
      width: 32,
      height: 32,
      border: "1.5px solid #0B1F66",
      borderRadius: "10px",
    },
  },
};

// LandingMasthead is exported for backward compatibility but renders nothing —
// the date strip was removed during the design refresh. Kept as a no-op so
// any older import continues to type-check.
export function LandingMasthead() {
  return null;
}

type MegaKey =
  | "platform"
  | "capabilities"
  | "ai-security"
  | "solutions"
  | "resources"
  | "company";

type MegaLink = {
  glyph: string;
  title: string;
  desc: string;
  href: string;
  ext?: boolean;
};

type MegaColumn = {
  heading: string;
  links: MegaLink[];
};

const PLATFORM_COLS: MegaColumn[] = [
  {
    heading: "Methodology",
    links: [
      {
        glyph: "",
        title: "Methodology v4.2",
        desc: "The adversarial assessment standard.",
        href: "/platform/methodology-v4-2",
      },
      {
        glyph: "V",
        title: "The Adversarial Cycle",
        desc: "Five phases, every engagement.",
        href: "/platform/the-adversarial-cycle",
      },
      {
        glyph: "¶",
        title: "Engagement Profiles",
        desc: "Quick, Standard, and Deep modes.",
        href: "/platform/engagement-profiles",
      },
    ],
  },
  {
    heading: "Capabilities",
    links: [
      {
        glyph: "W",
        title: "URL Scanning (DAST)",
        desc: "Live web and API exploit testing.",
        href: "/platform/web-dast",
      },
      {
        glyph: "S",
        title: "Repo Scanning",
        desc: "SAST, secrets, and dependency analysis.",
        href: "/platform/sast-and-secrets",
      },
      {
        glyph: "I",
        title: "IaC + Container",
        desc: "Terraform, Kubernetes, and Dockerfile policy.",
        href: "/platform/cloud-and-infrastructure",
      },
      {
        glyph: "A",
        title: "Authenticated Coverage",
        desc: "Session-aware crawling and authz checks.",
        href: "/platform/authenticated-coverage",
      },
      {
        glyph: "T",
        title: "Threat Models",
        desc: "Deterministic STRIDE and DREAD analysis.",
        href: "/platform/threat-models",
      },
      {
        glyph: "C",
        title: "Compliance Mapping",
        desc: "OWASP, SOC 2, PCI, NIST, ISO, HIPAA.",
        href: "/platform/audit-and-compliance",
      },
      {
        glyph: "B",
        title: "SBOM",
        desc: "SPDX and CycloneDX supply-chain evidence.",
        href: "/resources/repo-scan",
      },
      {
        glyph: "R",
        title: "LLM Red Team",
        desc: "OWASP LLM Top 10 attack modules.",
        href: "/platform/llm-red-team",
      },
      {
        glyph: "Σ",
        title: "Agent Swarms",
        desc: "Recon, breaker, and synthesis agents.",
        href: "/platform/agent-swarms",
      },
      {
        glyph: "Ω",
        title: "AI Agents",
        desc: "Tool-calling scan agent for LLM apps.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "E",
        title: "The Engine",
        desc: "Autonomous remediation and auto-patching.",
        href: "/platform/the-engine",
      },
      {
        glyph: "K",
        title: "Cloud & Infrastructure",
        desc: "AWS, Azure, GCP, CSPM, CIEM, DSPM.",
        href: "/platform/cloud-and-infrastructure",
      },
    ],
  },
  {
    heading: "Deliverables",
    links: [
      {
        glyph: "A",
        title: "Letter Grade",
        desc: "Heuristic A–F verdict per assessment.",
        href: "/platform/letter-grade",
      },
      {
        glyph: "†",
        title: "Technical Dossier",
        desc: "Engineering evidence and remediation.",
        href: "/platform/technical-dossier",
      },
      {
        glyph: "‡",
        title: "Executive Dossier",
        desc: "Audit and leadership summary.",
        href: "/platform/executive-dossier",
      },
      {
        glyph: "↻",
        title: "Re-examination",
        desc: "Verify any fix on demand.",
        href: "/platform/re-examination",
      },
      {
        glyph: "↧",
        title: "Export",
        desc: "DOCX, PDF, JSON, CSV, and SBOM.",
        href: "/platform/export",
      },
    ],
  },
];

const RESOURCES_COLS: MegaColumn[] = [
  {
    heading: "Reading Room",
    links: [
      {
        glyph: "M",
        title: "Methodology Brief",
        desc: "v4.2 monograph and rationale.",
        href: "/platform/methodology-v4-2",
      },
      {
        glyph: "¶",
        title: "Issued Reports",
        desc: "A library of past assessments.",
        href: "/resources/issued-reports",
      },
      {
        glyph: "F",
        title: "Findings Register",
        desc: "Sample evidence catalogue.",
        href: "/resources/findings-register",
      },
      {
        glyph: "∮",
        title: "Repository",
        desc: "MIT-licensed source, self-hostable.",
        href: "/resources/repo-scan",
      },
      {
        glyph: "G",
        title: "Glossary",
        desc: "Terms, classifications, conventions.",
        href: "/resources/overview",
      },
    ],
  },
  {
    heading: "Reference & Docs",
    links: [
      {
        glyph: "W",
        title: "URL scan (DAST)",
        desc: "Recon, crawl, probe, and verify.",
        href: "/resources/url-scan",
      },
      {
        glyph: "S",
        title: "Repo scan",
        desc: "SAST, SCA, IaC, and secrets.",
        href: "/resources/repo-scan",
      },
      {
        glyph: "B",
        title: "SBOM",
        desc: "SPDX 2.3 and CycloneDX 1.5 output.",
        href: "/resources/repo-scan",
      },
      {
        glyph: "T",
        title: "Threat model",
        desc: "Deterministic STRIDE and DREAD.",
        href: "/resources/threat-model",
      },
      {
        glyph: "Σ",
        title: "Swarm mode",
        desc: "Recon, breaker, and synthesis agents.",
        href: "/platform/agent-swarms",
      },
      {
        glyph: "R",
        title: "LLM red team",
        desc: "OWASP LLM Top 10 payload libraries.",
        href: "/platform/llm-red-team",
      },
      {
        glyph: "D",
        title: "User documentation",
        desc: "Configure and operate the platform.",
        href: "/resources/overview",
      },
      {
        glyph: "⌘",
        title: "Self-hosting",
        desc: "Docker Compose installation guide.",
        href: "/resources/overview",
      },
      {
        glyph: "/",
        title: "API reference",
        desc: "REST endpoints and webhooks.",
        href: "/resources/api-reference",
      },
      {
        glyph: "Δ",
        title: "Changelog",
        desc: "Methodology and platform revisions.",
        href: "/resources/overview",
      },
      {
        glyph: "○",
        title: "Status",
        desc: "Engine availability and incidents.",
        href: "/resources/overview",
      },
    ],
  },
  {
    heading: "Audience",
    links: [
      {
        glyph: "?",
        title: "Enquiries",
        desc: "Frequently considered questions.",
        href: "/enquiries",
      },
      {
        glyph: "!",
        title: "Security Disclosures",
        desc: "Responsible disclosure programme.",
        href: "/audience/security-disclosures",
      },
      {
        glyph: "E",
        title: "Pencheff for Engineers",
        desc: "Triage, evidence, fix verification.",
        href: "/audience/for-engineers",
      },
      {
        glyph: "Λ",
        title: "Pencheff for Auditors",
        desc: "Framework-mapped evidence packs.",
        href: "/audience/for-auditors",
      },
      {
        glyph: "X",
        title: "Pencheff for Executives",
        desc: "Letter grade and risk attestation.",
        href: "/audience/for-executives",
      },
    ],
  },
];

const CAPABILITIES_COLS: MegaColumn[] = [
  {
    heading: "Dynamic Testing",
    links: [
      {
        glyph: "I",
        title: "Injection coverage",
        desc: "SQLi, command, SSTI, XXE, SSRF, LDAP.",
        href: "/platform/web-dast",
      },
      {
        glyph: "X",
        title: "Client-side security",
        desc: "XSS, CSRF, CORS, clickjacking, redirects.",
        href: "/platform/web-dast",
      },
      {
        glyph: "K",
        title: "Authentication",
        desc: "Sessions, JWT, OAuth, MFA, IDOR.",
        href: "/platform/authenticated-coverage",
      },
      {
        glyph: "A",
        title: "API and SPA coverage",
        desc: "GraphQL, WebSockets, REST, OpenAPI.",
        href: "/platform/web-dast",
      },
      {
        glyph: "~",
        title: "Proxy and fuzzer",
        desc: "Intercepting proxy with OAST callbacks.",
        href: "/platform/web-dast",
      },
    ],
  },
  {
    heading: "Code & Supply Chain",
    links: [
      {
        glyph: "S",
        title: "Language scanners",
        desc: "15+ languages, parallel static analysis.",
        href: "/platform/sast-and-secrets",
      },
      {
        glyph: "G",
        title: "Secrets and malware",
        desc: "gitleaks, YARA, backdoor detection.",
        href: "/capabilities/secrets-and-malware",
      },
      {
        glyph: "D",
        title: "Dependency intelligence",
        desc: "OSV, KEV, EPSS, SSVC enrichment.",
        href: "/resources/repo-scan",
      },
      {
        glyph: "↻",
        title: "Auto-fix PRs",
        desc: "Deterministic patches with SARIF output.",
        href: "/platform/re-examination",
      },
      {
        glyph: "C",
        title: "Container gates",
        desc: "Image scans and Kubernetes policy.",
        href: "/platform/cloud-and-infrastructure",
      },
    ],
  },
  {
    heading: "Prioritization",
    links: [
      {
        glyph: "R",
        title: "Reachability",
        desc: "Link findings to live attack paths.",
        href: "/capabilities/overview",
      },
      {
        glyph: "Σ",
        title: "AI triage",
        desc: "Dedup, narratives, and severity reasoning.",
        href: "/capabilities/overview",
      },
      {
        glyph: "A",
        title: "Letter grade",
        desc: "Executive-grade risk scoring.",
        href: "/platform/letter-grade",
      },
      {
        glyph: "T",
        title: "Threat modeling",
        desc: "STRIDE, DREAD, abuse cases.",
        href: "/platform/threat-models",
      },
    ],
  },
];

const AI_SECURITY_COLS: MegaColumn[] = [
  {
    heading: "LLM Red Team",
    links: [
      {
        glyph: "Ω",
        title: "OWASP LLM Top 10",
        desc: "Full coverage of the 2025 standard.",
        href: "/platform/llm-red-team",
      },
      {
        glyph: "↯",
        title: "Attack strategies",
        desc: "Jailbreak corpora and regression suites.",
        href: "/platform/llm-red-team",
      },
      {
        glyph: "⟶",
        title: "Transports",
        desc: "Chat, HTTP, LiteLLM, MCP, chatbots.",
        href: "/platform/llm-red-team",
      },
      {
        glyph: "",
        title: "Evidence and cost",
        desc: "Traces, judges, and token accounting.",
        href: "/ai-security/evidence-and-cost",
      },
    ],
  },
  {
    heading: "Agentic Testing",
    links: [
      {
        glyph: "T",
        title: "Tool authorization",
        desc: "Probe tool calls and privilege boundaries.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "M",
        title: "Memory and context",
        desc: "Exfiltration and retrieval poisoning.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "P",
        title: "Planner attacks",
        desc: "Goal hijacking and policy bypass.",
        href: "/platform/agent-swarms",
      },
      {
        glyph: "Σ",
        title: "Swarm orchestration",
        desc: "Multi-agent recon and exploit roles.",
        href: "/platform/agent-swarms",
      },
    ],
  },
  {
    heading: "Guardrails",
    links: [
      {
        glyph: "G",
        title: "Sentry runtime guardrail",
        desc: "Policy checks on prompts and responses.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "⊕",
        title: "Sidecars and middleware",
        desc: "Proxy, LiteLLM, and MCP enforcement.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "",
        title: "AI governance",
        desc: "OWASP LLM, MITRE ATLAS, NIST AI RMF.",
        href: "/platform/audit-and-compliance",
      },
      {
        glyph: "↻",
        title: "Regression tests",
        desc: "Block known jailbreaks after release.",
        href: "/platform/llm-red-team",
      },
    ],
  },
];

const SOLUTIONS_COLS: MegaColumn[] = [
  {
    heading: "Program Workflows",
    links: [
      {
        glyph: "⌚",
        title: "CI/CD gates",
        desc: "Repo, IaC, container policy blocking.",
        href: "/solutions/overview",
      },
      {
        glyph: "A",
        title: "Authenticated app pentest",
        desc: "Session-aware browser crawling.",
        href: "/platform/authenticated-coverage",
      },
      {
        glyph: "Σ",
        title: "AI product release",
        desc: "LLM red team and guardrails.",
        href: "/solutions/overview",
      },
      {
        glyph: "○",
        title: "Continuous ASM",
        desc: "Asset discovery and drift monitoring.",
        href: "/asm",
      },
    ],
  },
  {
    heading: "Deployment Models",
    links: [
      {
        glyph: "S",
        title: "SaaS app",
        desc: "Dashboards, reports, multi-workspace.",
        href: "/signup",
      },
      {
        glyph: "/",
        title: "CLI and CI",
        desc: "Deterministic checks in pipelines.",
        href: "/resources/api-reference",
      },
      {
        glyph: "⌘",
        title: "MCP server",
        desc: "Security automation for AI agents.",
        href: "/resources/api-reference",
      },
      {
        glyph: "H",
        title: "Self-hosting",
        desc: "Run the stack inside your boundary.",
        href: "/resources/overview",
      },
    ],
  },
  {
    heading: "By Audience",
    links: [
      {
        glyph: "S",
        title: "Security teams",
        desc: "Verified risk and remediation queues.",
        href: "/solutions/overview",
      },
      {
        glyph: "E",
        title: "Engineers",
        desc: "Developer-ready evidence and PRs.",
        href: "/solutions/overview",
      },
      {
        glyph: "Λ",
        title: "Auditors",
        desc: "Compliance appendices and retests.",
        href: "/company/our-auditors",
      },
      {
        glyph: "X",
        title: "Executives",
        desc: "Letter grade and portfolio posture.",
        href: "/solutions/overview",
      },
    ],
  },
];

const COMPANY_COLS: MegaColumn[] = [
  {
    heading: "Our Practice",
    links: [
      {
        glyph: "",
        title: "Our Discipline",
        desc: "How we work · what we believe",
        href: "/company/our-discipline",
      },
      {
        glyph: "A",
        title: "Our Auditors",
        desc: "Customers using the report",
        href: "/company/our-auditors",
      },
      {
        glyph: "P",
        title: "Our Partners",
        desc: "Implementation specialists",
        href: "/company/our-partners",
      },
      {
        glyph: "¶",
        title: "Case Studies",
        desc: "Engagements at scale",
        href: "/company/case-studies",
      },
      {
        glyph: "∰",
        title: "Trust & Compliance",
        desc: "SOC 2 · ISO 27001 · GDPR posture",
        href: "/compliance",
      },
    ],
  },
  {
    heading: "Correspondence",
    links: [
      {
        glyph: "№",
        title: "Newsroom",
        desc: "Press coverage & bulletins",
        href: "/company/newsroom",
      },
      {
        glyph: "✉",
        title: "Contact",
        desc: "Direct correspondence",
        href: "/company/contact",
      },
      {
        glyph: "C",
        title: "Careers",
        desc: "Open positions · the standing committee",
        href: "/company/careers",
      },
      {
        glyph: "L",
        title: "Leadership",
        desc: "The editorial board",
        href: "/company/leadership",
      },
      {
        glyph: "⊕",
        title: "Brand & Press",
        desc: "Logos · likeness · usage",
        href: "/company/newsroom",
      },
    ],
  },
];

function MegaPanel({
  id,
  cols,
  feature,
  newsletter,
  isOpen,
  onMouseEnter,
  onMouseLeave,
  onLinkClick,
}: {
  id: string;
  cols: MegaColumn[];
  feature?: {
    eyebrow: string;
    new?: boolean;
    title: React.ReactNode;
    body: string;
    cta: string;
    href: string;
  };
  newsletter?: { eyebrow: string; title: React.ReactNode; body: string };
  isOpen: boolean;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
  onLinkClick: () => void;
}) {
  const className = `lp-mega${isOpen ? " lp-is-open" : ""}${newsletter ? " lp-has-newsletter" : ""}${feature ? " lp-has-feature" : ""}${feature && !newsletter && cols.length === 2 ? " lp-two-col" : ""}`;
  return (
    <div
      className={className}
      id={id}
      data-mega={id.replace("mega-", "")}
      aria-hidden={!isOpen}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    >
      <div className="lp-mega-grid">
        {newsletter && (
          <aside className="lp-mega-newsletter">
            <div className="lp-news-eyebrow">{newsletter.eyebrow}</div>
            <h4>{newsletter.title}</h4>
            <p>{newsletter.body}</p>
            <form className="lp-news-form" onSubmit={(e) => e.preventDefault()}>
              <input
                type="email"
                placeholder="your@correspondence.com"
                aria-label="Email address"
              />
              <button type="submit" className="lp-news-btn">
                Subscribe to the periodical
              </button>
            </form>
          </aside>
        )}

        {cols.map((col, ci) => (
          <div className="lp-mega-col" key={`${id}-${ci}`}>
            <h6>{col.heading}</h6>
            <div
              className={`lp-mega-col-stack${
                col.links.length > 6 ? " lp-mega-scroll" : ""
              }`}
            >
              {col.links.map((l, li) => {
                const delay = 120 + (ci * col.links.length + li) * 32;
                const isExternal =
                  l.ext ||
                  /^https?:/.test(l.href) ||
                  l.href.startsWith("mailto:");
                const props = {
                  className: "lp-mega-link",
                  style: {
                    ["--lp-md" as string]: `${delay}ms`,
                  } as React.CSSProperties,
                  onClick: onLinkClick,
                };
                const inner = (
                  <>
                    <span className="lp-mega-glyph">{l.glyph}</span>
                    <div>
                      <div className="lp-mega-link-title">
                        {l.title}
                        {l.ext && <span className="lp-ext">↗</span>}
                      </div>
                      <div className="lp-mega-link-desc">{l.desc}</div>
                    </div>
                  </>
                );
                return isExternal ? (
                  <a
                    key={l.title}
                    href={l.href}
                    target={l.ext ? "_blank" : undefined}
                    rel={l.ext ? "noreferrer" : undefined}
                    {...props}
                  >
                    {inner}
                  </a>
                ) : (
                  <Link key={l.title} href={l.href} {...props}>
                    {inner}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}

        {feature && (
          <aside className="lp-mega-feature">
            <div>
              <div className="lp-feature-eyebrow">
                {feature.eyebrow}
                {feature.new && <span className="lp-feature-new">New</span>}
              </div>
              <h4>{feature.title}</h4>
              <p>{feature.body}</p>
            </div>
            <Link
              className="lp-feature-cta"
              href={feature.href}
              onClick={onLinkClick}
            >
              {feature.cta}
            </Link>
          </aside>
        )}
      </div>
    </div>
  );
}

export function LandingNav() {
  const { isLoaded, isSignedIn } = useAuth();
  const [openKey, setOpenKey] = useState<MegaKey | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [mobileSection, setMobileSection] = useState<MegaKey | "root" | null>(
    null,
  );
  const closeTimer = useRef<number | null>(null);
  const openTimers = useRef<Record<string, number>>({});

  const HOVER_DELAY = 80;
  const CLOSE_DELAY = 220;

  function cancelClose() {
    if (closeTimer.current) {
      window.clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  }
  function scheduleClose() {
    cancelClose();
    closeTimer.current = window.setTimeout(() => setOpenKey(null), CLOSE_DELAY);
  }
  function scheduleOpen(key: MegaKey) {
    cancelClose();
    if (openTimers.current[key]) window.clearTimeout(openTimers.current[key]);
    openTimers.current[key] = window.setTimeout(
      () => setOpenKey(key),
      HOVER_DELAY,
    );
  }
  function cancelScheduledOpen(key: MegaKey) {
    if (openTimers.current[key]) {
      window.clearTimeout(openTimers.current[key]);
      delete openTimers.current[key];
    }
  }
  function toggle(key: MegaKey) {
    cancelClose();
    setOpenKey((curr) => (curr === key ? null : key));
  }
  function close() {
    cancelClose();
    setOpenKey(null);
    setMobileOpen(false);
    setMobileSection(null);
  }

  // Escape key to close
  useEffect(() => {
    if (!openKey) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") close();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openKey]);

  // Close on big scroll
  useEffect(() => {
    if (!openKey) return;
    let lastY = window.scrollY;
    function onScroll() {
      if (Math.abs(window.scrollY - lastY) > 80) {
        close();
      }
      lastY = window.scrollY;
    }
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, [openKey]);

  function trigger(key: MegaKey, label: string) {
    return (
      <div
        className={`lp-nav-item${openKey === key ? " lp-is-open" : ""}`}
        onMouseEnter={() => scheduleOpen(key)}
        onMouseLeave={() => {
          cancelScheduledOpen(key);
          scheduleClose();
        }}
      >
        <button
          type="button"
          className="lp-nav-trigger"
          aria-haspopup="true"
          aria-expanded={openKey === key}
          aria-controls={`mega-${key}`}
          onClick={() => toggle(key)}
        >
          {label}
          <span className="lp-caret" aria-hidden>
            ▾
          </span>
        </button>
      </div>
    );
  }

  return (
    <>
      <div
        className={`lp-mega-backdrop${openKey ? " lp-open" : ""}`}
        aria-hidden
        onClick={close}
      />

      <div
        className={`lp-mobile-backdrop${mobileOpen ? " lp-open" : ""}`}
        aria-hidden
        onClick={close}
      />

      <div className={`lp-mobile-sheet${mobileOpen ? " lp-open" : ""}`}>
        <div className="lp-mobile-head">
          <div className="lp-mobile-title">Pencheff</div>
          <button
            type="button"
            className="lp-mobile-close"
            aria-label="Close menu"
            onClick={close}
          >
            ✕
          </button>
        </div>

        <div className="lp-mobile-body">
          <div className="lp-mobile-section">
            <button
              type="button"
              className="lp-mobile-sec-btn"
              aria-expanded={mobileSection === "platform"}
              onClick={() =>
                setMobileSection((v) =>
                  v === "platform" ? "root" : "platform",
                )
              }
            >
              Platform <span aria-hidden>▾</span>
            </button>
            {mobileSection === "platform" && (
              <div className="lp-mobile-links">
                {PLATFORM_COLS.flatMap((c) => c.links).map((l) => (
                  <Link
                    key={`m-plat-${l.title}`}
                    href={l.href}
                    className="lp-mobile-link"
                    onClick={close}
                  >
                    {l.title}
                  </Link>
                ))}
              </div>
            )}
          </div>

          <div className="lp-mobile-section">
            <button
              type="button"
              className="lp-mobile-sec-btn"
              aria-expanded={mobileSection === "capabilities"}
              onClick={() =>
                setMobileSection((v) =>
                  v === "capabilities" ? "root" : "capabilities",
                )
              }
            >
              Capabilities <span aria-hidden>▾</span>
            </button>
            {mobileSection === "capabilities" && (
              <div className="lp-mobile-links">
                {CAPABILITIES_COLS.flatMap((c) => c.links).map((l) => (
                  <Link
                    key={`m-cap-${l.title}`}
                    href={l.href}
                    className="lp-mobile-link"
                    onClick={close}
                  >
                    {l.title}
                  </Link>
                ))}
              </div>
            )}
          </div>

          <div className="lp-mobile-section">
            <button
              type="button"
              className="lp-mobile-sec-btn"
              aria-expanded={mobileSection === "ai-security"}
              onClick={() =>
                setMobileSection((v) =>
                  v === "ai-security" ? "root" : "ai-security",
                )
              }
            >
              AI Security <span aria-hidden>▾</span>
            </button>
            {mobileSection === "ai-security" && (
              <div className="lp-mobile-links">
                {AI_SECURITY_COLS.flatMap((c) => c.links).map((l) => (
                  <Link
                    key={`m-ai-${l.title}`}
                    href={l.href}
                    className="lp-mobile-link"
                    onClick={close}
                  >
                    {l.title}
                  </Link>
                ))}
              </div>
            )}
          </div>

          <div className="lp-mobile-section">
            <button
              type="button"
              className="lp-mobile-sec-btn"
              aria-expanded={mobileSection === "solutions"}
              onClick={() =>
                setMobileSection((v) =>
                  v === "solutions" ? "root" : "solutions",
                )
              }
            >
              Solutions <span aria-hidden>▾</span>
            </button>
            {mobileSection === "solutions" && (
              <div className="lp-mobile-links">
                {SOLUTIONS_COLS.flatMap((c) => c.links).map((l) => (
                  <Link
                    key={`m-sol-${l.title}`}
                    href={l.href}
                    className="lp-mobile-link"
                    onClick={close}
                  >
                    {l.title}
                  </Link>
                ))}
              </div>
            )}
          </div>

          <div className="lp-mobile-section">
            <button
              type="button"
              className="lp-mobile-sec-btn"
              aria-expanded={mobileSection === "resources"}
              onClick={() =>
                setMobileSection((v) =>
                  v === "resources" ? "root" : "resources",
                )
              }
            >
              Resources <span aria-hidden>▾</span>
            </button>
            {mobileSection === "resources" && (
              <div className="lp-mobile-links">
                {RESOURCES_COLS.flatMap((c) => c.links).map((l) => (
                  <Link
                    key={`m-res-${l.title}`}
                    href={l.href}
                    className="lp-mobile-link"
                    onClick={close}
                  >
                    {l.title}
                  </Link>
                ))}
              </div>
            )}
          </div>

          <div className="lp-mobile-section">
            <button
              type="button"
              className="lp-mobile-sec-btn"
              aria-expanded={mobileSection === "company"}
              onClick={() =>
                setMobileSection((v) => (v === "company" ? "root" : "company"))
              }
            >
              Company <span aria-hidden>▾</span>
            </button>
            {mobileSection === "company" && (
              <div className="lp-mobile-links">
                {COMPANY_COLS.flatMap((c) => c.links).map((l) => (
                  <Link
                    key={`m-co-${l.title}`}
                    href={l.href}
                    className="lp-mobile-link"
                    onClick={close}
                  >
                    {l.title}
                  </Link>
                ))}
              </div>
            )}
          </div>

          <div className="lp-mobile-links lp-mobile-links-tight">
            <a
              href={
                process.env.NEXT_PUBLIC_DOCS_URL ?? "https://docs.pencheff.com"
              }
              target="_blank"
              rel="noreferrer"
              className="lp-mobile-link"
              onClick={() => setMobileOpen(false)}
            >
              Docs ↗
            </a>
            {!isSignedIn && (
              <>
                <Link href="/login" className="lp-mobile-link" onClick={close}>
                  Sign in
                </Link>
                <Link href="/signup" className="lp-mobile-link" onClick={close}>
                  Open an account
                </Link>
              </>
            )}
            {isSignedIn && (
              <Link
                href="/dashboard"
                className="lp-mobile-link"
                onClick={close}
              >
                Dashboard
              </Link>
            )}
          </div>
        </div>
      </div>

      <nav className="lp-nav" aria-label="Pencheff">
        <div className="lp-nav-inner">
          <Link href="/" className="lp-brand" aria-label="Pencheff">
            <span className="lp-monogram" aria-hidden>
              <LogoMark size={32} priority />
            </span>
            <span className="lp-wordmark">Pencheff</span>
            <span
              className="lp-beta-pill"
              title="Pencheff is free and open source (MIT licence)."
            >
              Open source
            </span>
          </Link>

          <div className="lp-nav-links">
            {trigger("platform", "Platform")}
            {trigger("capabilities", "Capabilities")}
            {trigger("ai-security", "AI Security")}
            {trigger("solutions", "Solutions")}
            {trigger("resources", "Resources")}
            {trigger("company", "Company")}
            <a
              className="lp-nav-link"
              href={
                process.env.NEXT_PUBLIC_DOCS_URL ?? "https://docs.pencheff.com"
              }
              target="_blank"
              rel="noreferrer"
            >
              Docs ↗
            </a>
          </div>

          <div className="lp-nav-cta">
            <button
              type="button"
              className="lp-nav-mobile-btn"
              aria-label="Open menu"
              aria-expanded={mobileOpen}
              onClick={() => {
                setMobileOpen((v) => !v);
                setMobileSection("root");
              }}
            >
              Menu
              <span className="lp-caret" aria-hidden>
                ▾
              </span>
            </button>
            <ThemeToggle variant="landing" />
            {isLoaded && !isSignedIn && (
              <>
                <Link
                  className="lp-nav-signin"
                  href="/login"
                  style={{ whiteSpace: "nowrap" }}
                >
                  Sign in
                </Link>
                <Link
                  className="lp-btn lp-btn-pink lp-btn-arrow"
                  href="/signup"
                  style={{ whiteSpace: "nowrap" }}
                >
                  Open an account
                </Link>
              </>
            )}
            {isLoaded && isSignedIn && (
              <>
                <Link className="lp-nav-signin" href="/dashboard">
                  Dashboard
                </Link>
                <UserButton appearance={userButtonAppearance} />
              </>
            )}
          </div>
        </div>

        <div
          className="lp-mega-stack"
          role="region"
          aria-label="Site navigation menus"
        >
          <MegaPanel
            id="mega-platform"
            cols={PLATFORM_COLS}
            isOpen={openKey === "platform"}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            onLinkClick={close}
          />
          <MegaPanel
            id="mega-capabilities"
            cols={CAPABILITIES_COLS}
            isOpen={openKey === "capabilities"}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            onLinkClick={close}
          />
          <MegaPanel
            id="mega-ai-security"
            cols={AI_SECURITY_COLS}
            isOpen={openKey === "ai-security"}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            onLinkClick={close}
          />
          <MegaPanel
            id="mega-solutions"
            cols={SOLUTIONS_COLS}
            isOpen={openKey === "solutions"}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            onLinkClick={close}
          />
          <MegaPanel
            id="mega-resources"
            cols={RESOURCES_COLS}
            isOpen={openKey === "resources"}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            onLinkClick={close}
          />
          <MegaPanel
            id="mega-company"
            cols={COMPANY_COLS}
            feature={{
              eyebrow: "Bulletin · 2026 — Vol. II",
              title: (
                <>
                  Pencheff Adopts{" "}
                  <span className="lp-italic-gilt">Methodology v4.2.</span>
                </>
              ),
              body: "Refined exploit-chain composition, automated false-positive triage, and an updated grade attestation pipeline. Read the rationale.",
              cta: "Read the bulletin →",
              href: "/company/newsroom",
            }}
            isOpen={openKey === "company"}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            onLinkClick={close}
          />
        </div>
      </nav>
    </>
  );
}

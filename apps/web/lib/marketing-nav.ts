export type NavItem = {
  title: string;
  body: string;
  href: string;
};

export type NavGroup = {
  title: string;
  items: NavItem[];
};

export type NavMenu = {
  label: string;
  eyebrow: string;
  title: string;
  body: string;
  cta: NavItem;
  quickLinks: NavItem[];
  groups: NavGroup[];
};

export const NAV_MENUS: NavMenu[] = [
  {
    label: "Platform",
    eyebrow: "What Pencheff does",
    title: "A complete adversarial security platform",
    body: "Run web, API, code, dependency, cloud, AI, and internal-network assessments from one queue with unified findings, evidence, remediation, and audit output.",
    cta: {
      title: "Explore platform coverage",
      body: "See the full surface map on this page.",
      href: "#coverage",
    },
    quickLinks: [
      {
        title: "Dashboard",
        body: "Live risk, grade, scan status, and operational metrics.",
        href: "/dashboard",
      },
      {
        title: "Targets",
        body: "URLs, repos, AI apps, APIs, and infrastructure scopes.",
        href: "/targets/new",
      },
      {
        title: "Findings",
        body: "Verified evidence, severity, remediation, and owners.",
        href: "/findings",
      },
      {
        title: "Reports",
        body: "Executive, technical, compliance, and retest deliverables.",
        href: "/platform/reports",
      },
    ],
    groups: [
      {
        title: "Methodology",
        items: [
          {
            title: "Methodology v4.2",
            body: "The adversarial assessment standard: evidence rules, scope categories, phase definitions, and rationale.",
            href: "/platform/methodology-v4-2",
          },
          {
            title: "The Adversarial Cycle",
            body: "Five phases every engagement follows: recon, exploit, evidence, normalize, and deliver.",
            href: "/platform/the-adversarial-cycle",
          },
        ],
      },
      {
        title: "Security Surfaces",
        items: [
          {
            title: "Web DAST",
            body: "Authenticated crawling, API discovery, active probes, exploit chains, and request evidence.",
            href: "/platform/web-dast",
          },
          {
            title: "SAST and secrets",
            body: "Semgrep, Bandit, gosec, Brakeman, ESLint security, tree-sitter rules, and gitleaks.",
            href: "/platform/sast-and-secrets",
          },
          {
            title: "SCA and SBOM",
            body: "OSV, NVD, GHSA, RustSec, GoVulnDB, SPDX, CycloneDX, EPSS, KEV, and SSVC.",
            href: "/platform/sast-and-secrets",
          },
          {
            title: "IaC and containers",
            body: "Terraform, Kubernetes, Helm, Dockerfiles, Checkov, Trivy, tfsec, Kubesec, and registry gates.",
            href: "/platform/cloud-and-infrastructure",
          },
          {
            title: "ASM and assets",
            body: "Discovery, exposed services, subdomains, cloud edges, certificates, and drift.",
            href: "/asm",
          },
          {
            title: "Network, AD, mobile",
            body: "Internal VA, Active Directory checks, APK/IPA analysis, and mobile static findings.",
            href: "#coverage",
          },
        ],
      },
      {
        title: "Operational Core",
        items: [
          {
            title: "Unified finding stream",
            body: "One schema for DAST, SAST, SCA, IaC, AI, mobile, network, and manual evidence.",
            href: "/findings",
          },
          {
            title: "Engagement profiles",
            body: "Quick, Standard, Deep, Red-Team, AI-Only, Compliance, CI, and Continuous modes.",
            href: "/platform/engagement-profiles",
          },
          {
            title: "Schedules",
            body: "Continuous scans, release gates, recurring retests, and monitoring cadence.",
            href: "/schedules",
          },
          {
            title: "Observability",
            body: "OpenTelemetry traces, audit hash chain, SLOs, cost dashboards, and retention controls.",
            href: "/observability",
          },
          {
            title: "MCP toolkit",
            body: "Tool-calling security automation exposed through the Pencheff MCP server.",
            href: "/integrations",
          },
          {
            title: "Audit and compliance",
            body: "Evidence packs mapped to OWASP, PCI DSS, SOC 2, ISO 27001, HIPAA, NIST, and GDPR.",
            href: "/platform/audit-and-compliance",
          },
          {
            title: "Security Lake",
            body: "OCSF 1.3.0-normalized findings in an Apache Iceberg table — query, trend, export NDJSON/Parquet, or pull into your SIEM.",
            href: "/platform/security-lake",
          },
          {
            title: "Custom LLM providers",
            body: "Bring your own OpenAI, Anthropic, Gemini, Azure OpenAI, or compatible endpoint. One active provider powers all AI features; fail-closed, quotas bypassed.",
            href: "/platform/custom-llm-providers",
          },
          {
            title: "Authenticated coverage",
            body: "Session macros, role-aware crawling, OAuth, JWT, MFA, and business-logic coverage.",
            href: "/platform/authenticated-coverage",
          },
          {
            title: "Threat models",
            body: "Deterministic STRIDE and DREAD analysis with attack trees and generated mitigations.",
            href: "/platform/threat-models",
          },
          {
            title: "Cloud and infrastructure",
            body: "TLS, headers, subdomain takeover, cloud metadata signals, and certificate monitoring.",
            href: "/platform/cloud-and-infrastructure",
          },
        ],
      },
      {
        title: "AI Security",
        items: [
          {
            title: "LLM red team",
            body: "OWASP LLM Top 10 attack modules with jailbreak corpora, judges, and token accounting.",
            href: "/platform/llm-red-team",
          },
          {
            title: "Agent swarms",
            body: "Recon, breaker, exploit, synthesis, and reporting agent roles for automated testing.",
            href: "/platform/agent-swarms",
          },
          {
            title: "AI agents",
            body: "Tool-calling scan agent for testing LLM apps, chatbots, and agentic workflows.",
            href: "/platform/ai-agents",
          },
          {
            title: "The engine",
            body: "Autonomous orchestration, remediation pipeline, and auto-patching coordination.",
            href: "/platform/the-engine",
          },
        ],
      },
      {
        title: "Deliverables",
        items: [
          {
            title: "Letter grade",
            body: "Heuristic A–F verdict derived from severity, reachability, and evidence quality.",
            href: "/platform/letter-grade",
          },
          {
            title: "Technical dossier",
            body: "Engineering evidence, reproduction steps, fix guidance, and compliance mappings.",
            href: "/platform/technical-dossier",
          },
          {
            title: "Executive dossier",
            body: "Leadership summary with business risk, grade, posture trends, and audit-ready output.",
            href: "/platform/executive-dossier",
          },
          {
            title: "Re-examination",
            body: "Verify any fix on demand with targeted re-test probes against the same finding.",
            href: "/platform/re-examination",
          },
          {
            title: "Export",
            body: "DOCX, PDF, JSON, CSV, SARIF, SPDX, and CycloneDX output for every workflow.",
            href: "/platform/export",
          },
        ],
      },
    ],
  },
  {
    label: "Capabilities",
    eyebrow: "Everything the engine tests",
    title: "From live exploits to source-code proof",
    body: "Pencheff combines deterministic scanners, AI-guided probes, curated payloads, external tools, and evidence normalization so every signal lands in one remediation workflow.",
    cta: {
      title: "Start a new assessment",
      body: "Create a URL, repo, API, or AI target.",
      href: "/targets/new",
    },
    quickLinks: [
      {
        title: "URL scan",
        body: "DAST for live applications and APIs.",
        href: "/platform/web-dast",
      },
      {
        title: "Repo scan",
        body: "SAST, secrets, dependency, and IaC coverage.",
        href: "/platform/sast-and-secrets",
      },
      {
        title: "SBOM",
        body: "SPDX and CycloneDX output with vulnerability context.",
        href: "/platform/sast-and-secrets",
      },
      {
        title: "Compare scans",
        body: "Track fixes, regressions, and residual risk.",
        href: "/scans/compare",
      },
    ],
    groups: [
      {
        title: "Dynamic Testing",
        items: [
          {
            title: "Injection coverage",
            body: "SQLi, NoSQLi, command injection, SSTI, XXE, LDAP, path traversal, and deserialization.",
            href: "/platform/web-dast",
          },
          {
            title: "Client-side security",
            body: "Reflected, stored, and DOM XSS, CSRF, CORS, clickjacking, cache poisoning, and open redirect.",
            href: "/platform/web-dast",
          },
          {
            title: "Authentication",
            body: "Sessions, cookies, JWT, OAuth/OIDC, MFA bypass, brute force, IDOR, and privilege escalation.",
            href: "/platform/authenticated-coverage",
          },
          {
            title: "API and SPA coverage",
            body: "GraphQL, WebSockets, REST, OpenAPI, browser crawls, authenticated flows, and business logic.",
            href: "/platform/web-dast",
          },
          {
            title: "Proxy and fuzzer",
            body: "Intercepting proxy, passive scanner, parameter fuzzer, OAST callbacks, and replayable evidence.",
            href: "#coverage",
          },
        ],
      },
      {
        title: "Code And Supply Chain",
        items: [
          {
            title: "Language scanners",
            body: "Python, Go, Rails, JavaScript, Solidity, Kotlin, Swift, Scala, Dart, Lua, Erlang, and COBOL scaffolds.",
            href: "/platform/sast-and-secrets",
          },
          {
            title: "Secrets and malware",
            body: "gitleaks, YARA indicators, suspicious payloads, backdoor patterns, and evidence metadata.",
            href: "/capabilities/secrets-and-malware",
          },
          {
            title: "Dependency intelligence",
            body: "Fixed versions, exploitability, reachability, EPSS, KEV, SSVC, licenses, and advisory enrichment.",
            href: "/platform/sast-and-secrets",
          },
          {
            title: "Auto-fix PRs",
            body: "Deterministic patches, branch output, GitHub checks, SARIF, and reviewer-ready remediation.",
            href: "/platform/re-examination",
          },
          {
            title: "Container gates",
            body: "Images, registries, admission webhooks, Kubernetes policies, and deployment blocking.",
            href: "/platform/cloud-and-infrastructure",
          },
        ],
      },
      {
        title: "Prioritization",
        items: [
          {
            title: "Reachability",
            body: "Connect code and dependency issues to reachable runtime paths and attack context.",
            href: "#delivery",
          },
          {
            title: "AI triage",
            body: "Deduplication, exploit narratives, severity reasoning, and remediation prioritization.",
            href: "#delivery",
          },
          {
            title: "Letter grade",
            body: "Executive-grade risk scoring across app, repo, AI, cloud, and compliance posture.",
            href: "/platform/letter-grade",
          },
          {
            title: "Threat modeling",
            body: "STRIDE, DREAD, attack trees, abuse cases, and generated mitigations per engagement.",
            href: "/platform/threat-models",
          },
        ],
      },
    ],
  },
  {
    label: "AI Security",
    eyebrow: "LLM and agentic systems",
    title: "Red team models, agents, tools, and guardrails",
    body: "Test AI products before attackers do: prompt attacks, tool abuse, data leakage, unsafe output, guardrail bypass, multi-agent workflows, and runtime policy enforcement.",
    cta: {
      title: "Run an AI target",
      body: "Create an LLM, chatbot, API, or agentic workflow test.",
      href: "/targets/new",
    },
    quickLinks: [
      {
        title: "LLM red team",
        body: "OWASP LLM Top 10 campaigns with datasets and judges.",
        href: "/platform/llm-red-team",
      },
      {
        title: "AI agents",
        body: "Tool-use, planner, memory, and workflow security tests.",
        href: "/platform/ai-agents",
      },
      {
        title: "Agent swarms",
        body: "Recon, breaker, exploit, synthesis, and reporting agents.",
        href: "/platform/agent-swarms",
      },
      {
        title: "Recommended guardrails",
        body: "Scan-specific policy controls and runtime mitigations.",
        href: "#ai",
      },
    ],
    groups: [
      {
        title: "LLM Red Team",
        items: [
          {
            title: "OWASP LLM Top 10",
            body: "Prompt injection, insecure output, training data exposure, DoS, supply chain, data leakage, plugins, agency, overreliance, and model theft.",
            href: "/platform/llm-red-team",
          },
          {
            title: "Attack strategies",
            body: "Roleplay, payload splitting, obfuscation, encoding, jailbreak corpora, regression suites, and judge-backed scoring.",
            href: "/platform/llm-red-team",
          },
          {
            title: "Transports",
            body: "Chat completions, HTTP endpoints, LiteLLM, MCP tools, hosted chatbots, and custom adapters.",
            href: "/platform/llm-red-team",
          },
          {
            title: "Evidence and cost",
            body: "Conversation traces, pass/fail judges, token accounting, retries, and reproducible prompts.",
            href: "/ai-security/evidence-and-cost",
          },
        ],
      },
      {
        title: "Agentic Testing",
        items: [
          {
            title: "Tool authorization",
            body: "Abuse tests for tool calls, privilege boundaries, connector permissions, and unsafe side effects.",
            href: "/platform/ai-agents",
          },
          {
            title: "Memory and context",
            body: "Prompt persistence, data exfiltration, cross-session leakage, and retrieval poisoning.",
            href: "/platform/ai-agents",
          },
          {
            title: "Planner attacks",
            body: "Goal hijacking, policy bypass, hidden instructions, and chained tool misuse.",
            href: "/platform/agent-swarms",
          },
          {
            title: "Swarm orchestration",
            body: "Scope, recon, crawler, vuln, exploit, post-exploitation, detection, and report specialists.",
            href: "/platform/agent-swarms",
          },
        ],
      },
      {
        title: "Guardrails",
        items: [
          {
            title: "Sentry runtime guardrail",
            body: "Policy checks for prompts, responses, tools, HTML, secrets, PII, and unsafe actions.",
            href: "#ai",
          },
          {
            title: "Sidecars and middleware",
            body: "HTTP proxy, LiteLLM plugin, MCP middleware, and app-level enforcement patterns.",
            href: "#ai",
          },
          {
            title: "AI governance",
            body: "OWASP LLM, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001, GDPR, and SOC 2 mapping.",
            href: "#ai",
          },
          {
            title: "Regression tests",
            body: "Keep known jailbreaks, unsafe outputs, and policy bypasses from returning after releases.",
            href: "/platform/llm-red-team",
          },
        ],
      },
    ],
  },
];

export function slugifyNavTitle(value: string) {
  return value
    .toLowerCase()
    .replace(/&/g, "and")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function getMenuSlug(label: string) {
  return slugifyNavTitle(label);
}

export function getMenuOverviewHref(menu: NavMenu | string) {
  const label = typeof menu === "string" ? menu : menu.label;
  return `/${getMenuSlug(label)}/overview`;
}

export function getNavItemHref(menu: NavMenu | string, item: NavItem | string) {
  const label = typeof menu === "string" ? menu : menu.label;
  const title = typeof item === "string" ? item : item.title;
  return `/${getMenuSlug(label)}/${slugifyNavTitle(title)}`;
}

export type MarketingTopic = {
  menu: NavMenu;
  item: NavItem;
  slug: string;
  href: string;
  groupTitle: string;
  isOverview?: boolean;
};

export function getMarketingTopics() {
  return NAV_MENUS.flatMap((menu) => {
    const overview: MarketingTopic = {
      menu,
      item: {
        title: `${menu.label} overview`,
        body: menu.body,
        href: getMenuOverviewHref(menu),
      },
      slug: "overview",
      href: getMenuOverviewHref(menu),
      groupTitle: menu.eyebrow,
      isOverview: true,
    };
    const cta: MarketingTopic = {
      menu,
      item: menu.cta,
      slug: slugifyNavTitle(menu.cta.title),
      href: getNavItemHref(menu, menu.cta),
      groupTitle: "Featured action",
    };
    const quick = menu.quickLinks.map((item) => ({
      menu,
      item,
      slug: slugifyNavTitle(item.title),
      href: getNavItemHref(menu, item),
      groupTitle: "Featured",
    }));
    const grouped = menu.groups.flatMap((group) =>
      group.items.map((item) => ({
        menu,
        item,
        slug: slugifyNavTitle(item.title),
        href: getNavItemHref(menu, item),
        groupTitle: group.title,
      })),
    );
    return [overview, cta, ...quick, ...grouped];
  });
}

export function getMarketingTopic(menuSlug: string, itemSlug: string) {
  return getMarketingTopics().find(
    (topic) =>
      getMenuSlug(topic.menu.label) === menuSlug && topic.slug === itemSlug,
  );
}

export function getTopicsForMenu(menuSlug: string) {
  return getMarketingTopics().filter(
    (topic) => getMenuSlug(topic.menu.label) === menuSlug,
  );
}

// An "alias" topic is a nav entry whose data-supplied ``item.href`` points
// somewhere other than the auto-built ``/<menuSlug>/<slug>`` route. These
// entries exist so the marketing menu can reuse a single concept (e.g.
// "Agent swarms") across multiple menus while still linking to one canonical
// page (e.g. ``/platform/agent-swarms``). The auto-built alias URL is not
// where users navigate — but Next.js was still pre-rendering it under
// /<menuSlug>/<slug>, which produced near-duplicate content and caused
// Google to mark them as "Alternate page with proper canonical tag" or
// "Excluded by noindex" (GSC Page Indexing report 2026-05-18).
//
// Now: alias topics are skipped from static-param generation, served with
// a permanent redirect to the canonical destination, and excluded from
// the sitemap. Self-canonical topics (item.href === topic.href, or no
// explicit item.href on overview entries) still render normally.
export function isAliasTopic(topic: MarketingTopic): boolean {
  const itemHref = topic.item?.href;
  if (!itemHref) return false;
  if (itemHref.startsWith("#")) return true; // anchor-only — alias to overview
  return itemHref !== topic.href;
}

export function aliasTarget(topic: MarketingTopic): string {
  const itemHref = topic.item.href;
  if (itemHref.startsWith("#")) {
    // Anchor-only: send the user to the menu overview with the anchor
    // preserved so the in-page jump still works.
    return `${getMenuOverviewHref(topic.menu)}${itemHref}`;
  }
  return itemHref;
}

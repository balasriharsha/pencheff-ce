import Link from "next/link";
import { LandingNav } from "@/components/landing-nav";
import { JsonLd } from "@/components/json-ld";
import "@/styles/landing.css";
import { createMetadata } from "@/lib/seo";
import {
  breadcrumbJsonLd,
  graphJsonLd,
  organizationJsonLd,
  webPageJsonLd,
} from "@/lib/structured-data";

const DESCRIPTION =
  "Real-world examples of how Pencheff assessments surface exploitable vulnerabilities, produce audit-ready evidence, and support remediation. Coming soon.";

export const metadata = createMetadata({
  title: "Case Studies",
  description: DESCRIPTION,
  path: "/company/case-studies",
});

export default function CaseStudiesPage() {
  return (
    <div className="landing-root">
      <LandingNav />
      <JsonLd
        data={graphJsonLd([
          organizationJsonLd(),
          webPageJsonLd({
            name: "Case Studies | Pencheff",
            description: DESCRIPTION,
            path: "/company/case-studies",
          }),
          breadcrumbJsonLd([
            { name: "Home", path: "/" },
            { name: "Company", path: "/company/overview" },
            { name: "Case Studies", path: "/company/case-studies" },
          ]),
        ])}
      />

      <main className="lp-article">
        <div className="lp-container">
          <header className="lp-article-head lp-article-grid">
            <div className="lp-article-copy">
              <p className="lp-eyebrow">Company</p>
              <h1>Case Studies</h1>
              <p>
                We&apos;re preparing detailed write-ups of real Pencheff
                assessments — showing scope, findings, exploit chains, and
                remediation outcomes. We&apos;ll publish them here as engagements
                complete and clients approve sharing.
              </p>
            </div>
          </header>

          <div className="lp-article-body">
            <div className="lp-article-sections">
              <div className="lp-article-section">
                <h2>In the meantime</h2>
                <div className="lp-article-section-body">
                  <p>
                    If you&apos;re evaluating Pencheff for your security programme
                    and want to understand what a real assessment looks like,
                    we&apos;re happy to walk you through an example engagement
                    directly — scope, findings format, evidence quality, and
                    report output.
                  </p>
                  <p>
                    Write to{" "}
                    <a href="mailto:hello@pencheff.com">hello@pencheff.com</a>{" "}
                    with a brief description of your use case and we&apos;ll
                    set up a call.
                  </p>
                  <div className="lp-article-cta">
                    <Link href="/signup" className="lp-btn lp-btn-royal">
                      Start a free assessment
                    </Link>
                    <Link href="/company/contact" className="lp-btn lp-btn-ghost">
                      Contact us
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

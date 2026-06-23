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
  "Pencheff is a product of Magadha Group — the team behind the adversarial security platform.";

export const metadata = createMetadata({
  title: "Leadership",
  description: DESCRIPTION,
  path: "/company/leadership",
});

export default function LeadershipPage() {
  return (
    <div className="landing-root">
      <LandingNav />
      <JsonLd
        data={graphJsonLd([
          organizationJsonLd(),
          webPageJsonLd({
            name: "Leadership | Pencheff",
            description: DESCRIPTION,
            path: "/company/leadership",
          }),
          breadcrumbJsonLd([
            { name: "Home", path: "/" },
            { name: "Company", path: "/company/overview" },
            { name: "Leadership", path: "/company/leadership" },
          ]),
        ])}
      />

      <main className="lp-article">
        <div className="lp-container">
          <header className="lp-article-head lp-article-grid">
            <div className="lp-article-copy">
              <p className="lp-eyebrow">Company</p>
              <h1>Leadership</h1>
            </div>
          </header>

          <div className="lp-article-body">
            <div className="lp-article-sections">
              <div className="lp-article-section">
                <h2>A product of Magadha Group</h2>
                <div className="lp-article-section-body">
                  <p>
                    Pencheff is a product of{" "}
                    <a
                      href="https://magadhagroup.com"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Magadha Group
                    </a>{" "}
                    — built to use AI to run the adversarial testing cycle
                    autonomously, so security teams get rigorous, reproducible
                    findings without the manual overhead that makes thorough
                    testing expensive and slow.
                  </p>
                  <p>
                    Explore the wider group at{" "}
                    <a
                      href="https://magadhagroup.com"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      magadhagroup.com
                    </a>
                    . If you&apos;d like to connect, write to{" "}
                    <a href="mailto:hello@pencheff.com">hello@pencheff.com</a>.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

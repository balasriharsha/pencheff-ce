import { LandingNav } from "@/components/landing-nav";
import { JsonLd } from "@/components/json-ld";
import "@/styles/landing.css";
import { createMetadata } from "@/lib/seo";
import { breadcrumbJsonLd, webPageJsonLd } from "@/lib/structured-data";

const DESCRIPTION =
  "Pencheff is not actively hiring right now. Leave your details and we will reach out when roles open.";

export const metadata = createMetadata({
  title: "Careers",
  description: DESCRIPTION,
  path: "/company/careers",
});

export default function CareersPage() {
  return (
    <div className="landing-root">
      <LandingNav />
      <JsonLd
        data={[
          webPageJsonLd({
            name: "Careers | Pencheff",
            description: DESCRIPTION,
            path: "/company/careers",
          }),
          breadcrumbJsonLd([
            { name: "Home", path: "/" },
            { name: "Company", path: "/company/overview" },
            { name: "Careers", path: "/company/careers" },
          ]),
        ]}
      />

      <main className="lp-article">
        <div className="lp-container">
          <header className="lp-article-head lp-article-grid">
            <div className="lp-article-copy">
              <p className="lp-eyebrow">Company</p>
              <h1>Careers</h1>
              <p>
                We&apos;re not actively hiring right now. When we open roles,
                we&apos;ll post them here first.
              </p>
            </div>
          </header>

          <div className="lp-article-body">
            <div className="lp-article-sections">
              <div className="lp-article-section">
                <h2>Stay in touch</h2>
                <div className="lp-article-section-body">
                  <p>
                    If you work in application security, security engineering,
                    or adversarial tooling and want to be considered when we do
                    hire, send a brief introduction to{" "}
                    <a href="mailto:hello@pencheff.com?subject=Careers%20at%20Pencheff">
                      hello@pencheff.com
                    </a>{" "}
                    with the subject line &ldquo;Careers at Pencheff&rdquo;.
                  </p>
                  <p>
                    We read every message and will reach out if your background
                    fits a future opening.
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

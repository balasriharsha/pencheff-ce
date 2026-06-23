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
import { absoluteUrl } from "@/lib/seo";

const DESCRIPTION =
  "Contact Pencheff for sales, security assessments, partnerships, and responsible disclosure. We reply within one business day.";

export const metadata = createMetadata({
  title: "Contact",
  description: DESCRIPTION,
  path: "/company/contact",
});

const contactPageJsonLd = {
  "@type": "Organization",
  "@id": absoluteUrl("/#organization"),
  name: "Pencheff",
  url: absoluteUrl("/"),
  contactPoint: [
    {
      "@type": "ContactPoint",
      contactType: "customer support",
      email: "hello@pencheff.com",
      availableLanguage: "English",
      areaServed: "Worldwide",
    },
    {
      "@type": "ContactPoint",
      contactType: "technical support",
      email: "security@pencheff.com",
      availableLanguage: "English",
      areaServed: "Worldwide",
    },
  ],
  address: {
    "@type": "PostalAddress",
    addressCountry: "IN",
  },
};

export default function ContactPage() {
  return (
    <div className="landing-root">
      <LandingNav />
      <JsonLd
        data={graphJsonLd([
          organizationJsonLd(),
          webPageJsonLd({
            name: "Contact | Pencheff",
            description: DESCRIPTION,
            path: "/company/contact",
          }),
          breadcrumbJsonLd([
            { name: "Home", path: "/" },
            { name: "Company", path: "/company/overview" },
            { name: "Contact", path: "/company/contact" },
          ]),
          contactPageJsonLd,
        ])}
      />

      <main className="lp-article">
        <div className="lp-container">
          <header className="lp-article-head lp-article-grid">
            <div className="lp-article-copy">
              <p className="lp-eyebrow">Company</p>
              <h1>Contact us</h1>
              <p>
                Write to{" "}
                <a href="mailto:hello@pencheff.com">hello@pencheff.com</a> — we
                reply within one business day.
              </p>
            </div>
          </header>

          <div className="lp-article-body">
            <div className="lp-article-sections">
              <div className="lp-article-section">
                <h2>General enquiries &amp; sales</h2>
                <div className="lp-article-section-body">
                  <p>
                    For questions about enterprise deployments, onboarding,
                    platform capabilities, or anything else:{" "}
                    <a href="mailto:hello@pencheff.com">hello@pencheff.com</a>
                  </p>
                </div>
              </div>

              <div className="lp-article-section">
                <h2>Security &amp; responsible disclosure</h2>
                <div className="lp-article-section-body">
                  <p>
                    To report a vulnerability in Pencheff or its infrastructure,
                    write to{" "}
                    <a href="mailto:security@pencheff.com">
                      security@pencheff.com
                    </a>
                    . We acknowledge all disclosures within 24 hours and aim to
                    remediate critical issues within 7 days.
                  </p>
                </div>
              </div>

              <div className="lp-article-section">
                <h2>Location</h2>
                <div className="lp-article-section-body">
                  <p>
                    Pencheff is a remote-first company based in India. We work
                    with security teams and engineering organisations worldwide.
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

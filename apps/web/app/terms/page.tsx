import { LandingMarketingPage } from "@/components/landing-marketing-page";
import { LandingArticle } from "@/components/landing-article";
import { JsonLd } from "@/components/json-ld";
import { createMetadata } from "@/lib/seo";
import { breadcrumbJsonLd, webPageJsonLd } from "@/lib/structured-data";

const TERMS_DESCRIPTION =
  "Pencheff terms and conditions for authorized security testing, accounts, service availability, reports, and acceptable use.";

export const metadata = createMetadata({
  title: "Terms and Conditions",
  description: TERMS_DESCRIPTION,
  path: "/terms",
});

export default function TermsPage() {
  return (
    <LandingMarketingPage closing={false}>
      <JsonLd
        data={[
          webPageJsonLd({
            name: "Pencheff terms and conditions",
            description: TERMS_DESCRIPTION,
            path: "/terms",
          }),
          breadcrumbJsonLd([
            { name: "Home", path: "/" },
            { name: "Terms and conditions", path: "/terms" },
          ]),
        ]}
      />
      <LandingArticle
        eyebrow="Legal"
        title={
          <>
            Terms &{" "}
            <span className="lp-italic-gilt">conditions.</span>
          </>
        }
        lede="These terms govern access to and use of the Pencheff website and platform."
        sections={[
          {
            heading: "Authorised use only",
            body:
              "You must have explicit authorisation to test any target you submit. You are solely responsible for your targets, scope, credentials, and compliance with applicable laws and policies.",
          },
          {
            heading: "Accounts",
            body:
              "You are responsible for maintaining the confidentiality of your account and for all activity performed under it. Notify us if you suspect unauthorised access.",
          },
          {
            heading: "Service availability",
            body:
              "We may modify, suspend, or discontinue parts of the service to maintain security, reliability, or to improve the product. Planned maintenance may affect availability.",
          },
          {
            heading: "Content and reports",
            body:
              "Reports and findings are generated from automated and operator-configured analysis. You are responsible for interpreting results and validating fixes before relying on them for production or compliance decisions.",
          },
          {
            heading: "Acceptable behaviour",
            body:
              "Do not misuse the service, attempt to bypass controls, interfere with operation, or use the platform to harm others. We may restrict access for abuse or policy violations.",
          },
          {
            heading: "Contact",
            body:
              "Questions about these terms: balasriharsha.ch@gmail.com.",
          },
        ]}
      />
    </LandingMarketingPage>
  );
}

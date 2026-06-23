import { LandingMarketingPage } from "@/components/landing-marketing-page";
import { LandingArticle } from "@/components/landing-article";
import { JsonLd } from "@/components/json-ld";
import { createMetadata } from "@/lib/seo";
import { breadcrumbJsonLd, webPageJsonLd } from "@/lib/structured-data";

const PRIVACY_DESCRIPTION =
  "Pencheff privacy policy for website, account, product usage, security assessment data, retention, and support requests.";

export const metadata = createMetadata({
  title: "Privacy Policy",
  description: PRIVACY_DESCRIPTION,
  path: "/privacy",
});

export default function PrivacyPolicyPage() {
  return (
    <LandingMarketingPage closing={false}>
      <JsonLd
        data={[
          webPageJsonLd({
            name: "Pencheff privacy policy",
            description: PRIVACY_DESCRIPTION,
            path: "/privacy",
          }),
          breadcrumbJsonLd([
            { name: "Home", path: "/" },
            { name: "Privacy policy", path: "/privacy" },
          ]),
        ]}
      />
      <LandingArticle
        eyebrow="Legal"
        title={
          <>
            Privacy{" "}
            <span className="lp-italic-gilt">policy.</span>
          </>
        }
        lede="This policy describes how Pencheff collects, uses, and protects information when you use the website and platform."
        sections={[
          {
            heading: "Information we collect",
            body:
              "We collect account information you provide (such as name, email, and organisation details). We may also collect product usage data (such as pages visited and actions taken) to operate and improve the service.",
          },
          {
            heading: "Security assessment data",
            body:
              "When you run assessments, the platform may process target metadata, scan artefacts, and findings necessary to produce reports. You are responsible for ensuring you have authorisation to test any target you submit.",
          },
          {
            heading: "How we use information",
            body:
              "We use information to provide the service (authentication, running assessments, generating reports), to maintain security and reliability, to respond to enquiries, and to improve product quality.",
          },
          {
            heading: "Sharing",
            body:
              "We do not sell personal information. We may share data with service providers that help us operate the platform (for example, hosting and authentication), subject to appropriate safeguards.",
          },
          {
            heading: "Retention",
            body:
              "We retain information only as long as needed for the purposes described above, and as required for legal, security, and audit obligations where applicable.",
          },
          {
            heading: "Contact",
            body:
              "For privacy questions or requests, contact: balasriharsha.ch@gmail.com.",
          },
        ]}
      />
    </LandingMarketingPage>
  );
}

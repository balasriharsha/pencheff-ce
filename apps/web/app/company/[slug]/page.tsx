import {
  getMarketingDetailMetadata,
  getMarketingStaticParams,
  MarketingDetailPage,
} from "@/components/marketing-detail-page";
import "@/styles/landing.css";

const MENU = "company";

// Slugs that have a dedicated, hand-built page under app/company/<slug>/.
// In `output: export` the dynamic [slug] route writes the same out/*.html path
// as the static segment and clobbers it, so the bespoke page never shows.
// Excluding the slug here lets the dedicated page own the route.
const DEDICATED_SLUGS = new Set([
  "leadership",
  "careers",
  "case-studies",
  "contact",
]);

export function generateStaticParams() {
  return getMarketingStaticParams(MENU).filter(
    (p) => !DEDICATED_SLUGS.has(p.slug),
  );
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  return getMarketingDetailMetadata(MENU, slug);
}

export default async function CompanyDetailRoute({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  return <MarketingDetailPage menuSlug={MENU} slug={slug} />;
}

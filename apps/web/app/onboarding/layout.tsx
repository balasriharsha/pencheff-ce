import { privateRouteMetadata } from "@/lib/seo";

export const metadata = privateRouteMetadata;

export default function OnboardingLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}

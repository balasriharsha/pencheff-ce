import { privateRouteMetadata } from "@/lib/seo";

export const metadata = privateRouteMetadata;

export default function InviteLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}

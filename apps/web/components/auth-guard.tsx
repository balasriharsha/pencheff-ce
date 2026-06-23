"use client";

import { useAuth } from "@clerk/react";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import { useWorkspace } from "@/lib/workspace-context";

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const { isLoaded, isSignedIn } = useAuth();
  const { loading, loadError, orgs } = useWorkspace();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      router.replace("/login");
      return;
    }
    // Force signed-in users without an Org through onboarding before they
    // can see any tenant-scoped page. /onboarding itself is exempt so the
    // wizard can render. We require a SUCCESSFUL orgs load (!loadError) —
    // a failed /orgs fetch must never be mistaken for "zero orgs", or a
    // transient API error would wrongly eject a real user to onboarding.
    if (isLoaded && isSignedIn && !loading && !loadError && orgs.length === 0) {
      if (pathname !== "/onboarding") router.replace("/onboarding");
    }
  }, [isLoaded, isSignedIn, loading, loadError, orgs, pathname, router]);

  if (!isLoaded || !isSignedIn) return null;
  if (!loading && !loadError && orgs.length === 0 && pathname !== "/onboarding")
    return null;
  return <>{children}</>;
}

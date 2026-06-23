"use client";
import { ClerkProvider } from "@clerk/react";
import { useRouter } from "next/navigation";
import type { ReactNode } from "react";
import { clerkAppearance } from "@/lib/clerk-appearance";

// Cross-subdomain auth: after login/signup on pencheff.com, land on the app
// subdomain. Clerk's production instance must have cookies scoped to the apex
// domain (configure in the Clerk dashboard → Domains).
const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.pencheff.com";
const POST_LOGIN = `${APP_URL}/dashboard`;
const POST_SIGNUP = `${APP_URL}/dashboard`;

export function AppClerkProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  return (
    <ClerkProvider
      publishableKey={process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY!}
      routerPush={(to) => router.push(to)}
      routerReplace={(to) => router.replace(to)}
      appearance={clerkAppearance}
      signInUrl="/login"
      signUpUrl="/signup"
      signInFallbackRedirectUrl={POST_LOGIN}
      signUpFallbackRedirectUrl={POST_SIGNUP}
    >
      {children}
    </ClerkProvider>
  );
}

"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { SignIn, useAuth, useUser } from "@clerk/react";

/**
 * Desktop OAuth bridge — completes Clerk sign-in in the browser, then
 * exchanges the Clerk session JWT for a long-lived native JWT pair (via
 * POST /api/auth/desktop-bridge) and redirects to the Mac app's loopback
 * listener with the tokens in the query string.
 *
 * Called from Pencheff Studio's AuthService with two params:
 *   - redirect: the loopback URL the Mac app is listening on
 *              (must match /^http:\/\/127\.0\.0\.1:\d{4,5}\/callback$/)
 *   - state: CSRF nonce the Mac app generated; passed through verbatim
 */
function Bridge() {
  const params = useSearchParams();
  const redirect = params.get("redirect") ?? "";
  const state = params.get("state") ?? "";

  const validRedirect = useMemo(
    () => /^http:\/\/127\.0\.0\.1:\d{4,5}\/callback$/.test(redirect),
    [redirect],
  );

  const { getToken, isLoaded: authLoaded } = useAuth();
  const { isLoaded: userLoaded, isSignedIn } = useUser();

  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<
    "loading" | "signin" | "exchanging" | "redirecting"
  >("loading");

  useEffect(() => {
    if (!validRedirect) {
      setError(
        `Invalid loopback URL "${redirect}". Pencheff Studio passes a URL of the form http://127.0.0.1:<port>/callback; anything else is refused.`,
      );
      return;
    }
    if (!authLoaded || !userLoaded) return;
    if (!isSignedIn) {
      setPhase("signin");
      return;
    }

    setPhase("exchanging");
    (async () => {
      try {
        const clerkToken = await getToken();
        if (!clerkToken) throw new Error("No Clerk session token available");

        // The API moved to api.pencheff.com (static-export cutover removed
        // Next API routes). In prod NEXT_PUBLIC_API_URL is https://api.pencheff.com
        // → https://api.pencheff.com/auth/desktop-bridge; locally it falls back
        // to "/api" → /api/auth/desktop-bridge via the dev rewrite.
        const apiBase = process.env.NEXT_PUBLIC_API_URL || "/api";
        const res = await fetch(`${apiBase}/auth/desktop-bridge`, {
          method: "POST",
          headers: { Authorization: `Bearer ${clerkToken}` },
        });
        if (!res.ok) {
          const body = await res.text();
          throw new Error(
            `Token exchange failed (${res.status}): ${body || "no body"}`,
          );
        }
        const { access_token, refresh_token } = await res.json();
        if (!access_token || !refresh_token) {
          throw new Error("Exchange response missing token fields");
        }

        setPhase("redirecting");
        const u = new URL(redirect);
        u.searchParams.set("access_token", access_token);
        u.searchParams.set("refresh_token", refresh_token);
        u.searchParams.set("state", state);
        // Brief pause so the user sees the success state before we navigate
        await new Promise((r) => setTimeout(r, 250));
        window.location.href = u.toString();
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
      }
    })();
  }, [
    authLoaded,
    userLoaded,
    isSignedIn,
    redirect,
    state,
    getToken,
    validRedirect,
  ]);

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-50 p-8">
        <div className="max-w-md w-full bg-white rounded-xl border border-zinc-200 p-6 text-center">
          <div className="text-red-600 text-3xl mb-2">⚠️</div>
          <h1 className="text-lg font-semibold mb-2">Desktop sign-in failed</h1>
          <p className="text-sm text-zinc-600 whitespace-pre-wrap">{error}</p>
          <p className="text-xs text-zinc-400 mt-4">
            Return to Pencheff Studio and click Cancel to try again.
          </p>
        </div>
      </div>
    );
  }

  if (phase === "signin") {
    const here =
      typeof window !== "undefined"
        ? window.location.href
        : "/oauth/desktop-bridge";
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-zinc-50 p-8 gap-6">
        <div className="text-center max-w-md">
          <h1 className="text-2xl font-semibold">Sign in to Pencheff Studio</h1>
          <p className="text-sm text-zinc-600 mt-2">
            Finish signing in here. Pencheff Studio will pick up automatically
            once you&apos;re done.
          </p>
        </div>
        <SignIn
          routing="hash"
          forceRedirectUrl={here}
          signUpForceRedirectUrl={here}
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-50 p-8">
      <div className="text-center space-y-3">
        <div
          className="animate-spin h-8 w-8 border-2 border-violet-600 border-t-transparent rounded-full mx-auto"
          aria-hidden
        />
        <p className="text-sm text-zinc-600">
          {phase === "exchanging"
            ? "Handing off to Pencheff Studio…"
            : "Signed in. You can close this tab."}
        </p>
      </div>
    </div>
  );
}

export default function DesktopBridgePage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center bg-zinc-50">
          <p className="text-sm text-zinc-500">Loading…</p>
        </div>
      }
    >
      <Bridge />
    </Suspense>
  );
}

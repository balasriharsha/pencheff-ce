"use client";
import { SignIn } from "@clerk/react";

export function SignInBox() {
  return (
    <SignIn
      routing="hash"
      signUpUrl="/signup"
      fallbackRedirectUrl="/dashboard"
    />
  );
}

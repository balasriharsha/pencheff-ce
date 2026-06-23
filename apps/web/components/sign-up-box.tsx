"use client";
import { SignUp } from "@clerk/react";

export function SignUpBox() {
  return (
    <SignUp
      routing="hash"
      signInUrl="/login"
      fallbackRedirectUrl="/dashboard"
    />
  );
}

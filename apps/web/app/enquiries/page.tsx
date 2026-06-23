import { redirect } from "next/navigation";

// /support/contact-support is a marketing-nav alias that redirects back to
// /enquiries, so redirecting there creates an infinite loop. Send enquiries
// straight to the canonical contact page.
export default function EnquiriesPage() {
  redirect("/company/contact");
}

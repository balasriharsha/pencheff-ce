"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

// This body is authored docs content (apps/docs/pages/**); its root-relative
// links (/features/*, /reference/*, /tutorials/*, …) resolve on the docs site,
// not on the marketing host — left as-is they 404. Rewrite them to the docs
// origin so they behave like the page's "Documentation" links.
const DOCS_BASE =
  process.env.NEXT_PUBLIC_DOCS_URL ?? "https://docs.pencheff.com";

function resolveDocHref(href?: string): string | undefined {
  if (!href) return href;
  // Leave anchors, external links, and mailto/tel untouched.
  if (!href.startsWith("/")) return href;
  return `${DOCS_BASE}${href}`;
}

export function MarketingDocBody({ markdown }: { markdown: string }) {
  return (
    <div className="detail-doc-prose">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: () => null,
          a: ({ href, children, ...props }) => {
            const resolved = resolveDocHref(href);
            const external = resolved !== href || /^https?:/.test(href ?? "");
            return (
              <a
                href={resolved}
                {...(external
                  ? { target: "_blank", rel: "noopener noreferrer" }
                  : {})}
                {...props}
              >
                {children}
              </a>
            );
          },
        }}
      >
        {markdown}
      </ReactMarkdown>
    </div>
  );
}

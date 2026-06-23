import React from "react";
import type { DocsThemeConfig } from "nextra-theme-docs";
import DocsThemeToggle from "./components/theme-toggle";

const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.pencheff.com";
const LANDING_URL =
  process.env.NEXT_PUBLIC_LANDING_URL ?? "https://pencheff.com";

// Sunset Observability palette — keep in sync with apps/web + docs-custom.css
const INK = "#150F0A";
const GRAPHITE = "#322A20";
const SLATE = "#6B5E47";
const MIST = "#B5A993";
const HAIRLINE = "#E8DCC6";
const PAPER = "#FFFFFF";
const VELLUM = "#FBF6EC";
const EMBER = "#FB7A1C";
const EMBER_DEEP = "#E85A06";
const GILT = "#C9A24E";
const GILT_DEEP = "#8A6A2A";

const SERIF = "'Fraunces', Georgia, ui-serif, serif";
const SANS = "'Geist', 'Söhne', Inter, system-ui, sans-serif";

const config: DocsThemeConfig = {
  logo: (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 10,
        textDecoration: "none",
      }}
    >
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src="/logo.png"
        alt="Pencheff"
        width={32}
        height={32}
        style={{ display: "block", flexShrink: 0 }}
      />
      <span
        style={{
          fontFamily: SERIF,
          fontSize: 22,
          fontWeight: 500,
          fontVariationSettings: "'opsz' 48, 'SOFT' 30",
          letterSpacing: "-0.025em",
          color: INK,
          lineHeight: 1,
        }}
      >
        Pencheff
      </span>
    </span>
  ),
  project: {
    link: "https://github.com/BalaSriharsha-Ch/pencheff",
  },
  chat: {
    link: "https://discord.gg/pencheff",
  },
  docsRepositoryBase:
    "https://github.com/BalaSriharsha-Ch/pencheff/tree/main/apps/docs",
  navbar: {
    extraContent: (
      <>
        <DocsThemeToggle />
        <a
          href={APP_URL}
          style={{
            fontFamily: SANS,
            fontSize: 13,
            fontWeight: 600,
            letterSpacing: "0.005em",
            padding: "7px 16px",
            border: `1px solid ${EMBER_DEEP}`,
            borderRadius: 6,
            marginLeft: 10,
            color: PAPER,
            textDecoration: "none",
            transition: "background 0.2s, box-shadow 0.2s",
            background: `linear-gradient(180deg, ${EMBER} 0%, ${EMBER_DEEP} 100%)`,
            boxShadow:
              "inset 0 1px 0 rgba(255,255,255,0.32), 0 6px 16px -6px rgba(232,90,6,0.45)",
          }}
        >
          Open app →
        </a>
      </>
    ),
  },
  footer: {
    content: (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 10,
          width: "100%",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            width: "100%",
            flexWrap: "wrap",
            gap: 8,
          }}
        >
          <span style={{ fontFamily: SANS, fontSize: 13, color: SLATE }}>
            © {new Date().getFullYear()}{" "}
            <a
              href={LANDING_URL}
              target="_blank"
              rel="noreferrer"
              style={{
                color: GRAPHITE,
                textDecoration: "underline",
                textDecorationColor: GILT,
                textUnderlineOffset: 4,
              }}
            >
              Pencheff
            </a>{" "}
            · AI penetration testing
          </span>
          <span style={{ fontFamily: SANS, fontSize: 13, color: SLATE }}>
            <a href={LANDING_URL + "/pricing"} style={{ color: SLATE }}>
              Pricing
            </a>
            {" · "}
            <a href={APP_URL} style={{ color: SLATE }}>
              Dashboard
            </a>
            {" · "}
            <a
              href="https://github.com/BalaSriharsha-Ch/pencheff"
              style={{ color: SLATE }}
            >
              GitHub
            </a>
          </span>
        </div>
        <span
          style={{
            fontFamily: SANS,
            fontSize: 11,
            color: MIST,
            lineHeight: 1.6,
          }}
        >
          Third-party product names are used only for identification. Pencheff
          is not affiliated with, endorsed by, or sponsored by those owners.
          OWASP and OWASP Top 10 are trademarks or service marks of the OWASP
          Foundation; Pencheff is not affiliated with or endorsed by OWASP.
        </span>
      </div>
    ),
  },
  head: (
    <>
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Pencheff Docs</title>
      <meta property="og:title" content="Pencheff Docs" />
      <meta
        property="og:description"
        content="Pencheff — AI-native penetration testing agent. DAST, SCA, IaC, Network VA, continuous scanning, compliance reporting."
      />
      <link rel="icon" href="/logo.png" type="image/png" />
      <link rel="apple-touch-icon" href="/logo.png" />
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link
        rel="preconnect"
        href="https://fonts.gstatic.com"
        crossOrigin=""
      />
      {/* Default to dark — sets the theme before next-themes hydrates so
       *  the first paint already shows the sunset-night palette. Users can
       *  still toggle to light via the navbar moon/sun icon. */}
      <script
        dangerouslySetInnerHTML={{
          __html: `
            try {
              var stored = localStorage.getItem('theme');
              if (!stored) {
                localStorage.setItem('theme', 'dark');
                document.documentElement.classList.add('dark');
                document.documentElement.style.colorScheme = 'dark';
              }
            } catch(e) {}
          `,
        }}
      />
    </>
  ),
  search: { placeholder: "Search docs…" },
  sidebar: {
    defaultMenuCollapseLevel: 1,
    toggleButton: true,
  },
  toc: { backToTop: true },
  // Dark mode enabled — sunset-night palette in apps/docs/styles/docs-custom.css
  darkMode: true,
  // Ember orange (#FB7A1C) as the primary accent — hue 22°, sat 92%
  color: { hue: 22, saturation: 92 },
  banner: {
    key: "v1-release",
    content: (
      <a href="/release-notes" style={{ fontFamily: SANS, fontWeight: 500 }}>
        Pencheff v1.0 ships SCA + SBOM + IaC + host vulnerability assessment +
        YAML policy engine. Read the notes →
      </a>
    ),
    dismissible: true,
  },
};

export default config;

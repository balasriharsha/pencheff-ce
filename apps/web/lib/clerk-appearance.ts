/**
 * Clerk appearance tuned to "Sunset Observability":
 * warm paper canvas, hairline borders, Fraunces headlines, ember CTAs,
 * gilt accents. Palette mirrors apps/web/tailwind.config.ts so every
 * Clerk dialog (sign-in, sign-up, UserButton popover, Manage-account
 * modal, PricingTable) sits naturally next to the rest of the product.
 */

const PAPER = "#FFFFFF";
const VELLUM = "#FBF6EC";
const PARCHMENT = "#FDF8EF";
const HAIRLINE = "#E8DCC6";
const INK = "#150F0A";
const GRAPHITE = "#322A20";
const SLATE = "#6B5E47";
const MIST = "#B5A993";
const EMBER = "#FB7A1C";
const EMBER_DEEP = "#E85A06";
const GILT = "#C9A24E";
const GILT_DEEP = "#8A6A2A";
const OXBLOOD = "#7A1F1F";
const FOREST = "#2F5D3B";

const SERIF =
  "Fraunces, Tiempos, Georgia, ui-serif, serif";
const SANS =
  "Geist, Söhne, Inter, system-ui, -apple-system, Segoe UI, sans-serif";
const MONO = "'JetBrains Mono', 'Geist Mono', ui-monospace, monospace";

export const clerkAppearance = {
  variables: {
    colorPrimary: INK,
    colorBackground: PAPER,
    colorText: GRAPHITE,
    colorTextSecondary: SLATE,
    colorInputBackground: PAPER,
    colorInputText: GRAPHITE,
    colorNeutral: SLATE,
    colorDanger: OXBLOOD,
    colorSuccess: FOREST,
    colorWarning: GILT_DEEP,
    colorShimmer: HAIRLINE,
    fontFamily: SANS,
    fontFamilyButtons: SANS,
    fontSize: "14px",
    fontWeight: {
      normal: "400",
      medium: "500",
      semibold: "500",
      bold: "600",
    },
    borderRadius: "2px",
    spacingUnit: "1rem",
  },
  layout: {
    socialButtonsPlacement: "bottom",
    socialButtonsVariant: "blockButton",
    shimmer: false,
    unsafe_disableDevelopmentModeWarnings: true,
  },
  elements: {
    rootBox: { width: "100%" },

    // ── Card chrome (sign-in, sign-up, user-profile) ───────────────────
    card: {
      backgroundColor: PAPER,
      border: `1px solid ${HAIRLINE}`,
      borderRadius: "4px",
      boxShadow: "0 20px 48px -24px rgba(26,23,19,0.22)",
      padding: "2rem",
    },
    cardBox: { boxShadow: "none", borderRadius: "4px" },
    modalBackdrop: { backgroundColor: "rgba(26,23,19,0.45)" },
    modalContent: {
      backgroundColor: PAPER,
      border: `1px solid ${HAIRLINE}`,
      borderRadius: "4px",
    },

    headerTitle: {
      fontFamily: SERIF,
      fontSize: "28px",
      fontWeight: 500,
      letterSpacing: "-0.01em",
      color: INK,
    },
    headerSubtitle: { color: SLATE, fontSize: "14px" },

    // ── Social buttons ────────────────────────────────────────────────
    // The card is always white (PAPER), so the label must stay dark even when
    // the OS / site is in dark mode — set the text colour explicitly so
    // Clerk's prefers-color-scheme default can't flip it to white-on-white.
    socialButtonsBlockButton: {
      backgroundColor: PAPER,
      border: `1px solid ${INK}`,
      borderRadius: "2px",
      color: INK,
      fontWeight: 500,
      fontSize: "14px",
      "&:hover": { backgroundColor: VELLUM },
    },
    socialButtonsBlockButtonText: { color: INK, fontWeight: 500 },

    dividerLine: { backgroundColor: HAIRLINE },
    dividerText: {
      fontSize: "11px",
      letterSpacing: "0.18em",
      textTransform: "uppercase",
      color: SLATE,
      fontFamily: MONO,
    },

    // ── Form fields ───────────────────────────────────────────────────
    formFieldLabel: {
      fontSize: "11px",
      fontWeight: 500,
      letterSpacing: "0.18em",
      textTransform: "uppercase",
      color: SLATE,
      fontFamily: MONO,
    },
    formFieldInput: {
      border: `1px solid ${HAIRLINE}`,
      borderRadius: "6px",
      backgroundColor: PAPER,
      fontSize: "15px",
      color: GRAPHITE,
      "&:focus": {
        borderColor: EMBER,
        boxShadow: `0 0 0 2px rgba(251,122,28,0.18)`,
      },
    },
    formFieldHintText: { color: SLATE, fontSize: "12px" },
    formFieldErrorText: { color: OXBLOOD, fontSize: "12px" },

    formButtonPrimary: {
      backgroundColor: EMBER,
      backgroundImage: `linear-gradient(180deg, ${EMBER} 0%, ${EMBER_DEEP} 100%)`,
      border: `1px solid ${EMBER_DEEP}`,
      borderRadius: "6px",
      fontFamily: SANS,
      fontWeight: 600,
      fontSize: "14px",
      letterSpacing: "0.005em",
      textTransform: "none",
      boxShadow: `inset 0 1px 0 rgba(255,255,255,0.32), 0 8px 20px -8px rgba(232,90,6,0.45)`,
      "&:hover": {
        backgroundColor: EMBER_DEEP,
        backgroundImage: `linear-gradient(180deg, ${EMBER_DEEP} 0%, #C44805 100%)`,
        borderColor: "#C44805",
        boxShadow: `inset 0 1px 0 rgba(255,255,255,0.32), 0 14px 30px -10px rgba(232,90,6,0.6)`,
      },
    },
    formButtonReset: {
      color: SLATE,
      "&:hover": { color: INK, backgroundColor: "transparent" },
    },

    // Hide the "Secured by Clerk" and the development-mode banner —
    // both collide with the editorial look. (Safe: Clerk branding is
    // optional in their ToS for paid tiers; if you're on free, swap
    // ``display: none`` for a muted style below.)
    footer: { display: "none" },
    footerAction: { fontSize: "13px", color: SLATE },
    footerActionLink: {
      color: INK,
      textDecorationColor: GILT,
      textUnderlineOffset: "6px",
    },
    footerPages: { display: "none" },
    footerPagesLink: { display: "none" },
    logoBox: { display: "none" },
    internal: { display: "none" },
    // Dev-mode badge that pops up under Clerk test instances.
    badge__developmentMode: { display: "none" },

    identityPreview: {
      border: `1px solid ${HAIRLINE}`,
      borderRadius: "2px",
      backgroundColor: PAPER,
    },
    badge: {
      border: `1px solid ${HAIRLINE}`,
      borderRadius: "2px",
      color: SLATE,
      fontWeight: 500,
      letterSpacing: "0.16em",
      textTransform: "uppercase",
      fontSize: "10px",
      backgroundColor: VELLUM,
      fontFamily: MONO,
    },

    // ── UserButton popover ────────────────────────────────────────────
    userButtonPopoverCard: {
      border: `1px solid ${HAIRLINE}`,
      borderRadius: "4px",
      backgroundColor: PAPER,
      boxShadow: "0 20px 48px -24px rgba(26,23,19,0.22)",
    },
    userButtonPopoverMain: { backgroundColor: PAPER },
    userButtonPopoverFooter: {
      backgroundColor: VELLUM,
      borderTop: `1px solid ${HAIRLINE}`,
      "& p, & a": { color: SLATE, fontSize: "11px", fontFamily: MONO },
    },
    userButtonPopoverActionButton: {
      color: GRAPHITE,
      "&:hover": { backgroundColor: VELLUM, color: INK },
    },
    userButtonPopoverActionButtonText: { color: GRAPHITE, fontSize: "14px" },
    userButtonPopoverActionButtonIcon: { color: SLATE },
    userPreviewMainIdentifier: {
      color: INK,
      fontFamily: SERIF,
      fontSize: "15px",
      fontWeight: 500,
    },
    userPreviewSecondaryIdentifier: {
      color: SLATE,
      fontSize: "13px",
      fontFamily: MONO,
    },

    // ── UserProfile ("Manage account") modal ──────────────────────────
    // Clerk renders the modal as a two-column layout: a navigation
    // rail on the left and a stacked list of sections on the right.
    profilePage: { backgroundColor: PAPER },
    profileSection: {
      borderBottom: `1px solid ${HAIRLINE}`,
      paddingTop: "0.75rem",
      paddingBottom: "1.25rem",
    },
    profileSectionTitle: {
      fontFamily: SERIF,
      fontSize: "20px",
      fontWeight: 500,
      color: INK,
      letterSpacing: "-0.005em",
    },
    profileSectionTitleText: {
      fontFamily: SERIF,
      fontSize: "20px",
      fontWeight: 500,
      color: INK,
    },
    profileSectionSubtitle: { color: SLATE, fontSize: "13px" },
    profileSectionContent: { color: GRAPHITE, fontSize: "14px" },
    profileSectionPrimaryButton: {
      color: INK,
      fontWeight: 500,
      "&:hover": { color: GILT_DEEP, textDecoration: "underline" },
    },
    profileSectionItem: {
      paddingTop: "0.5rem",
      paddingBottom: "0.5rem",
    },

    // Navigation rail inside UserProfile.
    navbar: {
      backgroundColor: VELLUM,
      borderRight: `1px solid ${HAIRLINE}`,
    },
    navbarButtons: { gap: "0.25rem" },
    navbarButton: {
      color: SLATE,
      fontWeight: 500,
      fontSize: "13px",
      borderRadius: "2px",
      padding: "0.6rem 0.75rem",
      "&:hover": { backgroundColor: PAPER, color: INK },
    },
    navbarButtonIcon: { color: SLATE },
    navbarButton__active: {
      backgroundColor: PAPER,
      color: INK,
      borderLeft: `2px solid ${GILT}`,
    },
    pageScrollBox: { backgroundColor: PAPER },
    page: { backgroundColor: PAPER },

    accordionTriggerButton: {
      color: INK,
      fontWeight: 500,
      "&:hover": { backgroundColor: VELLUM },
    },
    accordionContent: { backgroundColor: PAPER },

    // Close-X on the modal.
    modalCloseButton: {
      color: SLATE,
      borderRadius: "2px",
      "&:hover": {
        color: INK,
        backgroundColor: VELLUM,
      },
    },

    // ── Menus / dropdowns (role selectors, more-options, etc.) ────────
    menuList: {
      backgroundColor: PAPER,
      border: `1px solid ${HAIRLINE}`,
      borderRadius: "4px",
      boxShadow: "0 8px 24px -12px rgba(26,23,19,0.18)",
    },
    menuItem: {
      color: GRAPHITE,
      fontSize: "14px",
      "&:hover": { backgroundColor: VELLUM, color: INK },
    },

    // ── PricingTable (signed-in billing) ──────────────────────────────
    pricingTableCard: {
      border: `1px solid ${HAIRLINE}`,
      borderRadius: "4px",
      backgroundColor: PAPER,
      boxShadow: "0 1px 2px rgba(26,23,19,0.04)",
    },
    pricingTable: { gap: "1.5rem" },

    // ── Organisations UI (unused but themed so accidental renders fit) ─
    organizationSwitcherTrigger: {
      border: `1px solid ${HAIRLINE}`,
      borderRadius: "2px",
      backgroundColor: VELLUM,
      color: GRAPHITE,
      "&:hover": { borderColor: INK, color: INK },
    },
    organizationPreviewMainIdentifier: { color: INK, fontFamily: SERIF },
  },
};

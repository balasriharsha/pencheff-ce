import type { CSSProperties, ReactNode } from "react";

export type AuthProofRow = { text: string; label: string };
export type AuthContextPanel = { title: string; body: string };

// CSS custom-property helper for the staggered entrance delays.
const delay = (ms: number) => ({ ["--lp-d"]: `${ms}ms` }) as CSSProperties;

/**
 * Shared shell for the marketing /login and /signup pages. Renders the dark
 * editorial copy column (eyebrow, title, lede, trust panel, context panels,
 * switch link) on the left and slots the Clerk card (`children`) on the right.
 * Presentational only — no auth logic lives here; SignInBox/SignUpBox keep
 * owning Clerk behavior.
 */
export function MarketingAuthPageShell({
  eyebrow,
  title,
  lede,
  proofTitle,
  proofRows,
  contextPanels,
  switchNote,
  children,
}: {
  eyebrow: string;
  title: string;
  lede: string;
  proofTitle: string;
  proofRows: AuthProofRow[];
  contextPanels: AuthContextPanel[];
  switchNote: ReactNode;
  children: ReactNode;
}) {
  return (
    <main className="lp-auth">
      <div className="lp-shell">
        <div className="lp-auth-grid">
          <section className="lp-auth-copy">
            <div className="lp-auth-intro">
              <span className="lp-eyebrow lp-fade-up">{eyebrow}</span>
              <h1 className="lp-h-section lp-fade-up" style={delay(100)}>
                {title}
              </h1>
              <p className="lp-lede lp-fade-up" style={delay(200)}>
                {lede}
              </p>
            </div>

            <div className="lp-auth-proof lp-fade-up" style={delay(300)}>
              <h2 className="lp-auth-panel-title">{proofTitle}</h2>
              <div className="lp-auth-proof-list">
                {proofRows.map((row) => (
                  <div className="lp-auth-proof-row" key={row.label}>
                    <span className="lp-auth-dot" aria-hidden="true" />
                    <span>{row.text}</span>
                    <b>{row.label}</b>
                  </div>
                ))}
              </div>
            </div>

            <div className="lp-auth-context lp-fade-up" style={delay(380)}>
              {contextPanels.map((panel) => (
                <div className="lp-auth-mini" key={panel.title}>
                  <h3 className="lp-auth-panel-title">{panel.title}</h3>
                  <p>{panel.body}</p>
                </div>
              ))}
            </div>

            <p className="lp-auth-switch lp-fade-up" style={delay(460)}>
              {switchNote}
            </p>
          </section>

          <div className="lp-auth-card lp-fade-spring" style={delay(180)}>
            {children}
          </div>
        </div>
      </div>
    </main>
  );
}

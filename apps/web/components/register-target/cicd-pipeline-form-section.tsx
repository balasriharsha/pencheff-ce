"use client";

import { Input, Label } from "@/components/brutal";

export type CicdProvider = "github_actions" | "gitlab_ci" | "jenkins" | "azure_pipelines" | "circleci";

export type CicdPipelineConfig = {
  kind: "cicd_pipeline";
  provider: CicdProvider;
  repo_url?: string;
  config_paths: string[];
  live_api_enabled: boolean;
};

export const DEFAULT_CICD_PIPELINE_CONFIG: CicdPipelineConfig = {
  kind: "cicd_pipeline",
  provider: "github_actions",
  repo_url: "",
  config_paths: [],
  live_api_enabled: false,
};

const PROVIDERS: Array<{ id: CicdProvider; label: string; default_paths: string }> = [
  { id: "github_actions", label: "GitHub Actions", default_paths: ".github/workflows/*.yml" },
  { id: "gitlab_ci",      label: "GitLab CI",       default_paths: ".gitlab-ci.yml" },
  { id: "jenkins",        label: "Jenkins",         default_paths: "Jenkinsfile, .jenkins/*.groovy" },
  { id: "azure_pipelines", label: "Azure Pipelines", default_paths: "azure-pipelines.yml" },
  { id: "circleci",       label: "CircleCI",        default_paths: ".circleci/config.yml" },
];

export function CicdPipelineFormSection({
  value,
  onChange,
  name,
  setName,
  rawConfigPaths,
  setRawConfigPaths,
}: {
  value: CicdPipelineConfig;
  onChange: (v: CicdPipelineConfig) => void;
  name: string;
  setName: (v: string) => void;
  rawConfigPaths: string;
  setRawConfigPaths: (v: string) => void;
}) {
  function onPathsChange(raw: string) {
    setRawConfigPaths(raw);
    const paths = raw.split(/[,\n]/).map((p) => p.trim()).filter(Boolean);
    onChange({ ...value, config_paths: paths });
  }

  const providerHint = PROVIDERS.find((p) => p.id === value.provider);

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">CP1</span>
          <h2 className="font-display text-[18px] text-ink">CI/CD Pipeline</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="prod-api GitHub Actions" />
          </div>
          <div className="md:col-span-2">
            <Label>Repository URL</Label>
            <Input
              type="url"
              placeholder="https://github.com/org/repo"
              value={value.repo_url ?? ""}
              onChange={(e) => onChange({ ...value, repo_url: e.target.value })}
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              The scanner clones this repo and audits the workflow / pipeline configs.
            </p>
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">CP2</span>
          <h2 className="font-display text-[18px] text-ink">Provider</h2>
        </div>
        <div className="grid sm:grid-cols-2 gap-2" role="radiogroup" aria-label="CI provider">
          {PROVIDERS.map((p) => {
            const active = value.provider === p.id;
            return (
              <button
                key={p.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onChange({ ...value, provider: p.id })}
                className={
                  "text-left border rounded-sm p-3 transition-colors " +
                  (active ? "border-ink bg-vellum" : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">{p.label}</span>
                <span className="mt-0.5 block font-mono text-[10px] text-mist">{p.default_paths}</span>
              </button>
            );
          })}
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="eyebrow-gilt">CP3</span>
          <h2 className="font-display text-[18px] text-ink">Config paths (optional)</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-3">
          One path per line. Auto-detected from the provider above when empty (default: <code>{providerHint?.default_paths}</code>).
        </p>
        <textarea
          rows={4}
          value={rawConfigPaths}
          onChange={(e) => onPathsChange(e.target.value)}
          placeholder=".github/workflows/deploy.yml&#10;.github/workflows/test.yml"
          className="w-full font-mono text-[12px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
        />
      </section>

      <hr className="rule" />

      <section>
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={value.live_api_enabled}
            onChange={(e) => onChange({ ...value, live_api_enabled: e.target.checked })}
            className="mt-1 w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span>
            <span className="block font-body text-[13px] text-ink">Enable Phase B live-API probing</span>
            <span className="block font-mono text-[11px] text-mist mt-0.5">
              When on, the scan also queries the provider API (GitHub Actions / GitLab CI / Jenkins REST)
              to enumerate workflows, secrets, deploy keys, runner pools. Requires a provider token —
              register via <code>POST /targets</code> with <code>kind_credentials</code>.
            </span>
          </span>
        </label>
      </section>
    </>
  );
}

"use client";

import { Input, Label } from "@/components/brutal";
import {
  AdvancedSection,
  FieldHint,
  HeaderRowsEditor,
  SectionIntro,
} from "./form-helpers";

type McpSourceType = "mcp_http" | "mcp_stdio" | "agent_http" | "agent_browser";
type Transport = "sse" | "streamable_http";
type LlmProvider =
  | "openai-chat"
  | "custom"
  | "executable"
  | "websocket"
  | "bedrock"
  | "vertex"
  | "azure-openai"
  | "browser";

type EnvRow = { key: string; value: string };
type HeaderRow = { key: string; value: string };

const SOURCE_TYPE_OPTIONS: {
  value: McpSourceType;
  label: string;
  help: string;
}[] = [
  {
    value: "mcp_http",
    label: "Remote MCP server",
    help: "Use this when you have an HTTPS/SSE MCP URL.",
  },
  {
    value: "mcp_stdio",
    label: "Local MCP command",
    help: "Use this when the scanner launches the MCP server with a command.",
  },
  {
    value: "agent_http",
    label: "Agent adapter",
    help: "Use this for an OpenAI-compatible agent adapter already wired to the scanner.",
  },
  {
    value: "agent_browser",
    label: "Agent web UI",
    help: "Use this when the agent is only available through a browser page.",
  },
];

const PROVIDER_OPTIONS: { value: LlmProvider; label: string }[] = [
  { value: "openai-chat", label: "OpenAI-compatible" },
  { value: "bedrock", label: "AWS Bedrock" },
  { value: "vertex", label: "Google Vertex AI" },
  { value: "azure-openai", label: "Azure OpenAI" },
  { value: "custom", label: "Custom template" },
  { value: "websocket", label: "WebSocket" },
  { value: "executable", label: "Executable" },
];

export function McpFormSection({
  name,
  setName,
  sourceType,
  setSourceType,
  url,
  setUrl,
  transport,
  setTransport,
  command,
  setCommand,
  cwd,
  setCwd,
  envRows,
  setEnvRows,
  provider,
  setProvider,
  model,
  setModel,
  requestTemplate,
  setRequestTemplate,
  responsePath,
  setResponsePath,
  promptSelector,
  setPromptSelector,
  sendSelector,
  setSendSelector,
  responseSelector,
  setResponseSelector,
  toolAllowlist,
  setToolAllowlist,
  toolDenylist,
  setToolDenylist,
  dynamicInvocation,
  setDynamicInvocation,
  destructiveOptIn,
  setDestructiveOptIn,
  headerRows,
  setHeaderRows,
}: {
  name: string;
  setName: (v: string) => void;
  sourceType: McpSourceType;
  setSourceType: (v: McpSourceType) => void;
  url: string;
  setUrl: (v: string) => void;
  transport: Transport;
  setTransport: (v: Transport) => void;
  command: string;
  setCommand: (v: string) => void;
  cwd: string;
  setCwd: (v: string) => void;
  envRows: EnvRow[];
  setEnvRows: (v: EnvRow[]) => void;
  provider: string;
  setProvider: (v: string) => void;
  model: string;
  setModel: (v: string) => void;
  requestTemplate: string;
  setRequestTemplate: (v: string) => void;
  responsePath: string;
  setResponsePath: (v: string) => void;
  promptSelector: string;
  setPromptSelector: (v: string) => void;
  sendSelector: string;
  setSendSelector: (v: string) => void;
  responseSelector: string;
  setResponseSelector: (v: string) => void;
  toolAllowlist: string;
  setToolAllowlist: (v: string) => void;
  toolDenylist: string;
  setToolDenylist: (v: string) => void;
  dynamicInvocation: boolean;
  setDynamicInvocation: (v: boolean) => void;
  destructiveOptIn: boolean;
  setDestructiveOptIn: (v: boolean) => void;
  headerRows: HeaderRow[];
  setHeaderRows: (v: HeaderRow[]) => void;
}) {
  const selectedSource = SOURCE_TYPE_OPTIONS.find(
    (option) => option.value === sourceType,
  );

  return (
    <div className="space-y-8">
      <section>
        <SectionIntro
          eyebrow="MCP / AI Agents"
          title="Choose the way Pencheff reaches your agent"
          description="Start with the connection type you already have. Most hosted MCP servers only need a URL and an optional token."
        />
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <Label>Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Production support agent"
            />
          </div>
          <div>
            <Label>What are you testing?</Label>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value as McpSourceType)}
              className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
            >
              {SOURCE_TYPE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            {selectedSource && <FieldHint>{selectedSource.help}</FieldHint>}
          </div>

          {sourceType === "mcp_http" && (
            <>
              <div className="md:col-span-2">
                <Label>MCP server URL</Label>
                <Input
                  type="url"
                  required
                  placeholder="https://mcp.example.com/sse"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="font-mono text-[13px]"
                />
              </div>
              <div>
                <Label>Transport</Label>
                <select
                  value={transport}
                  onChange={(e) => setTransport(e.target.value as Transport)}
                  className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
                >
                  <option value="sse">SSE</option>
                  <option value="streamable_http">Streamable HTTP</option>
                </select>
              </div>
            </>
          )}

          {sourceType === "mcp_stdio" && (
            <div className="md:col-span-2">
              <Label>Command to start the MCP server</Label>
              <textarea
                required
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                placeholder={"npx some-mcp-server\n--arg\nvalue"}
                rows={3}
                className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
              />
              <FieldHint>One command token per line is easiest to review.</FieldHint>
            </div>
          )}

          {sourceType === "agent_http" && (
            <>
              <div>
                <Label>Agent provider</Label>
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
                >
                  {PROVIDER_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <Label>Model</Label>
                <Input
                  list="mcp-model-presets"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder="gpt-4o-mini"
                  className="font-mono text-[13px]"
                />
                <datalist id="mcp-model-presets">
                  <option value="gpt-4o-mini" />
                  <option value="gpt-4.1-mini" />
                  <option value="claude-3-5-sonnet" />
                  <option value="llama-3.1-70b-instruct" />
                </datalist>
              </div>
            </>
          )}

          {sourceType === "agent_browser" && (
            <>
              <div className="md:col-span-2">
                <Label>Agent page URL</Label>
                <Input
                  type="url"
                  required
                  placeholder="https://chat.example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="font-mono text-[13px]"
                />
              </div>
              <div>
                <Label>Prompt input selector</Label>
                <Input
                  value={promptSelector}
                  onChange={(e) => setPromptSelector(e.target.value)}
                  placeholder="textarea#prompt-input"
                  className="font-mono text-[13px]"
                />
              </div>
              <div>
                <Label>Send button selector</Label>
                <Input
                  value={sendSelector}
                  onChange={(e) => setSendSelector(e.target.value)}
                  placeholder="button[type=submit]"
                  className="font-mono text-[13px]"
                />
              </div>
              <div className="md:col-span-2">
                <Label>Response selector</Label>
                <Input
                  value={responseSelector}
                  onChange={(e) => setResponseSelector(e.target.value)}
                  placeholder=".message-bubble:last-child"
                  className="font-mono text-[13px]"
                />
              </div>
            </>
          )}
        </div>
      </section>

      <section>
        <SectionIntro
          title="Authentication"
          description="Add a bearer token or API key only if this MCP server or agent needs one."
        />
        <HeaderRowsEditor rows={headerRows} setRows={setHeaderRows} />
      </section>

      <AdvancedSection
        title="Advanced MCP and agent settings"
        description="Use these for custom agent payloads, local command environment, or live tool-invocation tests."
      >
        {sourceType === "mcp_stdio" && (
          <div className="grid gap-5">
            <div>
              <Label>Working directory</Label>
              <Input
                value={cwd}
                onChange={(e) => setCwd(e.target.value)}
                placeholder="/home/user/my-mcp-project"
                className="font-mono text-[13px]"
              />
            </div>
            <div>
              <p className="mb-3 font-display text-[14px] text-ink">
                Environment variables (non-secret)
              </p>
              <div className="space-y-3">
                {envRows.map((row, idx) => (
                  <div
                    key={idx}
                    className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto] sm:items-end"
                  >
                    <div>
                      {idx === 0 && <Label>Name</Label>}
                      <Input
                        value={row.key}
                        placeholder="NODE_ENV"
                        onChange={(e) => {
                          const next = [...envRows];
                          next[idx] = { ...next[idx], key: e.target.value };
                          setEnvRows(next);
                        }}
                        className="font-mono text-[12px]"
                      />
                    </div>
                    <div>
                      {idx === 0 && <Label>Value</Label>}
                      <Input
                        value={row.value}
                        placeholder="production"
                        onChange={(e) => {
                          const next = [...envRows];
                          next[idx] = { ...next[idx], value: e.target.value };
                          setEnvRows(next);
                        }}
                        className="font-mono text-[12px]"
                      />
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        setEnvRows(envRows.filter((_, i) => i !== idx))
                      }
                      className="border border-hairline px-3 py-2 font-mono text-[11px] text-slate hover:border-ink hover:text-ink"
                    >
                      x
                    </button>
                  </div>
                ))}
                <button
                  type="button"
                  onClick={() =>
                    setEnvRows([...envRows, { key: "", value: "" }])
                  }
                  className="border border-dashed border-hairline px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-slate hover:border-ink hover:text-ink"
                >
                  + Add variable
                </button>
              </div>
            </div>
          </div>
        )}

        {sourceType === "agent_http" && provider === "custom" && (
          <div className="grid gap-5 md:grid-cols-2">
            <div>
              <Label>Request body template (JSON)</Label>
              <textarea
                required
                value={requestTemplate}
                onChange={(e) => setRequestTemplate(e.target.value)}
                rows={4}
                className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
              />
            </div>
            <div>
              <Label>Response JSONPath</Label>
              <Input
                required
                value={responsePath}
                onChange={(e) => setResponsePath(e.target.value)}
                placeholder="$.choices[0].message.content"
                className="font-mono text-[13px]"
              />
            </div>
          </div>
        )}

        <div>
          <h3 className="mb-4 font-display text-[16px] text-ink">
            Dynamic tool testing
          </h3>
          <div className="grid gap-5">
            <label className="inline-flex items-center gap-2 text-[13px] text-graphite">
              <input
                type="checkbox"
                checked={dynamicInvocation}
                onChange={(e) => {
                  const next = e.target.checked;
                  setDynamicInvocation(next);
                  if (!next) setDestructiveOptIn(false);
                }}
              />
              Invoke tools dynamically (read-only probes)
            </label>

            {dynamicInvocation && (
              <>
                <div>
                  <Label>Tool allowlist</Label>
                  <textarea
                    value={toolAllowlist}
                    onChange={(e) => setToolAllowlist(e.target.value)}
                    placeholder={"read_file,list_directory\nget_schema"}
                    rows={3}
                    className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
                  />
                </div>
                <div>
                  <Label>Tool denylist</Label>
                  <textarea
                    value={toolDenylist}
                    onChange={(e) => setToolDenylist(e.target.value)}
                    placeholder={"delete_file,drop_table\nexec_command"}
                    rows={3}
                    className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
                  />
                </div>
                <div>
                  <label className="inline-flex items-center gap-2 text-[13px] text-graphite">
                    <input
                      type="checkbox"
                      checked={destructiveOptIn}
                      disabled={!dynamicInvocation}
                      onChange={(e) => setDestructiveOptIn(e.target.checked)}
                    />
                    Allow destructive tool invocation
                  </label>
                  <FieldHint>
                    Destructive probing can modify or delete data. Enable only
                    for a sandbox target you own.
                  </FieldHint>
                </div>
              </>
            )}
          </div>
        </div>
      </AdvancedSection>
    </div>
  );
}

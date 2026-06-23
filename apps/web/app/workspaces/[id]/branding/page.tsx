"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Button } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { api } from "@/lib/api";

type Branding = {
  workspace_id: string;
  logo_url: string | null;
  primary_color: string | null;
  secondary_color: string | null;
  opening_letter_md: string | null;
  methodology_md: string | null;
  footer_text: string | null;
};

export default function BrandingPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const id = mounted ? pathSegment(pathname, 2) : "";
  const [b, setB] = useState<Branding | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!id) return;
    api<Branding | null>(`/workspaces/${id}/branding`).then((r) =>
      setB(
        r || {
          workspace_id: id,
          logo_url: null,
          primary_color: null,
          secondary_color: null,
          opening_letter_md: null,
          methodology_md: null,
          footer_text: null,
        },
      ),
    );
  }, [id]);

  async function save() {
    if (!b) return;
    await api(`/workspaces/${id}/branding`, { method: "PUT", json: b });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  if (!b) {
    return (
      <div className="py-6">
        <InlineLoading label="Loading…" />
      </div>
    );
  }

  return (
    <div className="max-w-[900px] mx-auto space-y-4">
      <h1 className="text-2xl font-black uppercase">Workspace branding</h1>
      <p className="text-graphite text-sm">
        Applied automatically to all reports generated from engagements in this
        workspace.
      </p>
      <label className="block">
        <span className="block uppercase text-xs font-bold mb-1">Logo URL</span>
        <input
          value={b.logo_url || ""}
          onChange={(e) => setB({ ...b, logo_url: e.target.value })}
          className="w-full border-2 border-ink px-3 py-1.5"
        />
      </label>
      <div className="grid grid-cols-2 gap-3">
        <label className="block">
          <span className="block uppercase text-xs font-bold mb-1">
            Primary color (hex)
          </span>
          <input
            value={b.primary_color || ""}
            onChange={(e) => setB({ ...b, primary_color: e.target.value })}
            placeholder="#1a73e8"
            className="w-full border-2 border-ink px-3 py-1.5"
          />
        </label>
        <label className="block">
          <span className="block uppercase text-xs font-bold mb-1">
            Secondary color (hex)
          </span>
          <input
            value={b.secondary_color || ""}
            onChange={(e) => setB({ ...b, secondary_color: e.target.value })}
            placeholder="#0b1d3a"
            className="w-full border-2 border-ink px-3 py-1.5"
          />
        </label>
      </div>
      <label className="block">
        <span className="block uppercase text-xs font-bold mb-1">
          Opening letter (markdown)
        </span>
        <textarea
          rows={5}
          value={b.opening_letter_md || ""}
          onChange={(e) => setB({ ...b, opening_letter_md: e.target.value })}
          className="w-full border-2 border-ink px-3 py-1.5 font-mono text-sm"
        />
      </label>
      <label className="block">
        <span className="block uppercase text-xs font-bold mb-1">
          Methodology (markdown)
        </span>
        <textarea
          rows={6}
          value={b.methodology_md || ""}
          onChange={(e) => setB({ ...b, methodology_md: e.target.value })}
          className="w-full border-2 border-ink px-3 py-1.5 font-mono text-sm"
        />
      </label>
      <label className="block">
        <span className="block uppercase text-xs font-bold mb-1">
          Footer text
        </span>
        <input
          value={b.footer_text || ""}
          onChange={(e) => setB({ ...b, footer_text: e.target.value })}
          className="w-full border-2 border-ink px-3 py-1.5"
        />
      </label>
      <div className="flex gap-3 items-center">
        <Button variant="lime" onClick={save}>
          Save
        </Button>
        {saved && <span className="text-sm text-sev-low">Saved.</span>}
      </div>
    </div>
  );
}

"use client"

/** CBOM (CycloneDX 1.6), SARIF 2.1.0, CSV, roadmap and CI-gate exports. */

import { useMemo, useState } from "react"
import { Check, Copy, Download, FileJson, FileSpreadsheet, ShieldCheck, Workflow } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { TIERS } from "@/components/ecdat/tier"
import { cn } from "@/lib/utils"
import { buildCbom } from "@/lib/ecdat/export/cbom"
import { buildSarif, githubActionWorkflow } from "@/lib/ecdat/export/sarif"
import { roadmapToMarkdown, type RoadmapItem } from "@/lib/ecdat/roadmap"
import type { CryptoAsset, RiskTier, ScanResult } from "@/lib/ecdat/types"

function saveFile(name: string, content: string, type: string) {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = name
  anchor.click()
  URL.revokeObjectURL(url)
}

function toCsv(assets: CryptoAsset[]): string {
  const header = [
    "risk_tier",
    "algorithm",
    "family",
    "primitive",
    "mode",
    "key_size",
    "file",
    "line",
    "occurrences",
    "language",
    "evidence",
    "confidence",
    "quantum_vulnerable",
    "classically_broken",
    "nist_status",
    "business_criticality",
    "sensitive_data",
    "facing",
    "system",
    "mosca_x",
    "mosca_y",
    "mosca_z",
    "mosca_margin",
    "recommendation",
    "standard",
  ]
  const escape = (value: unknown) => {
    const text = value === undefined || value === null ? "" : String(value)
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }
  const rows = assets.map((a) =>
    [
      a.riskTier,
      a.name,
      a.family,
      a.primitive,
      a.mode,
      a.keySize ?? "",
      a.file,
      a.line,
      a.occurrences,
      a.language,
      a.evidence,
      a.confidence,
      a.quantumVulnerable,
      a.classicallyBroken,
      a.nistStatus,
      a.classification.businessCriticality,
      a.classification.sensitiveData,
      a.classification.facing,
      a.systemKey,
      a.mosca.x,
      a.mosca.y,
      a.mosca.z,
      a.mosca.margin,
      a.recommendation?.primary ?? "",
      a.recommendation?.standard ?? "",
    ]
      .map(escape)
      .join(","),
  )
  return [header.join(","), ...rows].join("\n")
}

export function ExportPanel({
  scan,
  assets,
  roadmap,
}: {
  scan: ScanResult
  assets: CryptoAsset[]
  roadmap: RoadmapItem[]
}) {
  const [threshold, setThreshold] = useState<RiskTier>("High")
  const [copied, setCopied] = useState<string | null>(null)

  // Exports must reflect the *current* slider-adjusted scoring, not the raw scan.
  const scoped: ScanResult = useMemo(() => ({ ...scan, assets }), [scan, assets])

  const cbom = useMemo(() => JSON.stringify(buildCbom(scoped), null, 2), [scoped])
  const sarif = useMemo(() => JSON.stringify(buildSarif(scoped), null, 2), [scoped])
  const workflow = useMemo(() => githubActionWorkflow(threshold), [threshold])
  const stamp = scan.startedAt.slice(0, 10)

  async function copy(key: string, text: string) {
    await navigator.clipboard.writeText(text)
    setCopied(key)
    window.setTimeout(() => setCopied((current) => (current === key ? null : current)), 1600)
  }

  const artifacts = [
    {
      key: "cbom",
      icon: FileJson,
      title: "CBOM — CycloneDX 1.6",
      description:
        "ECMA-424 cryptographic bill of materials with cryptoProperties, occurrence evidence and PQC recommendations. Ingests into any CycloneDX-aware tool.",
      filename: `ecdat-cbom-${stamp}.cdx.json`,
      content: cbom,
      type: "application/json",
      meta: `${assets.length} components · ${(cbom.length / 1024).toFixed(1)} KB`,
    },
    {
      key: "sarif",
      icon: ShieldCheck,
      title: "SARIF 2.1.0",
      description:
        "Static-analysis results with security-severity ranks. Upload to GitHub code scanning and findings appear inline on the pull-request diff.",
      filename: `ecdat-findings-${stamp}.sarif`,
      content: sarif,
      type: "application/sarif+json",
      meta: `${assets.reduce((sum, a) => sum + a.locations.length, 0)} results · ${(sarif.length / 1024).toFixed(1)} KB`,
    },
    {
      key: "csv",
      icon: FileSpreadsheet,
      title: "Inventory CSV",
      description:
        "Flat one-row-per-asset export including the full Mosca arithmetic, for spreadsheets and GRC tooling.",
      filename: `ecdat-inventory-${stamp}.csv`,
      content: toCsv(assets),
      type: "text/csv",
      meta: `${assets.length} rows · 25 columns`,
    },
    {
      key: "roadmap",
      icon: Workflow,
      title: "Migration roadmap (Markdown)",
      description:
        "Wave-ordered remediation plan with effort estimates and per-item steps, ready to paste into a ticket or a board paper.",
      filename: `ecdat-roadmap-${stamp}.md`,
      content: roadmapToMarkdown(roadmap, scan.source.label),
      type: "text/markdown",
      meta: `${roadmap.length} work items`,
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Export artifacts</CardTitle>
          <CardDescription>
            Every export reflects the current Mosca assumptions, so a slider change is carried into the CBOM and the CI gate.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2">
          {artifacts.map((artifact) => {
            const Icon = artifact.icon
            return (
              <div
                key={artifact.key}
                className="flex flex-col gap-3 rounded-md border border-border bg-secondary/25 p-3"
              >
                <div className="flex items-start gap-2.5">
                  <Icon className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
                  <div className="flex min-w-0 flex-col gap-1">
                    <span className="text-sm font-medium text-foreground">{artifact.title}</span>
                    <span className="font-mono text-[11px] text-muted-foreground">{artifact.meta}</span>
                  </div>
                </div>
                <p className="flex-1 text-xs leading-relaxed text-muted-foreground">{artifact.description}</p>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    className="flex-1"
                    onClick={() => saveFile(artifact.filename, artifact.content, artifact.type)}
                  >
                    <Download data-icon="inline-start" />
                    Download
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => copy(artifact.key, artifact.content)}
                    aria-label={`Copy ${artifact.title}`}
                  >
                    {copied === artifact.key ? <Check /> : <Copy />}
                  </Button>
                </div>
                <span className="truncate font-mono text-[10px] text-muted-foreground">{artifact.filename}</span>
              </div>
            )
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex flex-col gap-1.5">
              <CardTitle>CI/CD gate</CardTitle>
              <CardDescription>
                Drop this workflow in to fail any pull request that introduces new quantum-vulnerable cryptography.
              </CardDescription>
            </div>
            <div className="flex items-center gap-1">
              <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Fail on</span>
              {TIERS.map((tier) => (
                <button
                  key={tier}
                  type="button"
                  onClick={() => setThreshold(tier)}
                  aria-pressed={threshold === tier}
                  className={cn(
                    "rounded-sm border px-2 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors",
                    threshold === tier
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground",
                  )}
                >
                  {tier}
                </button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <pre className="max-h-[380px] overflow-auto rounded-md border border-border bg-secondary/40 p-3 font-mono text-[11px] leading-relaxed text-foreground">
            <code>{workflow}</code>
          </pre>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => saveFile("ecdat-pqc-gate.yml", workflow, "text/yaml")}
            >
              <Download data-icon="inline-start" />
              Download workflow
            </Button>
            <Button size="sm" variant="ghost" onClick={() => copy("workflow", workflow)}>
              {copied === "workflow" ? <Check data-icon="inline-start" /> : <Copy data-icon="inline-start" />}
              {copied === "workflow" ? "Copied" : "Copy YAML"}
            </Button>
            <span className="font-mono text-[11px] text-muted-foreground">
              Calls <span className="text-foreground">POST /api/scan/ci</span> and returns SARIF directly.
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

"use client"

/** Prioritised PQC migration roadmap with a fully disclosed effort model. */

import { useState } from "react"
import { ChevronDown, Download } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { TIER_STYLES, TierChip } from "@/components/ecdat/tier"
import { cn } from "@/lib/utils"
import { WAVE_ORDER, roadmapToMarkdown, type RoadmapItem, type Wave } from "@/lib/ecdat/roadmap"

const WAVE_TONE: Record<Wave, string> = {
  "Wave 1 — Immediate (0-6 months)": "text-critical",
  "Wave 2 — Near term (6-18 months)": "text-high",
  "Wave 3 — Planned (18-36 months)": "text-medium",
  "Wave 4 — Monitor": "text-low",
}

function download(name: string, content: string, type: string) {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = name
  anchor.click()
  URL.revokeObjectURL(url)
}

function ItemCard({ item }: { item: RoadmapItem }) {
  const [open, setOpen] = useState(false)
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div
        className={cn(
          "rounded-md border bg-secondary/25 transition-colors",
          open ? "border-primary/40" : "border-border hover:border-primary/25",
        )}
      >
        <CollapsibleTrigger
          render={
            <button
              type="button"
              className="flex w-full flex-col gap-2 p-3 text-left sm:flex-row sm:items-center sm:justify-between"
            />
          }
        >
          <div className="flex min-w-0 flex-col gap-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <TierChip tier={item.riskTier} />
              <span className="font-mono text-sm font-medium text-foreground">{item.algorithm}</span>
              <span className="font-mono text-[11px] text-muted-foreground">→</span>
              <span className="font-mono text-xs text-primary">{item.target}</span>
            </div>
            <span className="truncate font-mono text-[11px] text-muted-foreground">
              {item.files.length} file{item.files.length === 1 ? "" : "s"} · {item.occurrences} occurrence
              {item.occurrences === 1 ? "" : "s"} · {item.standard}
            </span>
          </div>
          <div className="flex shrink-0 items-center gap-4">
            <div className="flex flex-col items-end">
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Effort</span>
              <span className="tabular font-mono text-sm text-foreground">{item.effortDays}d</span>
            </div>
            <ChevronDown
              className={cn("size-4 text-muted-foreground transition-transform", open && "rotate-180")}
              aria-hidden="true"
            />
          </div>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="flex flex-col gap-4 border-t border-border p-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1">
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Why now</span>
                <p className="text-xs leading-relaxed text-muted-foreground">{item.rationale}</p>
              </div>
              <div className="flex flex-col gap-1">
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Affected files</span>
                <ul className="flex flex-col gap-0.5">
                  {item.files.slice(0, 6).map((file) => (
                    <li key={file} className="font-mono text-[11px] text-foreground">
                      {file}
                    </li>
                  ))}
                  {item.files.length > 6 ? (
                    <li className="font-mono text-[11px] text-muted-foreground">+{item.files.length - 6} more</li>
                  ) : null}
                </ul>
              </div>
            </div>
            {item.hybrid ? (
              <p className="rounded-sm border border-primary/25 bg-primary/5 px-3 py-2 font-mono text-[11px] text-foreground">
                Hybrid transition option: {item.hybrid}
              </p>
            ) : null}
            <div className="flex flex-col gap-1.5">
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Steps</span>
              <ol className="flex flex-col gap-1.5">
                {item.actions.map((action, index) => (
                  <li key={action} className="flex gap-2.5 text-xs leading-relaxed text-foreground">
                    <span className="tabular shrink-0 font-mono text-[11px] text-primary">{index + 1}.</span>
                    {action}
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  )
}

export function RoadmapPanel({
  items,
  totals,
  label,
}: {
  items: RoadmapItem[]
  totals: { byWave: Map<Wave, { items: number; days: number }>; totalDays: number; totalItems: number }
  label: string
}) {
  if (!items.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Migration roadmap</CardTitle>
        </CardHeader>
        <CardContent>
          <Empty className="border border-dashed border-border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Download />
              </EmptyMedia>
              <EmptyTitle>Nothing to migrate</EmptyTitle>
              <EmptyDescription>
                No quantum-vulnerable or classically broken cryptography was found in the scanned scope.
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex flex-col gap-1.5">
              <CardTitle>Migration roadmap</CardTitle>
              <CardDescription>
                {totals.totalItems} work items · {totals.totalDays} engineer-days of engineering effort.
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                download(`ecdat-roadmap-${Date.now()}.md`, roadmapToMarkdown(items, label), "text/markdown")
              }
            >
              <Download data-icon="inline-start" />
              Export Markdown
            </Button>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {WAVE_ORDER.map((wave) => {
              const bucket = totals.byWave.get(wave)
              if (!bucket) return null
              return (
                <div key={wave} className="flex flex-col gap-1 rounded-md border border-border bg-secondary/30 p-3">
                  <span className={cn("font-mono text-[10px] uppercase tracking-widest", WAVE_TONE[wave])}>
                    {wave.split("—")[0].trim()}
                  </span>
                  <span className="text-[11px] leading-tight text-muted-foreground">
                    {wave.split("—")[1]?.replace(/[()]/g, "").trim()}
                  </span>
                  <span className="tabular mt-1 text-xl font-semibold leading-none text-foreground">{bucket.items}</span>
                  <span className="tabular font-mono text-[11px] text-muted-foreground">
                    {Math.round(bucket.days * 10) / 10}d effort
                  </span>
                </div>
              )
            })}
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            Effort model: base days per evidence type × log-scaled file count × algorithm complexity × business criticality. Every
            multiplier lives in <span className="font-mono text-foreground">lib/ecdat/roadmap.ts</span> — these are planning
            inputs, not quotes.
          </p>
        </CardContent>
      </Card>

      {WAVE_ORDER.map((wave) => {
        const waveItems = items.filter((item) => item.wave === wave)
        if (!waveItems.length) return null
        return (
          <Card key={wave}>
            <CardHeader>
              <CardTitle className={cn("font-mono text-sm", WAVE_TONE[wave])}>{wave}</CardTitle>
              <CardDescription>
                {waveItems.length} item{waveItems.length === 1 ? "" : "s"} ·{" "}
                {Math.round(waveItems.reduce((sum, i) => sum + i.effortDays, 0) * 10) / 10} engineer-days
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              {waveItems.map((item) => (
                <ItemCard key={item.key} item={item} />
              ))}
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}

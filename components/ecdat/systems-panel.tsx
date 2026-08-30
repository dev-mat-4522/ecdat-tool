"use client"

/**
 * F6 / U4 — application- and system-level risk rollup.
 *
 * The inventory answers "which line is a problem"; this view answers "which of
 * my systems is a problem". It is pure presentation over `derived.systems`
 * (built in `lib/ecdat/systems.ts`) — no new detection or scoring happens here.
 */

import { useState } from "react"
import { ChevronDown, Layers } from "lucide-react"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { TIER_STYLES, TIERS, TierChip, TypeBadge } from "@/components/ecdat/tier"
import { cn } from "@/lib/utils"
import type { CryptoAsset, SystemRollup } from "@/lib/ecdat/types"

function StatBlock({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</span>
      <span className="tabular text-2xl font-semibold leading-none text-foreground">{value}</span>
      {hint ? <span className="text-xs leading-relaxed text-muted-foreground">{hint}</span> : null}
    </div>
  )
}

export function SystemsPanel({
  systems,
  totals,
  onInspect,
}: {
  systems: SystemRollup[]
  totals: {
    systems: number
    counts: Record<string, number>
    external: number
    sensitive: number
    worstReadiness: number
  }
  onInspect: (asset: CryptoAsset) => void
}) {
  const [open, setOpen] = useState<string | null>(systems[0]?.key ?? null)

  if (!systems.length) {
    return (
      <Empty className="border border-dashed border-border">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <Layers />
          </EmptyMedia>
          <EmptyTitle>No systems to roll up</EmptyTitle>
          <EmptyDescription>Run a scan to group discovered crypto by application.</EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent className="grid grid-cols-2 gap-6 lg:grid-cols-4">
          <StatBlock label="Systems" value={String(totals.systems)} hint="Grouped by top-level path" />
          <StatBlock label="External-facing" value={String(totals.external)} hint="Reachable from outside" />
          <StatBlock label="Handle sensitive data" value={String(totals.sensitive)} hint="PII / payment / health" />
          <StatBlock label="Worst readiness" value={String(totals.worstReadiness)} hint="Lowest system score" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Systems by risk</CardTitle>
          <CardDescription>
            Each system takes the worst tier inside it. Expand a row to see the assets driving that rollup.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {systems.map((system) => {
            const expanded = open === system.key
            return (
              <div key={system.key} className="overflow-hidden rounded-md border border-border">
                <button
                  type="button"
                  onClick={() => setOpen((current) => (current === system.key ? null : system.key))}
                  aria-expanded={expanded}
                  className="flex w-full items-center gap-3 bg-secondary/30 px-3 py-2.5 text-left transition-colors hover:bg-accent/40"
                >
                  <TierChip tier={system.tier} />
                  <div className="flex min-w-0 flex-1 flex-col gap-1">
                    <span className="truncate font-mono text-sm font-medium text-foreground">{system.name}</span>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {system.types.map((type) => (
                        <TypeBadge key={type} type={type} />
                      ))}
                      <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                        {system.facing}
                      </span>
                      {system.sensitiveData > 0 ? (
                        <span className="font-mono text-[10px] uppercase tracking-wider text-amber-400/90">
                          sensitive ×{system.sensitiveData}
                        </span>
                      ) : null}
                    </div>
                  </div>
                  <div className="hidden shrink-0 items-center gap-4 sm:flex">
                    <div className="flex flex-col items-end">
                      <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Assets</span>
                      <span className="tabular font-mono text-sm text-foreground">{system.assets}</span>
                    </div>
                    <div className="flex flex-col items-end">
                      <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">QV</span>
                      <span className="tabular font-mono text-sm text-foreground">{system.quantumVulnerable}</span>
                    </div>
                    <div className="flex flex-col items-end">
                      <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Readiness</span>
                      <span className={cn("tabular font-mono text-sm", TIER_STYLES[system.tier].text)}>
                        {system.readiness}
                      </span>
                    </div>
                  </div>
                  <ChevronDown
                    className={cn("size-4 shrink-0 text-muted-foreground transition-transform", expanded && "rotate-180")}
                    aria-hidden="true"
                  />
                </button>

                {expanded ? (
                  <div className="flex flex-col divide-y divide-border border-t border-border">
                    <div className="flex flex-wrap gap-1 bg-background px-3 py-2">
                      {TIERS.map((tier) =>
                        system.counts[tier] ? (
                          <span
                            key={tier}
                            className={cn(
                              "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
                              TIER_STYLES[tier].chip,
                            )}
                          >
                            {tier} {system.counts[tier]}
                          </span>
                        ) : null,
                      )}
                    </div>
                    {system.members.map((asset) => (
                      <button
                        key={asset.id}
                        type="button"
                        onClick={() => onInspect(asset)}
                        className="flex items-center gap-3 px-3 py-2 text-left transition-colors hover:bg-accent/40"
                      >
                        <TierChip tier={asset.riskTier} />
                        <span className="font-mono text-sm text-foreground">{asset.name}</span>
                        <TypeBadge type={asset.type} />
                        <span className="ml-auto truncate font-mono text-[11px] text-muted-foreground">{asset.location}</span>
                      </button>
                    ))}
                  </div>
                ) : null}
              </div>
            )
          })}
        </CardContent>
      </Card>
    </div>
  )
}

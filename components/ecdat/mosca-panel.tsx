"use client"

/**
 * Interactive Mosca explorer.
 *
 * Z (years to a CRQC) is a forecast, not a measurement, so the honest thing to
 * do is expose it. Moving a slider re-scores the whole inventory in the browser
 * — no rescan — which turns "when do you think the quantum computer arrives?"
 * from an argument into a live sensitivity analysis.
 */

import { useMemo } from "react"
import { RotateCcw } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Slider } from "@/components/ui/slider"
import { Switch } from "@/components/ui/switch"
import { TIER_STYLES, TIERS, TierChip } from "@/components/ecdat/tier"
import { cn } from "@/lib/utils"
import { DEFAULT_MOSCA_PARAMS, MIGRATION_TIME, scoreAssets, tierCounts } from "@/lib/ecdat/risk"
import type { CryptoAsset, MoscaParams, RiskTier } from "@/lib/ecdat/types"

const CRQC_SCENARIOS = [
  { label: "Aggressive", year: 2030, note: "NIST IR 8547 deprecation date" },
  { label: "CNSA 2.0", year: 2033, note: "NSA PQC-exclusive deadline (default)" },
  { label: "Consensus", year: 2035, note: "NIST IR 8547 disallow date" },
  { label: "Conservative", year: 2040, note: "Median expert survey estimate" },
]

function sliderValue(value: number | readonly number[]): number {
  return typeof value === "number" ? value : value[0]
}

export function MoscaPanel({
  assets,
  params,
  setParams,
}: {
  /** Already scored with the current params. */
  assets: CryptoAsset[]
  params: MoscaParams
  setParams: (next: MoscaParams) => void
}) {
  const currentYear = new Date().getFullYear()
  const crqcYear = currentYear + params.z
  const counts = tierCounts(assets)
  const total = assets.length || 1

  // Baseline comparison so the operator can see exactly what their assumption changed.
  const baseline = useMemo(() => tierCounts(scoreAssets(assets, DEFAULT_MOSCA_PARAMS)), [assets])

  const sensitivity = useMemo(() => {
    return [2028, 2030, 2033, 2035, 2038, 2040].map((year) => {
      const scored = scoreAssets(assets, { ...params, z: year - currentYear })
      const c = tierCounts(scored)
      return { year, critical: c.Critical, high: c.High, atRisk: c.Critical + c.High }
    })
  }, [assets, params, currentYear])

  const maxAtRisk = Math.max(1, ...sensitivity.map((s) => s.atRisk))
  const isDefault =
    params.z === DEFAULT_MOSCA_PARAMS.z && params.xMultiplier === 1 && params.yOverride === undefined

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex flex-col gap-1.5">
              <CardTitle>Mosca inequality explorer</CardTitle>
              <CardDescription>
                {"X + Y > Z means the data is already exposed. Adjust the assumptions and the entire inventory re-scores instantly."}
              </CardDescription>
            </div>
            {!isDefault ? (
              <Button variant="outline" size="sm" onClick={() => setParams(DEFAULT_MOSCA_PARAMS)}>
                <RotateCcw data-icon="inline-start" />
                Reset to cited default
              </Button>
            ) : null}
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          <div className="rounded-md border border-border bg-secondary/30 p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                Z — years until a cryptographically relevant quantum computer
              </span>
              <span className="tabular font-mono text-sm text-foreground">
                {params.z}y · CRQC in <span className="text-primary">{crqcYear}</span>
              </span>
            </div>
            <Slider
              className="mt-4"
              value={[params.z]}
              min={1}
              max={30}
              step={1}
              onValueChange={(value) => setParams({ ...params, z: sliderValue(value) })}
              aria-label="Years until a cryptographically relevant quantum computer"
            />
            <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
              {CRQC_SCENARIOS.map((scenario) => {
                const active = crqcYear === scenario.year
                return (
                  <button
                    key={scenario.year}
                    type="button"
                    onClick={() => setParams({ ...params, z: scenario.year - currentYear })}
                    aria-pressed={active}
                    className={cn(
                      "flex flex-col gap-0.5 rounded-sm border px-2 py-1.5 text-left transition-colors",
                      active
                        ? "border-primary/50 bg-primary/10"
                        : "border-border hover:border-primary/30 hover:bg-accent/40",
                    )}
                  >
                    <span className={cn("font-mono text-xs font-medium", active ? "text-primary" : "text-foreground")}>
                      {scenario.year}
                    </span>
                    <span className="text-[11px] leading-tight text-muted-foreground">{scenario.label}</span>
                  </button>
                )
              })}
            </div>
            <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
              {CRQC_SCENARIOS.find((s) => s.year === crqcYear)?.note ??
                "Custom horizon — not tied to a published mandate."}
            </p>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-md border border-border bg-secondary/30 p-4">
              <div className="flex flex-wrap items-baseline justify-between gap-3">
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  X — data shelf-life multiplier
                </span>
                <span className="tabular font-mono text-sm text-foreground">{params.xMultiplier.toFixed(2)}×</span>
              </div>
              <Slider
                className="mt-4"
                value={[params.xMultiplier]}
                min={0.25}
                max={3}
                step={0.05}
                onValueChange={(value) => setParams({ ...params, xMultiplier: sliderValue(value) })}
                aria-label="Data shelf-life multiplier"
              />
              <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
                Scales the per-asset retention estimate inferred from file path and algorithm purpose. Raise it for regulated data
                with statutory retention.
              </p>
            </div>

            <div className="rounded-md border border-border bg-secondary/30 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  Y — override migration time
                </span>
                <Switch
                  checked={params.yOverride !== undefined}
                  onCheckedChange={(checked) => setParams({ ...params, yOverride: checked ? 2 : undefined })}
                  aria-label="Override migration time"
                />
              </div>
              {params.yOverride !== undefined ? (
                <>
                  <div className="mt-3 flex items-baseline justify-between">
                    <span className="text-xs text-muted-foreground">Fixed migration time for every asset</span>
                    <span className="tabular font-mono text-sm text-foreground">{params.yOverride.toFixed(1)}y</span>
                  </div>
                  <Slider
                    className="mt-3"
                    value={[params.yOverride]}
                    min={0}
                    max={12}
                    step={0.5}
                    onValueChange={(value) => setParams({ ...params, yOverride: sliderValue(value) })}
                    aria-label="Fixed migration time in years"
                  />
                </>
              ) : (
                <ul className="mt-3 flex flex-col gap-1">
                  {Object.entries(MIGRATION_TIME).map(([evidence, entry]) => (
                    <li key={evidence} className="flex items-baseline justify-between gap-3">
                      <span className="font-mono text-[11px] text-muted-foreground">{evidence}</span>
                      <span className="tabular font-mono text-[11px] text-foreground">{entry.years}y</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Effect of your assumptions</CardTitle>
            <CardDescription>Current scoring versus the cited CNSA 2.0 default.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {TIERS.map((tier) => {
              const delta = counts[tier] - baseline[tier]
              return (
                <div key={tier} className="flex items-center gap-3">
                  <TierChip tier={tier} className="w-[92px] justify-start" />
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                    <div
                      className={cn("h-full transition-all duration-300", TIER_STYLES[tier].bar)}
                      style={{ width: `${(counts[tier] / total) * 100}%` }}
                    />
                  </div>
                  <span className="tabular w-8 text-right font-mono text-xs text-foreground">{counts[tier]}</span>
                  <span
                    className={cn(
                      "tabular w-10 text-right font-mono text-[11px]",
                      delta > 0 ? "text-critical" : delta < 0 ? "text-low" : "text-muted-foreground",
                    )}
                  >
                    {delta === 0 ? "—" : `${delta > 0 ? "+" : ""}${delta}`}
                  </span>
                </div>
              )
            })}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Sensitivity to the CRQC date</CardTitle>
            <CardDescription>Assets at Critical or High risk under each published horizon.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2.5">
            {sensitivity.map((row) => {
              const active = row.year === crqcYear
              return (
                <button
                  key={row.year}
                  type="button"
                  onClick={() => setParams({ ...params, z: row.year - currentYear })}
                  className={cn(
                    "flex items-center gap-3 rounded-sm px-2 py-1 transition-colors",
                    active ? "bg-primary/10" : "hover:bg-accent/40",
                  )}
                >
                  <span
                    className={cn(
                      "tabular w-11 text-left font-mono text-xs",
                      active ? "text-primary" : "text-muted-foreground",
                    )}
                  >
                    {row.year}
                  </span>
                  <div className="flex h-2.5 flex-1 overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full bg-critical transition-all duration-300"
                      style={{ width: `${(row.critical / maxAtRisk) * 100}%` }}
                    />
                    <div
                      className="h-full bg-high transition-all duration-300"
                      style={{ width: `${(row.high / maxAtRisk) * 100}%` }}
                    />
                  </div>
                  <span className="tabular w-14 text-right font-mono text-xs text-foreground">
                    {row.atRisk} / {assets.length}
                  </span>
                </button>
              )
            })}
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              An earlier CRQC pushes assets from Medium into High and Critical: the migration simply has less runway. Flat lines
              mean the finding is urgent for classical reasons, independent of quantum timing.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

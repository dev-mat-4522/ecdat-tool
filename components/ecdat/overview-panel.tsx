"use client"

/**
 * Executive summary: readiness gauge, tier distribution, and the breakdown of
 * where quantum-vulnerable crypto actually lives.
 */

import { useMemo } from "react"
import { Bar, BarChart, Cell, Pie, PieChart, XAxis, YAxis } from "recharts"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Separator } from "@/components/ui/separator"
import { TIER_STYLES, TIERS, TierChip, TypeBadge, ScopeCaption } from "@/components/ecdat/tier"
import { cn } from "@/lib/utils"
import type { CryptoAsset, RiskTier, ScanResult } from "@/lib/ecdat/types"

const PRIMITIVE_LABELS: Record<string, string> = {
  signature: "Signature",
  "key-agreement": "Key agreement",
  "key-encapsulation": "Key encapsulation",
  "public-key-encryption": "PK encryption",
  encryption: "Encryption",
  hash: "Hash",
  mac: "MAC",
  kdf: "KDF",
  drbg: "RNG",
  protocol: "Protocol",
  other: "Other",
}

function Gauge({ score }: { score: number }) {
  const tier: RiskTier = score >= 80 ? "Low" : score >= 55 ? "Medium" : score >= 30 ? "High" : "Critical"
  const data = [
    { name: "ready", value: score },
    { name: "gap", value: 100 - score },
  ]
  return (
    <div className="relative flex items-center justify-center">
      <ChartContainer config={{}} className="aspect-square h-[136px] w-[136px]">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            innerRadius={48}
            outerRadius={64}
            startAngle={90}
            endAngle={-270}
            stroke="none"
            isAnimationActive={false}
          >
            <Cell fill={TIER_STYLES[tier].hex} />
            <Cell fill="var(--muted)" />
          </Pie>
        </PieChart>
      </ChartContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className={cn("tabular text-3xl font-semibold leading-none", TIER_STYLES[tier].text)}>{score}</span>
        <span className="mt-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Readiness</span>
      </div>
    </div>
  )
}

function StatBlock({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</span>
      <span className="tabular text-2xl font-semibold leading-none text-foreground">{value}</span>
      {hint ? <span className="text-xs leading-relaxed text-muted-foreground">{hint}</span> : null}
    </div>
  )
}

export function OverviewPanel({
  scan,
  assets,
  counts,
  readiness,
  quantumVulnerable,
  classicallyBroken,
  occurrences,
  onInspect,
}: {
  scan: ScanResult
  assets: CryptoAsset[]
  counts: Record<RiskTier, number>
  readiness: number
  quantumVulnerable: number
  classicallyBroken: number
  occurrences: number
  onInspect: (asset: CryptoAsset) => void
}) {
  const total = assets.length || 1

  const byPrimitive = useMemo(() => {
    const map = new Map<string, Record<RiskTier, number> & { primitive: string }>()
    for (const asset of assets) {
      const key = PRIMITIVE_LABELS[asset.primitive] ?? asset.primitive
      let row = map.get(key)
      if (!row) {
        row = { primitive: key, Critical: 0, High: 0, Medium: 0, Low: 0 }
        map.set(key, row)
      }
      row[asset.riskTier] += 1
    }
    return [...map.values()].sort(
      (a, b) => b.Critical + b.High - (a.Critical + a.High) || b.Medium + b.Low - (a.Medium + a.Low),
    )
  }, [assets])

  const chartConfig: ChartConfig = {
    Critical: { label: "Critical", color: "var(--critical)" },
    High: { label: "High", color: "var(--high)" },
    Medium: { label: "Medium", color: "var(--medium)" },
    Low: { label: "Low", color: "var(--low)" },
  }

  const topRisks = useMemo(
    () =>
      [...assets]
        .sort(
          (a, b) =>
            TIERS.indexOf(a.riskTier) - TIERS.indexOf(b.riskTier) ||
            b.mosca.margin - a.mosca.margin ||
            b.occurrences - a.occurrences,
        )
        .slice(0, 6),
    [assets],
  )

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent className="flex flex-col gap-6 md:flex-row md:items-center">
          <Gauge score={readiness} />
          <Separator className="md:hidden" />
          <div className="grid flex-1 grid-cols-2 gap-6 lg:grid-cols-4">
            <StatBlock label="Crypto assets" value={String(assets.length)} hint={`${occurrences} total occurrences`} />
            <StatBlock
              label="Quantum-vulnerable"
              value={String(quantumVulnerable)}
              hint={`${Math.round((quantumVulnerable / total) * 100)}% of inventory`}
            />
            <StatBlock label="Already broken" value={String(classicallyBroken)} hint="Classical attacks exist today" />
            <StatBlock
              label="Files scanned"
              value={String(scan.metrics.filesScanned)}
              hint={`${scan.metrics.filesPerSecond.toLocaleString()} files/s`}
            />
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Risk distribution</CardTitle>
            <CardDescription>Mosca tier assigned to every discovered asset.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted" role="img" aria-label="Risk tier distribution">
              {TIERS.map((tier) =>
                counts[tier] ? (
                  <div
                    key={tier}
                    className={TIER_STYLES[tier].bar}
                    style={{ width: `${(counts[tier] / total) * 100}%` }}
                    title={`${tier}: ${counts[tier]}`}
                  />
                ) : null,
              )}
            </div>
            <div className="flex flex-col gap-2">
              {TIERS.map((tier) => (
                <div key={tier} className="flex items-center justify-between gap-3">
                  <TierChip tier={tier} />
                  <div className="flex items-baseline gap-2">
                    <span className="tabular text-sm font-medium text-foreground">{counts[tier]}</span>
                    <span className="tabular font-mono text-[11px] text-muted-foreground">
                      {Math.round((counts[tier] / total) * 100)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle>Exposure by primitive</CardTitle>
            <CardDescription>Which cryptographic functions carry the risk.</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={chartConfig} className="h-[240px] w-full">
              <BarChart data={byPrimitive} layout="vertical" margin={{ left: 4, right: 12, top: 4, bottom: 4 }}>
                <XAxis type="number" hide />
                <YAxis
                  type="category"
                  dataKey="primitive"
                  width={96}
                  tickLine={false}
                  axisLine={false}
                  tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
                />
                <ChartTooltip content={<ChartTooltipContent />} />
                {TIERS.map((tier, index) => (
                  <Bar
                    key={tier}
                    dataKey={tier}
                    stackId="tier"
                    fill={TIER_STYLES[tier].hex}
                    radius={index === TIERS.length - 1 ? [0, 3, 3, 0] : 0}
                    isAnimationActive={false}
                  />
                ))}
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Most urgent findings</CardTitle>
          <CardDescription>Ranked by tier, then by how far the Mosca window is already blown.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {topRisks.map((asset) => (
            <button
              key={asset.id}
              type="button"
              onClick={() => onInspect(asset)}
              className="flex flex-col gap-2 rounded-md border border-border bg-secondary/30 px-3 py-2.5 text-left transition-colors hover:border-primary/40 hover:bg-accent/40 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="flex min-w-0 flex-col gap-1">
                <div className="flex flex-wrap items-center gap-2">
                  <TierChip tier={asset.riskTier} />
                  <span className="font-mono text-sm font-medium text-foreground">{asset.name}</span>
                  <TypeBadge type={asset.type} />
                  <span className="font-mono text-[11px] text-muted-foreground">{PRIMITIVE_LABELS[asset.primitive]}</span>
                </div>
                <span className="truncate font-mono text-[11px] text-muted-foreground">{asset.location}</span>
                <ScopeCaption note={asset.scopeNote} />
              </div>
              <div className="flex shrink-0 items-center gap-4">
                <div className="flex flex-col items-end">
                  <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Margin</span>
                  <span className={cn("tabular font-mono text-sm", TIER_STYLES[asset.riskTier].text)}>
                    {asset.mosca.margin > 0 ? "+" : ""}
                    {asset.mosca.margin}y
                  </span>
                </div>
                <div className="hidden flex-col items-end sm:flex">
                  <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Target</span>
                  <span className="font-mono text-xs text-foreground">{asset.recommendation?.primary ?? "review"}</span>
                  {/* U6 — surface the latency/size trade-off next to the target. */}
                  {asset.recommendation?.performanceNote ? (
                    <span className="max-w-[220px] text-right font-mono text-[10px] leading-tight text-muted-foreground">
                      {asset.recommendation.performanceNote}
                    </span>
                  ) : null}
                </div>
              </div>
            </button>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

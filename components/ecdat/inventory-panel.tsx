"use client"

/** The CBOM inventory table: search, tier/language/primitive filters, sorting. */

import { useMemo, useState } from "react"
import { ArrowUpDown, Search } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ScopeCaption, TIERS, TierChip, TypeBadge } from "@/components/ecdat/tier"
import { cn } from "@/lib/utils"
import type { CryptoAsset, RiskTier } from "@/lib/ecdat/types"

type SortKey = "risk" | "name" | "occurrences" | "margin" | "file"

/** U2 — optional columns the analyst can toggle on when they matter. */
type OptionalColumn = "mode" | "sensitive" | "facing"
const OPTIONAL_COLUMNS: { id: OptionalColumn; label: string }[] = [
  { id: "mode", label: "Mode" },
  { id: "sensitive", label: "Sensitive data" },
  { id: "facing", label: "Facing" },
]

const TIER_RANK: Record<RiskTier, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 }

export function InventoryPanel({ assets, onInspect }: { assets: CryptoAsset[]; onInspect: (asset: CryptoAsset) => void }) {
  const [query, setQuery] = useState("")
  const [tierFilter, setTierFilter] = useState<RiskTier | "all">("all")
  const [langFilter, setLangFilter] = useState<string>("all")
  const [columns, setColumns] = useState<Record<OptionalColumn, boolean>>({ mode: false, sensitive: false, facing: false })
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({ key: "risk", dir: "asc" })

  const languages = useMemo(() => [...new Set(assets.map((a) => a.language))].sort(), [assets])

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const filtered = assets.filter((asset) => {
      if (tierFilter !== "all" && asset.riskTier !== tierFilter) return false
      if (langFilter !== "all" && asset.language !== langFilter) return false
      if (!needle) return true
      return (
        asset.name.toLowerCase().includes(needle) ||
        asset.file.toLowerCase().includes(needle) ||
        asset.family.toLowerCase().includes(needle) ||
        asset.primitive.toLowerCase().includes(needle) ||
        asset.snippet.toLowerCase().includes(needle) ||
        (asset.recommendation?.primary.toLowerCase().includes(needle) ?? false)
      )
    })

    const factor = sort.dir === "asc" ? 1 : -1
    return filtered.sort((a, b) => {
      switch (sort.key) {
        case "name":
          return factor * a.name.localeCompare(b.name)
        case "occurrences":
          return factor * (a.occurrences - b.occurrences)
        case "margin":
          return factor * (b.mosca.margin - a.mosca.margin)
        case "file":
          return factor * a.file.localeCompare(b.file)
        default:
          return factor * (TIER_RANK[a.riskTier] - TIER_RANK[b.riskTier] || b.mosca.margin - a.mosca.margin)
      }
    })
  }, [assets, query, tierFilter, langFilter, sort])

  function toggleSort(key: SortKey) {
    setSort((prev) => (prev.key === key ? { key, dir: prev.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }))
  }

  function SortHead({ label, sortKey, className }: { label: string; sortKey: SortKey; className?: string }) {
    return (
      <TableHead className={className}>
        <button
          type="button"
          onClick={() => toggleSort(sortKey)}
          className={cn(
            "inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-widest transition-colors hover:text-foreground",
            sort.key === sortKey ? "text-primary" : "text-muted-foreground",
          )}
        >
          {label}
          <ArrowUpDown className="size-3" aria-hidden="true" />
        </button>
      </TableHead>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Cryptographic bill of materials</CardTitle>
        <CardDescription>
          {rows.length} of {assets.length} assets. Click any row for evidence and the Mosca calculation.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <InputGroup className="lg:max-w-xs">
            <InputGroupAddon>
              <Search />
            </InputGroupAddon>
            <InputGroupInput
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Algorithm, file, primitive…"
              aria-label="Search inventory"
            />
          </InputGroup>

          <div className="flex flex-wrap items-center gap-1">
            <button
              type="button"
              onClick={() => setTierFilter("all")}
              aria-pressed={tierFilter === "all"}
              className={cn(
                "rounded-sm border px-2 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors",
                tierFilter === "all"
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              All
            </button>
            {TIERS.map((tier) => (
              <button
                key={tier}
                type="button"
                onClick={() => setTierFilter(tier)}
                aria-pressed={tierFilter === tier}
                className={cn(
                  "rounded-sm border px-2 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors",
                  tierFilter === tier
                    ? "border-primary/40 bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:text-foreground",
                )}
              >
                {tier}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-1 lg:ml-auto">
            <button
              type="button"
              onClick={() => setLangFilter("all")}
              aria-pressed={langFilter === "all"}
              className={cn(
                "rounded-sm border px-2 py-1 font-mono text-[11px] transition-colors",
                langFilter === "all"
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              all langs
            </button>
            {languages.map((lang) => (
              <button
                key={lang}
                type="button"
                onClick={() => setLangFilter(lang)}
                aria-pressed={langFilter === lang}
                className={cn(
                  "rounded-sm border px-2 py-1 font-mono text-[11px] transition-colors",
                  langFilter === lang
                    ? "border-primary/40 bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:text-foreground",
                )}
              >
                {lang}
              </button>
            ))}
          </div>
        </div>

        {/* U2 — extra CBOM columns, off by default to keep the table scannable. */}
        <div className="flex flex-wrap items-center gap-1">
          <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Columns</span>
          {OPTIONAL_COLUMNS.map((col) => (
            <button
              key={col.id}
              type="button"
              onClick={() => setColumns((prev) => ({ ...prev, [col.id]: !prev[col.id] }))}
              aria-pressed={columns[col.id]}
              className={cn(
                "rounded-sm border px-2 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors",
                columns[col.id]
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              {col.label}
            </button>
          ))}
        </div>

        {rows.length === 0 ? (
          <Empty className="border border-dashed border-border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Search />
              </EmptyMedia>
              <EmptyTitle>No matching assets</EmptyTitle>
              <EmptyDescription>Loosen the filters or clear the search term.</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <div className="overflow-hidden rounded-md border border-border">
            <Table>
              <TableHeader>
                <TableRow className="bg-secondary/40 hover:bg-secondary/40">
                  <SortHead label="Risk" sortKey="risk" className="w-[110px]" />
                  <SortHead label="Algorithm" sortKey="name" />
                  <TableHead className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                    Primitive
                  </TableHead>
                  {columns.mode ? (
                    <TableHead className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      Mode
                    </TableHead>
                  ) : null}
                  {columns.sensitive ? (
                    <TableHead className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      Sensitive
                    </TableHead>
                  ) : null}
                  {columns.facing ? (
                    <TableHead className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      Facing
                    </TableHead>
                  ) : null}
                  <SortHead label="Location" sortKey="file" />
                  <SortHead label="Uses" sortKey="occurrences" className="text-right" />
                  <SortHead label="Margin" sortKey="margin" className="text-right" />
                  <TableHead className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                    Target
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((asset) => (
                  <TableRow
                    key={asset.id}
                    onClick={() => onInspect(asset)}
                    tabIndex={0}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault()
                        onInspect(asset)
                      }
                    }}
                    className="cursor-pointer"
                  >
                    <TableCell>
                      <TierChip tier={asset.riskTier} />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-medium text-foreground">{asset.name}</span>
                        <TypeBadge type={asset.type} />
                        {asset.classicallyBroken ? (
                          <Badge variant="destructive" className="font-mono text-[10px]">
                            broken
                          </Badge>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{asset.primitive}</TableCell>
                    {columns.mode ? (
                      <TableCell className="font-mono text-xs text-muted-foreground">{asset.mode}</TableCell>
                    ) : null}
                    {columns.sensitive ? (
                      <TableCell className="font-mono text-xs">
                        {asset.classification.sensitiveData ? (
                          <span className="text-amber-400/90">Yes</span>
                        ) : (
                          <span className="text-muted-foreground">No</span>
                        )}
                      </TableCell>
                    ) : null}
                    {columns.facing ? (
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {asset.classification.facing}
                      </TableCell>
                    ) : null}
                    <TableCell className="max-w-[280px] font-mono text-xs text-muted-foreground">
                      <div className="flex flex-col gap-1">
                        <span className="truncate">{asset.location}</span>
                        <ScopeCaption note={asset.scopeNote} />
                      </div>
                    </TableCell>
                    <TableCell className="tabular text-right font-mono text-xs text-foreground">{asset.occurrences}</TableCell>
                    <TableCell className="tabular text-right font-mono text-xs text-foreground">
                      {asset.mosca.margin > 0 ? "+" : ""}
                      {asset.mosca.margin}y
                    </TableCell>
                    <TableCell className="max-w-[200px] truncate font-mono text-xs text-primary">
                      {asset.recommendation?.primary ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

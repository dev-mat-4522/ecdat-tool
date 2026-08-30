import { Info } from "lucide-react"

import { cn } from "@/lib/utils"
import type { AssetType, RiskTier } from "@/lib/ecdat/types"

/** Single source of truth for the risk colour scale used across the UI. */
export const TIER_STYLES: Record<RiskTier, { chip: string; dot: string; text: string; bar: string; hex: string }> = {
  Critical: {
    chip: "bg-critical/15 text-critical border-critical/30",
    dot: "bg-critical",
    text: "text-critical",
    bar: "bg-critical",
    hex: "var(--critical)",
  },
  High: {
    chip: "bg-high/15 text-high border-high/30",
    dot: "bg-high",
    text: "text-high",
    bar: "bg-high",
    hex: "var(--high)",
  },
  Medium: {
    chip: "bg-medium/15 text-medium border-medium/30",
    dot: "bg-medium",
    text: "text-medium",
    bar: "bg-medium",
    hex: "var(--medium)",
  },
  Low: {
    chip: "bg-low/15 text-low border-low/30",
    dot: "bg-low",
    text: "text-low",
    bar: "bg-low",
    hex: "var(--low)",
  },
}

export const TIERS: RiskTier[] = ["Critical", "High", "Medium", "Low"]

export function TierChip({ tier, className }: { tier: RiskTier; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wider",
        TIER_STYLES[tier].chip,
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", TIER_STYLES[tier].dot)} aria-hidden="true" />
      {tier}
    </span>
  )
}

export function TierDot({ tier, className }: { tier: RiskTier; className?: string }) {
  return <span className={cn("size-2 rounded-full", TIER_STYLES[tier].dot, className)} aria-hidden="true" />
}

/**
 * U3 — artefact-type badges for the new asset classes (keys, protocols,
 * hardware modules, cloud services). Kept visually distinct from the risk-tier
 * scale so a "Hardware module" chip is never mistaken for a severity.
 */
const TYPE_BADGE: Partial<Record<AssetType, { label: string; className: string }>> = {
  key: { label: "Key", className: "border-primary/40 bg-primary/10 text-primary" },
  protocol: { label: "Protocol", className: "border-sky-400/40 bg-sky-400/10 text-sky-300" },
  "hardware-module": { label: "Hardware module", className: "border-fuchsia-400/40 bg-fuchsia-400/10 text-fuchsia-300" },
  "cloud-service": { label: "Cloud service", className: "border-violet-400/40 bg-violet-400/10 text-violet-300" },
  certificate: { label: "Certificate", className: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300" },
  library: { label: "Library", className: "border-border bg-muted/60 text-muted-foreground" },
}

/** Renders a type badge for the artefact classes that need one; null otherwise. */
export function TypeBadge({ type, className }: { type: AssetType; className?: string }) {
  const style = TYPE_BADGE[type]
  if (!style) return null
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wider",
        style.className,
        className,
      )}
    >
      {style.label}
    </span>
  )
}

/**
 * U5 — scope caption shown on every finding whose detection mode is narrower
 * than source-level evidence (HSM/cloud references, binary/container metadata).
 * The PRD treats this as a correctness requirement, so it renders verbatim.
 */
export function ScopeCaption({ note, className }: { note?: string; className?: string }) {
  if (!note) return null
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 font-mono text-[10px] leading-tight text-muted-foreground",
        className,
      )}
    >
      <Info className="size-3 shrink-0 text-amber-400/80" aria-hidden="true" />
      {note}
    </span>
  )
}

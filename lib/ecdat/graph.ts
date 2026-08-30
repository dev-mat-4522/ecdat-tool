/**
 * Crypto dependency graph.
 *
 * Four ranked columns — directory -> file -> library/family -> algorithm —
 * with risk-weighted edges. Laid out deterministically on the server so the UI
 * renders an SVG without a physics simulation (fast, stable between renders,
 * and screenshot-reproducible for a demo).
 */

import type { CryptoAsset, RiskTier } from "./types"

export type NodeKind = "directory" | "file" | "family" | "algorithm"

export interface GraphNode {
  id: string
  label: string
  kind: NodeKind
  column: number
  /** Normalised 0-1 vertical position. */
  y: number
  weight: number
  riskTier: RiskTier
  meta?: string
}

export interface GraphEdge {
  from: string
  to: string
  weight: number
  riskTier: RiskTier
}

export interface CryptoGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  columns: { kind: NodeKind; label: string }[]
}

const TIER_RANK: Record<RiskTier, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 }

function worseTier(a: RiskTier, b: RiskTier): RiskTier {
  return TIER_RANK[a] <= TIER_RANK[b] ? a : b
}

function dirOf(file: string): string {
  const parts = file.split("/")
  if (parts.length === 1) return "/"
  return parts.slice(0, Math.min(2, parts.length - 1)).join("/")
}

function shortenFile(file: string): string {
  const parts = file.split("/")
  return parts.length <= 2 ? file : `…/${parts.slice(-2).join("/")}`
}

export function buildGraph(assets: CryptoAsset[], maxPerColumn = 14): CryptoGraph {
  interface Agg {
    id: string
    label: string
    kind: NodeKind
    weight: number
    riskTier: RiskTier
    meta?: string
  }

  const dirs = new Map<string, Agg>()
  const files = new Map<string, Agg>()
  const families = new Map<string, Agg>()
  const algos = new Map<string, Agg>()
  const edgeMap = new Map<string, GraphEdge>()

  const bump = (map: Map<string, Agg>, id: string, label: string, kind: NodeKind, tier: RiskTier, weight: number, meta?: string) => {
    const existing = map.get(id)
    if (existing) {
      existing.weight += weight
      existing.riskTier = worseTier(existing.riskTier, tier)
      return
    }
    map.set(id, { id, label, kind, weight, riskTier: tier, meta })
  }

  const link = (from: string, to: string, tier: RiskTier, weight: number) => {
    const key = `${from}->${to}`
    const existing = edgeMap.get(key)
    if (existing) {
      existing.weight += weight
      existing.riskTier = worseTier(existing.riskTier, tier)
      return
    }
    edgeMap.set(key, { from, to, weight, riskTier: tier })
  }

  for (const asset of assets) {
    const dir = dirOf(asset.file)
    const dirId = `dir:${dir}`
    const fileId = `file:${asset.file}`
    const familyId = `fam:${asset.family}`
    const algoId = `algo:${asset.name}`
    const w = asset.occurrences

    bump(dirs, dirId, dir === "/" ? "(root)" : dir, "directory", asset.riskTier, w)
    bump(files, fileId, shortenFile(asset.file), "file", asset.riskTier, w, asset.file)
    bump(families, familyId, asset.family, "family", asset.riskTier, w, asset.primitive)
    bump(algos, algoId, asset.name, "algorithm", asset.riskTier, w, asset.nistStatus)

    link(dirId, fileId, asset.riskTier, w)
    link(fileId, familyId, asset.riskTier, w)
    link(familyId, algoId, asset.riskTier, w)
  }

  // Keep the heaviest nodes per column so the graph stays readable on big repos.
  const trim = (map: Map<string, Agg>) =>
    [...map.values()]
      .sort((a, b) => TIER_RANK[a.riskTier] - TIER_RANK[b.riskTier] || b.weight - a.weight)
      .slice(0, maxPerColumn)

  const columnsData: Agg[][] = [trim(dirs), trim(files), trim(families), trim(algos)]
  const kept = new Set(columnsData.flat().map((n) => n.id))

  const nodes: GraphNode[] = []
  columnsData.forEach((column, columnIndex) => {
    const count = column.length
    column.forEach((node, index) => {
      nodes.push({
        ...node,
        column: columnIndex,
        y: count === 1 ? 0.5 : index / (count - 1),
      })
    })
  })

  const edges = [...edgeMap.values()].filter((e) => kept.has(e.from) && kept.has(e.to))

  return {
    nodes,
    edges,
    columns: [
      { kind: "directory", label: "Area" },
      { kind: "file", label: "File" },
      { kind: "family", label: "Library / family" },
      { kind: "algorithm", label: "Algorithm" },
    ],
  }
}

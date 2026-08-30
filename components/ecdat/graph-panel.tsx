"use client"

/**
 * Crypto dependency graph — a four-column Sankey-ish flow from code area to
 * algorithm. Layout is computed on the server (`buildGraph`), so this component
 * is pure rendering: deterministic, no physics simulation, no layout jitter.
 */

import { useMemo, useState } from "react"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { TIER_STYLES, TIERS } from "@/components/ecdat/tier"
import { cn } from "@/lib/utils"
import type { CryptoGraph } from "@/lib/ecdat/graph"

const WIDTH = 1000
const HEIGHT = 460
const PAD_X = 76
const PAD_Y = 34
const NODE_W = 132
const NODE_H = 22

export function GraphPanel({ graph }: { graph: CryptoGraph }) {
  const [hovered, setHovered] = useState<string | null>(null)

  const positioned = useMemo(() => {
    const columnCount = graph.columns.length
    const usableW = WIDTH - PAD_X * 2 - NODE_W
    const usableH = HEIGHT - PAD_Y * 2 - NODE_H
    const map = new Map<string, { x: number; y: number; cx: number; cy: number }>()
    for (const node of graph.nodes) {
      const x = PAD_X + (columnCount === 1 ? 0 : (node.column / (columnCount - 1)) * usableW)
      const y = PAD_Y + node.y * usableH
      map.set(node.id, { x, y, cx: x + NODE_W / 2, cy: y + NODE_H / 2 })
    }
    return map
  }, [graph])

  const maxWeight = Math.max(1, ...graph.edges.map((e) => e.weight))

  /** Nodes reachable from the hovered node in either direction. */
  const highlighted = useMemo(() => {
    if (!hovered) return null
    const keep = new Set<string>([hovered])
    let changed = true
    while (changed) {
      changed = false
      for (const edge of graph.edges) {
        if (keep.has(edge.from) && !keep.has(edge.to)) {
          keep.add(edge.to)
          changed = true
        }
        if (keep.has(edge.to) && !keep.has(edge.from)) {
          keep.add(edge.from)
          changed = true
        }
      }
    }
    return keep
  }, [hovered, graph.edges])

  if (!graph.nodes.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Crypto dependency graph</CardTitle>
          <CardDescription>No assets to graph.</CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex flex-col gap-1.5">
            <CardTitle>Crypto dependency graph</CardTitle>
            <CardDescription>
              Code area → file → library family → algorithm. Edge thickness is occurrence count; colour is the worst risk tier
              flowing through it. Hover to isolate a path.
            </CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            {TIERS.map((tier) => (
              <span key={tier} className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                <span className={cn("h-0.5 w-4", TIER_STYLES[tier].bar)} aria-hidden="true" />
                {tier}
              </span>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <svg
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            className="h-auto w-full min-w-[760px]"
            role="img"
            aria-label="Cryptographic dependency graph from code area to algorithm"
          >
            {graph.columns.map((column, index) => {
              const x = PAD_X + (graph.columns.length === 1 ? 0 : (index / (graph.columns.length - 1)) * (WIDTH - PAD_X * 2 - NODE_W))
              return (
                <text
                  key={column.kind}
                  x={x}
                  y={18}
                  className="fill-muted-foreground font-mono"
                  style={{ fontSize: 10, letterSpacing: "0.12em", textTransform: "uppercase" }}
                >
                  {column.label.toUpperCase()}
                </text>
              )
            })}

            <g>
              {graph.edges.map((edge) => {
                const from = positioned.get(edge.from)
                const to = positioned.get(edge.to)
                if (!from || !to) return null
                const x1 = from.x + NODE_W
                const y1 = from.cy
                const x2 = to.x
                const y2 = to.cy
                const mid = (x1 + x2) / 2
                const dim = highlighted ? !(highlighted.has(edge.from) && highlighted.has(edge.to)) : false
                return (
                  <path
                    key={`${edge.from}->${edge.to}`}
                    d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                    fill="none"
                    stroke={TIER_STYLES[edge.riskTier].hex}
                    strokeWidth={0.8 + (edge.weight / maxWeight) * 3.2}
                    opacity={dim ? 0.06 : 0.42}
                    className="transition-opacity duration-200"
                  />
                )
              })}
            </g>

            <g>
              {graph.nodes.map((node) => {
                const pos = positioned.get(node.id)
                if (!pos) return null
                const dim = highlighted ? !highlighted.has(node.id) : false
                const isHovered = hovered === node.id
                return (
                  <g
                    key={node.id}
                    opacity={dim ? 0.22 : 1}
                    className="cursor-default transition-opacity duration-200"
                    onMouseEnter={() => setHovered(node.id)}
                    onMouseLeave={() => setHovered(null)}
                  >
                    <title>
                      {`${node.label}${node.meta ? ` — ${node.meta}` : ""} · ${node.weight} occurrence${
                        node.weight === 1 ? "" : "s"
                      } · ${node.riskTier}`}
                    </title>
                    <rect
                      x={pos.x}
                      y={pos.y}
                      width={NODE_W}
                      height={NODE_H}
                      rx={3}
                      fill="var(--card)"
                      stroke={TIER_STYLES[node.riskTier].hex}
                      strokeWidth={isHovered ? 1.6 : 1}
                    />
                    <rect
                      x={pos.x}
                      y={pos.y}
                      width={3}
                      height={NODE_H}
                      rx={1.5}
                      fill={TIER_STYLES[node.riskTier].hex}
                    />
                    <text
                      x={pos.x + 9}
                      y={pos.y + 15}
                      className="fill-foreground font-mono"
                      style={{ fontSize: 9.5 }}
                    >
                      {node.label.length > 21 ? `${node.label.slice(0, 20)}…` : node.label}
                    </text>
                    <text
                      x={pos.x + NODE_W - 6}
                      y={pos.y + 15}
                      textAnchor="end"
                      className="fill-muted-foreground font-mono"
                      style={{ fontSize: 9 }}
                    >
                      {node.weight}
                    </text>
                  </g>
                )
              })}
            </g>
          </svg>
        </div>
      </CardContent>
    </Card>
  )
}

"use client"

/**
 * Client-side scan state + derivation.
 *
 * The whole analysis layer (Mosca scoring, recommendations, roadmap,
 * compliance, graph) is pure TypeScript, so it runs in the browser as well as
 * on the server. That is what makes the Mosca sliders feel instant: moving X/Y/Z
 * re-scores the existing asset set in a `useMemo` instead of re-scanning the
 * repository. Scanning is the expensive part and it happens exactly once.
 */

import { useCallback, useMemo, useRef, useState } from "react"

import { compliancePosture } from "./compliance"
import { buildGraph } from "./graph"
import { applyRecommendations } from "./recommend"
import { DEFAULT_MOSCA_PARAMS, readinessScore, scoreAssets, tierCounts } from "./risk"
import { buildRoadmap, roadmapTotals } from "./roadmap"
import { buildSystems, systemTotals } from "./systems"
import type { Facing, MoscaParams, ScanResult } from "./types"

export interface ScanRequest {
  /** `container` carries files already extracted from an image in the browser. */
  kind: "demo" | "github" | "upload" | "container"
  repo?: string
  files?: { path: string; content: string }[]
  label?: string
  useCache?: boolean
  /** F5 — scan-level Internal/External declaration. */
  facing?: Facing
  /** Warnings raised while preparing the input (container extraction limits). */
  warnings?: string[]
}

export interface PreviousRun {
  scanId: string
  label: string
  durationMs: number
  analyzeMs: number
  filesScanned: number
  filesFromCache: number
  filesPerSecond: number
}

export function useScan() {
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [status, setStatus] = useState<"idle" | "scanning" | "error">("idle")
  const [error, setError] = useState<string | null>(null)
  const [params, setParams] = useState<MoscaParams>(DEFAULT_MOSCA_PARAMS)
  const [history, setHistory] = useState<PreviousRun[]>([])
  const abortRef = useRef<AbortController | null>(null)

  const run = useCallback(async (request: ScanRequest) => {
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    setStatus("scanning")
    setError(null)

    const clientStart = performance.now()
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...request, moscaParams: params }),
        signal: controller.signal,
      })
      const payload = await response.json()
      if (!response.ok) throw new Error(payload?.error ?? `Scan failed (${response.status}).`)

      const result = payload as ScanResult
      const wallMs = Math.round(performance.now() - clientStart)

      setScan(result)
      setStatus("idle")
      setHistory((prev) =>
        [
          {
            scanId: result.scanId,
            label: `${result.source.label} · round-trip ${wallMs}ms`,
            durationMs: result.metrics.durationMs,
            analyzeMs: result.metrics.analyzeMs,
            filesScanned: result.metrics.filesScanned,
            filesFromCache: result.metrics.filesFromCache,
            filesPerSecond: result.metrics.filesPerSecond,
          },
          ...prev,
        ].slice(0, 6),
      )
      return result
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return null
      const message = caught instanceof Error ? caught.message : "Scan failed."
      setError(message)
      setStatus("error")
      return null
    }
  }, [params])

  /**
   * Re-score in the browser whenever the Mosca inputs change. `scoreAssets`
   * and `applyRecommendations` are both pure, so this is a few thousand
   * arithmetic operations — well under a frame for realistic asset counts.
   */
  const assets = useMemo(() => {
    if (!scan) return []
    return applyRecommendations(scoreAssets(scan.assets, params))
  }, [scan, params])

  const derived = useMemo(() => {
    const counts = tierCounts(assets)
    const roadmap = buildRoadmap(assets)
    const systems = buildSystems(assets)
    return {
      counts,
      readiness: readinessScore(assets),
      roadmap,
      roadmapTotals: roadmapTotals(roadmap),
      compliance: compliancePosture(assets),
      graph: buildGraph(assets),
      systems,
      systemTotals: systemTotals(systems),
      quantumVulnerable: assets.filter((a) => a.quantumVulnerable).length,
      classicallyBroken: assets.filter((a) => a.classicallyBroken).length,
      sensitive: assets.filter((a) => a.classification.sensitiveData).length,
      external: assets.filter((a) => a.classification.facing === "External").length,
      occurrences: assets.reduce((sum, a) => sum + a.occurrences, 0),
    }
  }, [assets])

  const reset = useCallback(() => {
    abortRef.current?.abort()
    setScan(null)
    setStatus("idle")
    setError(null)
  }, [])

  return {
    scan,
    assets,
    derived,
    status,
    error,
    params,
    setParams,
    history,
    run,
    reset,
    isScanning: status === "scanning",
  }
}

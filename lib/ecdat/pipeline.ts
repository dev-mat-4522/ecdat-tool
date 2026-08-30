/**
 * ECDAT pipeline orchestration.
 *
 * Input files -> scanner -> classification -> Mosca risk -> recommendation,
 * with a content-addressed finding cache so re-scans only pay for files whose
 * bytes actually changed (the "diff-aware incremental rescan" feature).
 */

import { applyRecommendations } from "./recommend"
import { buildAssets } from "./classification"
import { DEFAULT_MOSCA_PARAMS, scoreAssets } from "./risk"
import { isScannable, scanFile } from "./scanner"
import type { EvidenceKind, Facing, Language, MoscaParams, RawFinding, ScanMetrics, ScanResult, ScanTarget } from "./types"

/** FNV-1a content hash — cheap, dependency-free, good enough for cache keys. */
export function contentHash(text: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(16).padStart(8, "0") + text.length.toString(16)
}

interface CacheEntry {
  findings: RawFinding[]
  warnings: string[]
  language: Language
}

/**
 * Process-local finding cache keyed by `path@sha`. Persists for the lifetime of
 * the server instance; bounded so a long-lived instance cannot grow unbounded.
 */
const findingCache = new Map<string, CacheEntry>()
const CACHE_LIMIT = 4000

function cacheGet(key: string) {
  const hit = findingCache.get(key)
  if (hit) {
    // refresh LRU position
    findingCache.delete(key)
    findingCache.set(key, hit)
  }
  return hit
}

function cacheSet(key: string, entry: CacheEntry) {
  if (findingCache.size >= CACHE_LIMIT) {
    const oldest = findingCache.keys().next().value
    if (oldest) findingCache.delete(oldest)
  }
  findingCache.set(key, entry)
}

export function cacheStats() {
  return { entries: findingCache.size, limit: CACHE_LIMIT }
}

export function resetCache() {
  findingCache.clear()
}

export interface AnalyzeOptions {
  source: ScanResult["source"]
  moscaParams?: MoscaParams
  /** Files discovered before extension filtering, for honest coverage metrics. */
  filesDiscovered?: number
  fetchMs?: number
  extraWarnings?: string[]
  useCache?: boolean
  /** F5 — scan-level Internal/External declaration; `Mixed` falls back to path heuristics. */
  facing?: Facing
  /**
   * F10 — rewrites every finding's evidence kind, used when the files did not
   * come from a repository but out of a container image. The originating
   * detector stays visible in `detector` and `detail`.
   */
  evidenceTag?: EvidenceKind
}

export function analyze(targets: ScanTarget[], options: AnalyzeOptions): ScanResult {
  const started = Date.now()
  const params = options.moscaParams ?? DEFAULT_MOSCA_PARAMS
  const findings: RawFinding[] = []
  const warnings: string[] = [...(options.extraWarnings ?? [])]
  const parseErrors: ScanMetrics["parseErrors"] = []
  const languageBreakdown: Record<string, number> = {}
  const scannedFiles: ScanResult["scannedFiles"] = []

  let bytesScanned = 0
  let filesScanned = 0
  let filesSkipped = 0
  let filesFromCache = 0

  for (const target of targets) {
    if (!isScannable(target.path)) {
      filesSkipped++
      continue
    }

    const cacheKey = `${target.path}@${target.sha}`
    let outcome = options.useCache === false ? undefined : cacheGet(cacheKey)

    if (outcome) {
      filesFromCache++
    } else {
      const result = scanFile(target.path, target.content)
      if (result.error) {
        parseErrors.push({ file: target.path, error: result.error })
      }
      outcome = { findings: result.findings, warnings: result.warnings, language: result.language }
      if (options.useCache !== false) cacheSet(cacheKey, outcome)
    }

    filesScanned++
    bytesScanned += target.size
    languageBreakdown[outcome.language] = (languageBreakdown[outcome.language] ?? 0) + 1
    findings.push(
      ...(options.evidenceTag
        ? outcome.findings.map((f) => ({
            ...f,
            kind: options.evidenceTag as EvidenceKind,
            detail: f.detail ? `${f.detail} — from container image layer` : "from container image layer",
          }))
        : outcome.findings),
    )
    warnings.push(...outcome.warnings)
    scannedFiles.push({
      path: target.path,
      language: outcome.language,
      findings: outcome.findings.length,
      sha: target.sha,
    })
  }

  const analyzeStart = Date.now()
  const facing: Facing = options.facing ?? "Mixed"
  const assets = applyRecommendations(scoreAssets(buildAssets(findings, { facing }), params))
  const analyzeMs = Date.now() - analyzeStart
  const durationMs = Math.max(1, Date.now() - started)

  return {
    scanId: contentHash(`${options.source.label}:${started}:${targets.length}`),
    source: options.source,
    startedAt: new Date(started).toISOString(),
    assets,
    moscaParams: params,
    facing,
    scannedFiles,
    warnings: [...new Set(warnings)].slice(0, 60),
    metrics: {
      filesDiscovered: options.filesDiscovered ?? targets.length,
      filesScanned,
      filesSkipped,
      filesFromCache,
      bytesScanned,
      findings: findings.length,
      durationMs,
      fetchMs: options.fetchMs ?? 0,
      analyzeMs,
      filesPerSecond: Math.round((filesScanned / durationMs) * 1000),
      kbPerSecond: Math.round(bytesScanned / 1024 / (durationMs / 1000)),
      parseErrors,
      languageBreakdown,
    },
  }
}

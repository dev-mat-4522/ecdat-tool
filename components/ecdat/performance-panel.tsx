"use client"

/**
 * Scan telemetry + coverage.
 *
 * Performance is a stated goal, so it is measured and shown rather than
 * claimed: throughput, the fetch/analyse split, cache hit rate on rescans, and
 * every file the walker touched (including the ones with no findings, which is
 * what makes the coverage claim auditable).
 */

import { useMemo, useState } from "react"
import { AlertTriangle, Database, FileWarning, Gauge, Timer } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { cn } from "@/lib/utils"
import type { ScanResult } from "@/lib/ecdat/types"
import type { PreviousRun } from "@/lib/ecdat/use-scan"

function Metric({
  icon: Icon,
  label,
  value,
  unit,
  hint,
}: {
  icon: typeof Gauge
  label: string
  value: string
  unit?: string
  hint?: string
}) {
  return (
    <div className="flex flex-col gap-1.5 rounded-md border border-border bg-secondary/25 p-3">
      <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        <Icon className="size-3" aria-hidden="true" />
        {label}
      </span>
      <span className="tabular text-2xl font-semibold leading-none text-foreground">
        {value}
        {unit ? <span className="ml-1 text-sm font-normal text-muted-foreground">{unit}</span> : null}
      </span>
      {hint ? <span className="text-[11px] leading-relaxed text-muted-foreground">{hint}</span> : null}
    </div>
  )
}

export function PerformancePanel({ scan, history }: { scan: ScanResult; history: PreviousRun[] }) {
  const [showAllFiles, setShowAllFiles] = useState(false)
  const { metrics } = scan

  const cacheRate = metrics.filesScanned + metrics.filesFromCache
    ? Math.round((metrics.filesFromCache / (metrics.filesScanned + metrics.filesFromCache)) * 100)
    : 0

  const files = useMemo(
    () => [...scan.scannedFiles].sort((a, b) => b.findings - a.findings || a.path.localeCompare(b.path)),
    [scan.scannedFiles],
  )
  const visible = showAllFiles ? files : files.slice(0, 40)
  const withFindings = files.filter((f) => f.findings > 0).length

  const fetchShare = metrics.durationMs ? Math.round((metrics.fetchMs / metrics.durationMs) * 100) : 0

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric
          icon={Gauge}
          label="Throughput"
          value={metrics.filesPerSecond.toLocaleString()}
          unit="files/s"
          hint={`${metrics.kbPerSecond.toLocaleString()} KB/s of source analysed`}
        />
        <Metric
          icon={Timer}
          label="Analysis time"
          value={metrics.analyzeMs.toLocaleString()}
          unit="ms"
          hint={
            metrics.fetchMs
              ? `plus ${metrics.fetchMs.toLocaleString()}ms fetching source (${fetchShare}% of wall time)`
              : "no network fetch — local source"
          }
        />
        <Metric
          icon={Database}
          label="Cache hits"
          value={`${cacheRate}%`}
          hint={`${metrics.filesFromCache} of ${metrics.filesScanned + metrics.filesFromCache} files served from the content-hash cache`}
        />
        <Metric
          icon={FileWarning}
          label="Findings"
          value={metrics.findings.toLocaleString()}
          hint={`${withFindings} of ${files.length} scanned files contain cryptography`}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Incremental rescan</CardTitle>
            <CardDescription>
              Each file is keyed by a content hash, so an unchanged file is never re-parsed. Run the same scan twice to watch the
              analysis time collapse.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {history.length <= 1 ? (
              <Alert>
                <AlertTriangle />
                <AlertTitle>Only one run recorded</AlertTitle>
                <AlertDescription>
                  Re-run the same scan to see the diff-aware speed-up. The second pass reuses cached parse results for every file
                  whose content hash is unchanged.
                </AlertDescription>
              </Alert>
            ) : (
              history.map((run, index) => {
                const first = history[history.length - 1]
                const speedup = run.analyzeMs > 0 ? first.analyzeMs / run.analyzeMs : 1
                return (
                  <div key={`${run.scanId}-${index}`} className="flex flex-col gap-1.5">
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="truncate font-mono text-[11px] text-muted-foreground">
                        {index === 0 ? "latest · " : `#${history.length - index} · `}
                        {run.label}
                      </span>
                      <span className="tabular shrink-0 font-mono text-xs text-foreground">{run.analyzeMs}ms</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                        <div
                          className={cn("h-full", run.filesFromCache > 0 ? "bg-low" : "bg-primary")}
                          style={{
                            width: `${Math.max(3, Math.min(100, (run.analyzeMs / Math.max(1, first.analyzeMs)) * 100))}%`,
                          }}
                        />
                      </div>
                      <span className="tabular w-20 shrink-0 text-right font-mono text-[10px] text-muted-foreground">
                        {run.filesFromCache > 0 ? `${run.filesFromCache} cached` : "cold"}
                      </span>
                      {index !== history.length - 1 && speedup > 1.05 ? (
                        <span className="tabular w-14 shrink-0 text-right font-mono text-[10px] text-low">
                          {speedup.toFixed(1)}× faster
                        </span>
                      ) : (
                        <span className="w-14 shrink-0" />
                      )}
                    </div>
                  </div>
                )
              })
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Coverage and diagnostics</CardTitle>
            <CardDescription>What the walker touched, skipped, and could not parse.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-col gap-2">
              {[
                ["Files discovered", metrics.filesDiscovered],
                ["Files analysed", metrics.filesScanned],
                ["Served from cache", metrics.filesFromCache],
                ["Skipped (not scannable)", metrics.filesSkipped],
                ["Bytes analysed", `${(metrics.bytesScanned / 1024).toFixed(1)} KB`],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex items-baseline justify-between gap-3 border-b border-border pb-1.5 last:border-0">
                  <span className="text-xs text-muted-foreground">{label}</span>
                  <span className="tabular font-mono text-xs text-foreground">{String(value)}</span>
                </div>
              ))}
            </div>

            <Separator />

            <div className="flex flex-col gap-1.5">
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Language breakdown</span>
              {Object.entries(metrics.languageBreakdown)
                .sort((a, b) => b[1] - a[1])
                .map(([language, count]) => (
                  <div key={language} className="flex items-center gap-2">
                    <span className="w-20 shrink-0 font-mono text-[11px] text-muted-foreground">{language}</span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full bg-primary/70"
                        style={{ width: `${(count / Math.max(...Object.values(metrics.languageBreakdown))) * 100}%` }}
                      />
                    </div>
                    <span className="tabular w-8 shrink-0 text-right font-mono text-[11px] text-foreground">{count}</span>
                  </div>
                ))}
            </div>

            {metrics.parseErrors.length ? (
              <>
                <Separator />
                <div className="flex flex-col gap-1">
                  <span className="font-mono text-[10px] uppercase tracking-widest text-medium">
                    Parse degradations ({metrics.parseErrors.length})
                  </span>
                  <p className="text-[11px] leading-relaxed text-muted-foreground">
                    These files fell back to a lexical pass rather than being skipped, so coverage is preserved at lower
                    confidence.
                  </p>
                  <ul className="flex flex-col gap-0.5">
                    {metrics.parseErrors.slice(0, 6).map((error) => (
                      <li key={error.file} className="font-mono text-[11px] text-muted-foreground">
                        <span className="text-foreground">{error.file}</span> — {error.error}
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            ) : null}

            {scan.warnings.length ? (
              <>
                <Separator />
                <div className="flex flex-col gap-1">
                  <span className="font-mono text-[10px] uppercase tracking-widest text-medium">Warnings</span>
                  <ul className="flex flex-col gap-0.5">
                    {scan.warnings.slice(0, 6).map((warning) => (
                      <li key={warning} className="text-[11px] leading-relaxed text-muted-foreground">
                        {warning}
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Scanned files</CardTitle>
          <CardDescription>
            Full walk log — including files with zero findings, which is what makes the coverage number verifiable.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <ScrollArea className="max-h-[320px] rounded-md border border-border">
            <ul className="divide-y divide-border">
              {visible.map((file) => (
                <li key={file.path} className="flex items-center justify-between gap-3 px-3 py-1.5">
                  <span className="truncate font-mono text-[11px] text-foreground">{file.path}</span>
                  <div className="flex shrink-0 items-center gap-3">
                    <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                      {file.language}
                    </span>
                    <span
                      className={cn(
                        "tabular w-8 text-right font-mono text-[11px]",
                        file.findings > 0 ? "text-medium" : "text-muted-foreground",
                      )}
                    >
                      {file.findings}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </ScrollArea>
          {files.length > 40 ? (
            <button
              type="button"
              onClick={() => setShowAllFiles((prev) => !prev)}
              className="self-start font-mono text-[11px] text-primary transition-colors hover:text-foreground"
            >
              {showAllFiles ? "Show fewer" : `Show all ${files.length} files`}
            </button>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}

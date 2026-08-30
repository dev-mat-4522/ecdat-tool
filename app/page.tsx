"use client"

import { useState } from "react"
import {
  Activity,
  ArrowRight,
  Binary,
  BookOpen,
  Command,
  Download,
  Layers,
  Network,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Terminal,
  Waypoints,
  X,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { ScanConsole } from "@/components/ecdat/scan-console"
import { OverviewPanel } from "@/components/ecdat/overview-panel"
import { InventoryPanel } from "@/components/ecdat/inventory-panel"
import { SystemsPanel } from "@/components/ecdat/systems-panel"
import { MoscaPanel } from "@/components/ecdat/mosca-panel"
import { GraphPanel } from "@/components/ecdat/graph-panel"
import { RoadmapPanel } from "@/components/ecdat/roadmap-panel"
import { CompliancePanel } from "@/components/ecdat/compliance-panel"
import { ExportPanel } from "@/components/ecdat/export-panel"
import { PerformancePanel } from "@/components/ecdat/performance-panel"
import { MethodPanel } from "@/components/ecdat/method-panel"
import { AssetDetail } from "@/components/ecdat/asset-detail"
import { useScan, type ScanRequest } from "@/lib/ecdat/use-scan"
import type { CryptoAsset } from "@/lib/ecdat/types"

// Systems (U4/F6) is appended so the existing tab order is untouched.
const NAV = [
  { id: "overview", label: "Overview", icon: Activity },
  { id: "inventory", label: "Asset inventory", icon: Binary },
  { id: "risk", label: "Risk explorer", icon: ShieldCheck },
  { id: "graph", label: "Dependency graph", icon: Network },
  { id: "roadmap", label: "Migration roadmap", icon: Waypoints },
  { id: "compliance", label: "Compliance posture", icon: BookOpen },
  { id: "systems", label: "Systems", icon: Layers },
]

const CAPABILITIES = [
  { icon: Binary, title: "Full CBOM discovery", body: "Python AST plus Java, JS/TS, Go and C# signatures surface every algorithm, key, protocol, certificate, HSM and cloud-KMS reference." },
  { icon: ShieldCheck, title: "Mosca risk scoring", body: "Live X + Y > Z sliders re-tier the whole inventory in the browser, so harvest-now-decrypt-later exposure is quantified, not guessed." },
  { icon: Waypoints, title: "Migration roadmap", body: "Wave-ordered remediation with NIST PQC targets, hybrid options and the latency trade-off attached to each recommendation." },
  { icon: Download, title: "Standards exports", body: "CycloneDX 1.6 CBOM, SARIF 2.1.0 for code scanning, an inventory CSV and a drop-in CI gate — every export tracks the current scoring." },
]

const STEPS = [
  { n: "01", title: "Point ECDAT at code", body: "Scan the bundled demo, any public GitHub repository, a local folder, a .jar, or a container image tarball unpacked in the browser." },
  { n: "02", title: "See the exposure", body: "Assets are classified, scored on the Mosca inequality and rolled up by system, with scope disclaimers on every inferred finding." },
  { n: "03", title: "Export the plan", body: "Take the CBOM, SARIF, roadmap and CI gate straight into your tooling. Nothing is written to disk or retained after the response." },
]

function scrollTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" })
}

export default function Home() {
  const { scan, assets, derived, history, isScanning, error, params, setParams, run, reset } = useScan()
  const {
    counts,
    readiness,
    quantumVulnerable,
    classicallyBroken,
    occurrences,
    roadmap,
    roadmapTotals,
    compliance,
    graph,
    systems,
    systemTotals,
  } = derived
  const [selected, setSelected] = useState<CryptoAsset | null>(null)
  const [active, setActive] = useState("overview")
  const hasResult = Boolean(scan)

  const result = scan ? { ...scan, assets, roadmap, roadmapTotals, compliance, graph } : null

  function handleScan(request: ScanRequest) {
    setSelected(null)
    setActive("overview")
    run(request)
  }

  if (!hasResult) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <header className="sticky top-0 z-20 border-b border-border/60 bg-background/80 backdrop-blur">
          <div className="mx-auto flex h-16 max-w-6xl items-center gap-6 px-5 lg:px-8">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-md bg-gradient-violet text-primary-foreground">
                <Binary className="size-5" aria-hidden="true" />
              </div>
              <div>
                <div className="font-mono text-sm font-semibold tracking-[0.18em]">ECDAT</div>
                <div className="font-mono text-[9px] uppercase tracking-[0.22em] text-muted-foreground">crypto discovery tool</div>
              </div>
            </div>
            <nav className="ml-auto hidden items-center gap-7 font-mono text-xs text-muted-foreground md:flex">
              <button type="button" onClick={() => scrollTo("features")} className="transition-colors hover:text-foreground">Capabilities</button>
              <button type="button" onClick={() => scrollTo("how")} className="transition-colors hover:text-foreground">How it works</button>
              <button type="button" onClick={() => scrollTo("scan")} className="transition-colors hover:text-foreground">Scan</button>
            </nav>
            <Button size="sm" className="ml-auto gap-2 rounded-full bg-gradient-violet font-mono text-xs md:ml-0" onClick={() => scrollTo("scan")}>
              Get started <ArrowRight data-icon="inline-end" />
            </Button>
          </div>
        </header>

        <section className="relative overflow-hidden">
          <div className="hero-glow pointer-events-none absolute inset-x-0 top-0 -z-10 h-[520px]" />
          <div className="mx-auto flex max-w-4xl flex-col items-center px-5 pb-14 pt-20 text-center lg:pt-28">
            <Badge variant="outline" className="mb-6 gap-1.5 rounded-full border-primary/30 bg-primary/10 font-mono text-[10px] uppercase tracking-widest text-primary">
              <Sparkles className="size-3" /> Post-quantum readiness workspace
            </Badge>
            <h1 className="text-balance font-sans text-4xl font-semibold leading-[1.05] tracking-tight md:text-6xl">
              See your cryptography.
              <br />
              <span className="text-gradient-violet">Prepare for what&apos;s next.</span>
            </h1>
            <p className="mt-6 max-w-2xl text-balance text-base leading-7 text-muted-foreground md:text-lg">
              ECDAT discovers every cryptographic asset across source, manifests, configuration, keys, certificates and containers —
              then turns quantum risk into an actionable, standards-based migration plan.
            </p>
            <div className="mt-9 flex flex-col items-center gap-3 sm:flex-row">
              <Button size="lg" className="gap-2 rounded-full bg-gradient-violet px-7 font-mono text-sm" onClick={() => scrollTo("scan")}>
                Run a scan <ArrowRight data-icon="inline-end" />
              </Button>
              <Button size="lg" variant="outline" className="gap-2 rounded-full px-7 font-mono text-sm" onClick={() => scrollTo("how")}>
                See how it works
              </Button>
            </div>
          </div>
        </section>

        <section id="scan" className="mx-auto max-w-4xl px-5 pb-20 lg:px-8">
          <div className="rounded-2xl border border-border bg-card/60 p-1.5 shadow-2xl shadow-primary/5 backdrop-blur">
            <div className="rounded-xl border border-border/60 bg-background/80 p-5 md:p-7">
              <div className="mb-5 flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-primary">
                <Terminal className="size-3" /> cryptographic inventory / new scan
              </div>
              <ScanConsole onScan={handleScan} isScanning={isScanning} hasResult={hasResult} onReset={reset} />
              {error ? (
                <div className="mt-4 rounded-md border border-destructive/40 bg-destructive/10 p-4 font-mono text-xs text-destructive">{error}</div>
              ) : null}
              {isScanning ? (
                <div className="mt-4 flex items-center gap-3 rounded-md border border-primary/30 bg-primary/5 p-4 font-mono text-xs text-primary">
                  <RefreshCw className="size-4 animate-spin" /> Scanning source, resolving signatures, and calculating Mosca exposure…
                </div>
              ) : null}
            </div>
          </div>
        </section>

        <section id="features" className="border-t border-border/60 bg-secondary/20">
          <div className="mx-auto max-w-6xl px-5 py-16 lg:px-8">
            <h2 className="max-w-2xl text-balance font-sans text-2xl font-semibold tracking-tight md:text-3xl">
              A complete crypto-asset pipeline, in the browser.
            </h2>
            <div className="mt-10 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {CAPABILITIES.map((cap) => {
                const Icon = cap.icon
                return (
                  <div key={cap.title} className="flex flex-col gap-3 rounded-xl border border-border bg-card p-5">
                    <div className="flex size-9 items-center justify-center rounded-md border border-primary/30 bg-primary/10 text-primary">
                      <Icon className="size-4" aria-hidden="true" />
                    </div>
                    <h3 className="font-mono text-sm font-semibold text-foreground">{cap.title}</h3>
                    <p className="text-sm leading-6 text-muted-foreground">{cap.body}</p>
                  </div>
                )
              })}
            </div>
          </div>
        </section>

        <section id="how" className="border-t border-border/60">
          <div className="mx-auto max-w-6xl px-5 py-16 lg:px-8">
            <h2 className="max-w-2xl text-balance font-sans text-2xl font-semibold tracking-tight md:text-3xl">
              Three steps from source to a migration plan.
            </h2>
            <div className="mt-10 grid gap-6 md:grid-cols-3">
              {STEPS.map((step) => (
                <div key={step.n} className="flex flex-col gap-3">
                  <span className="font-mono text-3xl font-semibold text-gradient-violet">{step.n}</span>
                  <h3 className="font-mono text-sm font-semibold text-foreground">{step.title}</h3>
                  <p className="text-sm leading-6 text-muted-foreground">{step.body}</p>
                </div>
              ))}
            </div>
            <div className="mt-12 flex flex-col items-start gap-4 rounded-xl border border-border bg-card p-6 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="font-sans text-lg font-semibold text-foreground">Ready to see your exposure?</div>
                <p className="mt-1 text-sm text-muted-foreground">Run the bundled demo repository — no network access required.</p>
              </div>
              <Button size="lg" className="gap-2 rounded-full bg-gradient-violet px-7 font-mono text-sm" onClick={() => scrollTo("scan")}>
                Run a scan <ArrowRight data-icon="inline-end" />
              </Button>
            </div>
          </div>
        </section>

        <footer className="border-t border-border/60">
          <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-5 py-8 font-mono text-[11px] text-muted-foreground sm:flex-row lg:px-8">
            <span>ECDAT — Enterprise Cryptography Discovery &amp; Analysis Tool</span>
            <span>CycloneDX 1.6 · SARIF 2.1.0 · local analysis only</span>
          </div>
        </footer>

        <AssetDetail asset={selected} onClose={() => setSelected(null)} />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-20 border-b border-border/80 bg-background/95 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-[1600px] items-center gap-6 px-5 lg:px-8">
          <button type="button" onClick={reset} className="flex min-w-[220px] items-center gap-3 text-left">
            <div className="flex size-9 items-center justify-center rounded-md bg-gradient-violet text-primary-foreground">
              <Binary className="size-5" aria-hidden="true" />
            </div>
            <div>
              <div className="font-mono text-sm font-semibold tracking-[0.18em]">ECDAT</div>
              <div className="font-mono text-[9px] uppercase tracking-[0.22em] text-muted-foreground">crypto discovery tool</div>
            </div>
          </button>
          <div className="hidden h-5 w-px bg-border md:block" />
          <div className="hidden items-center gap-2 font-mono text-[11px] text-muted-foreground md:flex">
            <span className="size-1.5 rounded-full bg-primary" />
            Post-quantum readiness workspace
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Badge variant="outline" className="hidden gap-1.5 rounded-sm font-mono text-[10px] uppercase tracking-wider sm:flex"><Sparkles className="size-3 text-primary" /> local analysis</Badge>
            <Button variant="outline" size="sm" className="gap-2 rounded-sm font-mono text-xs" onClick={() => setActive("method")}><Command data-icon="inline-start" /> methodology</Button>
          </div>
        </div>
      </header>

      <div className="mx-auto flex max-w-[1600px]">
        <aside className="hidden w-60 shrink-0 border-r border-border lg:block">
          <div className="sticky top-16 flex min-h-[calc(100vh-4rem)] flex-col p-4">
            <div className="mb-6 px-2 font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">Workspace</div>
            <nav className="flex flex-col gap-1" aria-label="ECDAT sections">
              {NAV.map((item) => {
                const Icon = item.icon
                return <Button key={item.id} variant={active === item.id ? "secondary" : "ghost"} className="justify-start gap-3 rounded-sm font-mono text-xs" onClick={() => setActive(item.id)}><Icon data-icon="inline-start" />{item.label}</Button>
              })}
              <Button variant={active === "performance" ? "secondary" : "ghost"} className="justify-start gap-3 rounded-sm font-mono text-xs" onClick={() => setActive("performance")}><RefreshCw data-icon="inline-start" />Performance</Button>
            </nav>
            <Separator className="my-6" />
            <div className="mt-auto rounded-md border border-border bg-card p-4">
              <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-primary">{result?.source.label}</div>
              <p className="text-xs leading-5 text-muted-foreground">{result?.metrics.filesScanned} files analyzed · readiness {readiness}/100.</p>
            </div>
          </div>
        </aside>

        <main className="min-w-0 flex-1">
          <div className="mx-auto max-w-6xl px-5 py-6 lg:px-10">
            {result && <>
              <div className="mb-6 flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
                <div className="flex items-center gap-3 font-mono text-xs"><span className="size-2 rounded-full bg-primary" />{result.source.label}<span className="text-muted-foreground">·</span><span className="text-muted-foreground">{result.metrics.filesScanned} files analyzed</span></div>
                <div className="flex gap-2"><Button variant="outline" size="sm" className="gap-2 rounded-sm font-mono text-xs" onClick={reset}><X data-icon="inline-start" /> new scan</Button><Button variant="outline" size="sm" className="gap-2 rounded-sm font-mono text-xs" onClick={() => setActive("exports")}><Download data-icon="inline-start" /> exports</Button></div>
              </div>

              <div className="mb-6 flex gap-1 overflow-x-auto border-b border-border pb-px lg:hidden">
                {[...NAV, { id: "performance", label: "Performance", icon: RefreshCw }].map((item) => <Button key={item.id} variant="ghost" size="sm" className={active === item.id ? "rounded-b-none border-b-2 border-primary font-mono text-xs" : "rounded-b-none font-mono text-xs text-muted-foreground"} onClick={() => setActive(item.id)}>{item.label}</Button>)}
              </div>

              {active === "overview" && <OverviewPanel scan={result} assets={assets} counts={counts} readiness={readiness} quantumVulnerable={quantumVulnerable} classicallyBroken={classicallyBroken} occurrences={occurrences} onInspect={setSelected} />}
              {active === "inventory" && <InventoryPanel assets={assets} onInspect={setSelected} />}
              {active === "systems" && <SystemsPanel systems={systems} totals={systemTotals} onInspect={setSelected} />}
              {active === "risk" && <MoscaPanel assets={assets} params={params} setParams={setParams} />}
              {active === "graph" && graph && <GraphPanel graph={graph} />}
              {active === "roadmap" && <RoadmapPanel items={result.roadmap ?? []} totals={result.roadmapTotals} label={result.source.label} />}
              {active === "compliance" && <CompliancePanel posture={result.compliance} />}
              {active === "performance" && <PerformancePanel scan={result} history={history} />}
              {active === "exports" && <ExportPanel scan={result} assets={assets} roadmap={result.roadmap ?? []} />}
              {active === "method" && <MethodPanel />}
            </>}
          </div>
        </main>
      </div>
      <AssetDetail asset={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

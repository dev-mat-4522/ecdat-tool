"use client"

/**
 * Scan intake. Source kinds — bundled demo repo, any public GitHub repository,
 * a local folder/file selection (now including `.jar`), or a container image
 * tarball unpacked in the browser.
 */

import { useRef, useState } from "react"
import { FolderUp, GitBranch, Loader2, Play, RotateCcw, Boxes, Container } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"
import { extractContainerImage } from "@/lib/ecdat/container"
import { isBinaryTarget, isScannable } from "@/lib/ecdat/scanner"
import type { ScanRequest } from "@/lib/ecdat/use-scan"
import type { Facing } from "@/lib/ecdat/types"

// U7 — local uploads now also accept `.jar`/`.war`/`.ear` (F9) and key/keystore
// files (F1); the server-side classifier is the final authority.
const SCANNABLE =
  /\.(py|java|js|jsx|ts|tsx|mjs|cjs|go|cs|conf|cnf|ini|yaml|yml|toml|json|txt|properties|pem|crt|cer|pub|tf|tfvars|jar|war|ear|key|jks|p12|pfx|keystore|bks|p8|pk8|asc|gpg)$|(^|\/)(requirements\.txt|package\.json|go\.mod|pom\.xml|build\.gradle|Pipfile|pyproject\.toml|Dockerfile|Containerfile)$/i

const IGNORED_DIR = /(^|\/)(node_modules|\.git|dist|build|\.next|venv|__pycache__|vendor|target)(\/|$)/

const SAMPLE_REPOS = [
  { label: "pyca/cryptography", value: "pyca/cryptography" },
  { label: "psf/requests", value: "psf/requests" },
  { label: "pallets/flask", value: "pallets/flask" },
]

type Mode = "demo" | "github" | "upload" | "container"

const FACINGS: { id: Facing; label: string }[] = [
  { id: "Mixed", label: "Mixed" },
  { id: "Internal", label: "Internal" },
  { id: "External", label: "External" },
]

/** Reads a file as a byte-preserving latin1 string for the JAR/binary detectors. */
async function readLatin1(file: File): Promise<string> {
  const buffer = new Uint8Array(await file.arrayBuffer())
  let out = ""
  for (let i = 0; i < buffer.length; i++) out += String.fromCharCode(buffer[i])
  return out
}

export function ScanConsole({
  onScan,
  isScanning,
  hasResult,
  onReset,
}: {
  onScan: (request: ScanRequest) => void
  isScanning: boolean
  hasResult: boolean
  onReset: () => void
}) {
  const [mode, setMode] = useState<Mode>("demo")
  const [facing, setFacing] = useState<Facing>("Mixed")
  const [repo, setRepo] = useState("")
  const [uploadState, setUploadState] = useState<{ count: number; label: string } | null>(null)
  const [reading, setReading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const pendingFiles = useRef<{ path: string; content: string }[]>([])
  const pendingWarnings = useRef<string[]>([])
  const fileInput = useRef<HTMLInputElement>(null)
  const dirInput = useRef<HTMLInputElement>(null)
  const imageInput = useRef<HTMLInputElement>(null)

  async function handleFiles(fileList: FileList | null) {
    if (!fileList?.length) return
    setReading(true)
    setUploadError(null)
    pendingWarnings.current = []
    const files: { path: string; content: string }[] = []
    let skipped = 0

    for (const file of Array.from(fileList)) {
      const path = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name
      if (IGNORED_DIR.test(path) || !SCANNABLE.test(path) || file.size > 8_000_000) {
        skipped++
        continue
      }
      if (files.length >= 800) {
        skipped++
        continue
      }
      // JAR/keystore binaries must reach the scanner byte-preserved.
      const content = isBinaryTarget(path) ? await readLatin1(file) : await file.text()
      files.push({ path, content })
    }

    pendingFiles.current = files
    setReading(false)

    if (!files.length) {
      setUploadState(null)
      setUploadError("No scannable source files in that selection.")
      return
    }
    const root = files[0].path.includes("/") ? files[0].path.split("/")[0] : "local selection"
    setUploadState({
      count: files.length,
      label: `${root} — ${files.length} file${files.length === 1 ? "" : "s"}${skipped ? `, ${skipped} skipped` : ""}`,
    })
  }

  async function handleImage(fileList: FileList | null) {
    const file = fileList?.[0]
    if (!file) return
    setReading(true)
    setUploadError(null)
    pendingFiles.current = []
    pendingWarnings.current = []
    try {
      const bytes = new Uint8Array(await file.arrayBuffer())
      const extraction = await extractContainerImage(bytes, isScannable, isBinaryTarget)
      pendingFiles.current = extraction.files.map((f) => ({ path: f.path, content: f.content }))
      pendingWarnings.current = extraction.warnings
      setReading(false)
      if (!pendingFiles.current.length) {
        setUploadState(null)
        setUploadError(
          "No scannable files were extracted from the image. ECDAT reads filesystem layers only.",
        )
        return
      }
      setUploadState({
        count: pendingFiles.current.length,
        label: `${file.name} — ${pendingFiles.current.length} file(s) from ${extraction.layers} layer(s)`,
      })
    } catch (error) {
      setReading(false)
      setUploadState(null)
      setUploadError(error instanceof Error ? error.message : "Could not read that image tarball.")
    }
  }

  function submit() {
    if (mode === "demo") {
      onScan({ kind: "demo", facing })
      return
    }
    if (mode === "github") {
      if (!repo.trim()) return
      onScan({ kind: "github", repo: repo.trim(), facing })
      return
    }
    if (!pendingFiles.current.length) return
    if (mode === "container") {
      onScan({
        kind: "container",
        files: pendingFiles.current,
        label: uploadState?.label,
        warnings: pendingWarnings.current,
        facing,
      })
      return
    }
    onScan({ kind: "upload", files: pendingFiles.current, label: uploadState?.label, facing })
  }

  const canSubmit =
    !isScanning &&
    !reading &&
    (mode === "demo"
      ? true
      : mode === "github"
        ? repo.trim().length > 2
        : pendingFiles.current.length > 0)

  const modes: { id: Mode; label: string; icon: typeof Boxes }[] = [
    { id: "demo", label: "Demo repo", icon: Boxes },
    { id: "github", label: "GitHub URL", icon: GitBranch },
    { id: "upload", label: "Local files", icon: FolderUp },
    { id: "container", label: "Container image", icon: Container },
  ]

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-1 rounded-md border border-border bg-secondary/40 p-1 sm:grid-cols-4">
        {modes.map((item) => {
          const Icon = item.icon
          const active = mode === item.id
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setMode(item.id)
                setUploadError(null)
              }}
              aria-pressed={active}
              className={cn(
                "flex items-center justify-center gap-2 rounded-sm px-3 py-2 font-mono text-xs uppercase tracking-wider transition-colors",
                active ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground",
              )}
            >
              <Icon className="size-3.5" aria-hidden="true" />
              {item.label}
            </button>
          )
        })}
      </div>

      {/* U1 — scan-level Internal/External declaration (F5). */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Facing</span>
        <div className="flex items-center gap-1 rounded-md border border-border bg-secondary/40 p-1">
          {FACINGS.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setFacing(item.id)}
              aria-pressed={facing === item.id}
              className={cn(
                "rounded-sm px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors",
                facing === item.id ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {item.label}
            </button>
          ))}
        </div>
        <span className="text-[11px] text-muted-foreground">
          {facing === "Mixed" ? "Path heuristics decide per-asset facing." : `Every asset defaults to ${facing}-facing.`}
        </span>
      </div>

      {mode === "demo" ? (
        <p className="text-sm leading-relaxed text-muted-foreground">
          Scans <span className="font-mono text-foreground">vulnbank</span>, a bundled payment-service fixture spanning Python,
          Java, JavaScript, Go, C#, NGINX/OpenSSL config, dependency manifests, a PEM certificate, standalone key material, HSM and
          cloud-KMS references, a Dockerfile and a JAR. Every detector path and risk tier is represented, so the full pipeline is
          demonstrable offline.
        </p>
      ) : null}

      {mode === "github" ? (
        <div className="flex flex-col gap-3">
          <Input
            value={repo}
            onChange={(event) => setRepo(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.nativeEvent.isComposing && event.keyCode !== 229 && canSubmit) submit()
            }}
            placeholder="github.com/owner/repo  ·  owner/repo  ·  owner/repo/tree/branch"
            className="font-mono text-sm"
            aria-label="GitHub repository"
          />
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Try</span>
            {SAMPLE_REPOS.map((sample) => (
              <button
                key={sample.value}
                type="button"
                onClick={() => setRepo(sample.value)}
                className="rounded-sm border border-border px-2 py-1 font-mono text-[11px] text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
              >
                {sample.label}
              </button>
            ))}
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            Public repositories only, fetched as a tarball through the GitHub API. Large repos are capped at 800 scannable files
            per run.
          </p>
        </div>
      ) : null}

      {mode === "upload" ? (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm" onClick={() => dirInput.current?.click()}>
              <FolderUp data-icon="inline-start" />
              Select folder
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={() => fileInput.current?.click()}>
              Select files
            </Button>
          </div>
          <input
            ref={dirInput}
            type="file"
            multiple
            // @ts-expect-error — non-standard but universally supported directory picker
            webkitdirectory="true"
            directory="true"
            className="sr-only"
            onChange={(event) => handleFiles(event.target.files)}
          />
          <input ref={fileInput} type="file" multiple className="sr-only" onChange={(event) => handleFiles(event.target.files)} />
          {reading ? (
            <p className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
              Reading files…
            </p>
          ) : null}
          {uploadState ? (
            <p className="rounded-sm border border-primary/25 bg-primary/5 px-3 py-2 font-mono text-xs text-foreground">
              {uploadState.label}
            </p>
          ) : null}
          {uploadError ? <p className="font-mono text-xs text-critical">{uploadError}</p> : null}
          <p className="text-xs leading-relaxed text-muted-foreground">
            Source, config, key files and `.jar` archives are read in the browser and posted for a single analysis pass. Nothing is
            written to disk or retained after the response.
          </p>
        </div>
      ) : null}

      {mode === "container" ? (
        <div className="flex flex-col gap-3">
          <Button type="button" variant="outline" size="sm" onClick={() => imageInput.current?.click()}>
            <Container data-icon="inline-start" />
            Select image tarball
          </Button>
          <input
            ref={imageInput}
            type="file"
            accept=".tar,.tar.gz,.tgz,application/x-tar,application/gzip"
            className="sr-only"
            onChange={(event) => handleImage(event.target.files)}
          />
          {reading ? (
            <p className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
              Unpacking image layers…
            </p>
          ) : null}
          {uploadState ? (
            <p className="rounded-sm border border-primary/25 bg-primary/5 px-3 py-2 font-mono text-xs text-foreground">
              {uploadState.label}
            </p>
          ) : null}
          {uploadError ? <p className="font-mono text-xs text-critical">{uploadError}</p> : null}
          <p className="text-xs leading-relaxed text-muted-foreground">
            Export an image with <span className="font-mono text-foreground">docker save image:tag -o image.tar</span>, then select
            it here. Layers are unpacked in the browser and the existing file-walk runs over the extracted files. Scope: filesystem
            layers only — runtime configuration, base-image provenance and registry metadata are not inspected.
          </p>
        </div>
      ) : null}

      <div className="flex items-center gap-2">
        <Button type="button" onClick={submit} disabled={!canSubmit} className="flex-1">
          {isScanning ? <Loader2 data-icon="inline-start" className="animate-spin" /> : <Play data-icon="inline-start" />}
          {isScanning ? "Scanning…" : "Run scan"}
        </Button>
        {hasResult ? (
          <Button type="button" variant="ghost" size="icon" onClick={onReset} aria-label="Clear results">
            <RotateCcw />
          </Button>
        ) : null}
      </div>
    </div>
  )
}

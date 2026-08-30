/**
 * POST /api/scan — the single scan entry point for every source kind.
 *
 * Body: { kind: "demo" }
 *     | { kind: "github", repo: string, useCache?: boolean }
 *     | { kind: "upload", files: { path: string, content: string }[] }
 *     | { kind: "container", files: [...], warnings?: string[] }
 *
 * Every kind also accepts an optional `facing: "Internal" | "External" | "Mixed"`
 * (F5) and `moscaParams`.
 *
 * Container images are unpacked in the browser (`lib/ecdat/container.ts`) and
 * arrive here as ordinary extracted files, tagged with `container` evidence.
 */

import { DEMO_FILES, DEMO_REPO_LABEL } from "@/lib/ecdat/demo-repo"
import { fetchRepoTargets, parseRepoInput } from "@/lib/ecdat/github"
import { analyze, contentHash } from "@/lib/ecdat/pipeline"
import { DEFAULT_MOSCA_PARAMS } from "@/lib/ecdat/risk"
import type { Facing, MoscaParams, ScanTarget } from "@/lib/ecdat/types"

export const maxDuration = 60

interface UploadFile {
  path?: string
  content?: string
}

function toTargets(files: UploadFile[]): ScanTarget[] {
  const targets: ScanTarget[] = []
  for (const file of files) {
    if (!file?.path || typeof file.content !== "string") continue
    targets.push({
      path: file.path.replace(/^\.?\//, ""),
      content: file.content,
      size: file.content.length,
      sha: contentHash(file.content),
    })
  }
  return targets
}

/** F5 — anything unrecognised stays `Mixed`, which keeps path heuristics active. */
function parseFacing(input: unknown): Facing {
  return input === "Internal" || input === "External" ? input : "Mixed"
}

function parseWarnings(input: unknown): string[] {
  if (!Array.isArray(input)) return []
  return input.filter((w): w is string => typeof w === "string").slice(0, 40)
}

function parseMosca(input: unknown): MoscaParams {
  if (!input || typeof input !== "object") return DEFAULT_MOSCA_PARAMS
  const raw = input as Record<string, unknown>
  const z = Number(raw.z)
  const xMultiplier = Number(raw.xMultiplier)
  const yOverride = raw.yOverride === null || raw.yOverride === undefined ? undefined : Number(raw.yOverride)
  return {
    z: Number.isFinite(z) ? Math.min(40, Math.max(0, z)) : DEFAULT_MOSCA_PARAMS.z,
    xMultiplier: Number.isFinite(xMultiplier) ? Math.min(3, Math.max(0.25, xMultiplier)) : 1,
    yOverride: yOverride !== undefined && Number.isFinite(yOverride) ? Math.min(20, Math.max(0, yOverride)) : undefined,
  }
}

export async function POST(request: Request) {
  let body: Record<string, unknown>
  try {
    body = (await request.json()) as Record<string, unknown>
  } catch {
    return Response.json({ error: "Invalid JSON body." }, { status: 400 })
  }

  const kind = String(body.kind ?? "demo")
  const moscaParams = parseMosca(body.moscaParams)
  const useCache = body.useCache !== false
  const facing = parseFacing(body.facing)

  try {
    if (kind === "demo") {
      const targets = toTargets(DEMO_FILES)
      const result = analyze(targets, {
        source: { kind: "demo", label: DEMO_REPO_LABEL, ref: "bundled" },
        moscaParams,
        filesDiscovered: DEMO_FILES.length,
        useCache,
        facing,
      })
      return Response.json(result)
    }

    if (kind === "upload") {
      const files = Array.isArray(body.files) ? (body.files as UploadFile[]) : []
      if (!files.length) {
        return Response.json({ error: "No files were provided." }, { status: 400 })
      }
      if (files.length > 800) {
        return Response.json({ error: "Upload limited to 800 files per scan." }, { status: 413 })
      }
      const targets = toTargets(files)
      if (!targets.length) {
        return Response.json({ error: "None of the uploaded files are readable text." }, { status: 400 })
      }
      const result = analyze(targets, {
        source: { kind: "upload", label: String(body.label ?? `${targets.length} uploaded file(s)`) },
        moscaParams,
        filesDiscovered: files.length,
        useCache,
        facing,
      })
      return Response.json(result)
    }

    // F10 — files already extracted from an image layer set or a Dockerfile.
    if (kind === "container") {
      const files = Array.isArray(body.files) ? (body.files as UploadFile[]) : []
      const warnings = parseWarnings(body.warnings)
      const targets = toTargets(files)
      if (!targets.length) {
        return Response.json(
          {
            error:
              "No scannable files were extracted from the image. ECDAT reads filesystem layers only — runtime config, base-image metadata and registries are out of scope.",
          },
          { status: 400 },
        )
      }
      const result = analyze(targets, {
        source: { kind: "container", label: String(body.label ?? `container image (${targets.length} files)`) },
        moscaParams,
        filesDiscovered: files.length,
        useCache,
        facing,
        evidenceTag: "container",
        extraWarnings: [
          "Container scan scope: files inside the image filesystem layers only. Runtime configuration, base-image provenance and registry metadata are not inspected.",
          ...warnings,
        ],
      })
      return Response.json(result)
    }

    if (kind === "github") {
      const parsed = parseRepoInput(String(body.repo ?? ""))
      if (!parsed) {
        return Response.json(
          { error: "Could not parse that repository. Use a GitHub URL or owner/repo." },
          { status: 400 },
        )
      }
      const fetched = await fetchRepoTargets(parsed)
      const result = analyze(fetched.targets, {
        source: { kind: "github", label: fetched.label, ref: fetched.ref, url: fetched.url },
        moscaParams,
        filesDiscovered: fetched.filesDiscovered,
        fetchMs: fetched.fetchMs,
        extraWarnings: fetched.warnings,
        useCache,
        facing,
      })
      return Response.json(result)
    }

    return Response.json({ error: `Unknown scan kind "${kind}".` }, { status: 400 })
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed."
    console.log("[v0] scan error:", message)
    return Response.json({ error: message }, { status: 502 })
  }
}

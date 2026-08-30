/**
 * GitHub repository ingestion.
 *
 * Uses the Git trees API to enumerate the repo in one request, filters to
 * scannable paths *before* downloading anything, then fetches file contents
 * concurrently from raw.githubusercontent.com. This is the main throughput win
 * over a naive clone-and-walk: on a large repo ECDAT downloads a few hundred KB
 * instead of tens of megabytes.
 */

import { isScannable } from "./scanner"
import { contentHash } from "./pipeline"
import type { ScanTarget } from "./types"

export interface ParsedRepo {
  owner: string
  repo: string
  ref?: string
}

export function parseRepoInput(input: string): ParsedRepo | null {
  const trimmed = input.trim().replace(/\.git$/, "").replace(/\/+$/, "")
  if (!trimmed) return null

  // Full URL form, including /tree/<ref> deep links.
  const urlMatch = trimmed.match(/github\.com\/([^/\s]+)\/([^/\s]+)(?:\/tree\/([^/\s]+))?/i)
  if (urlMatch) {
    return { owner: urlMatch[1], repo: urlMatch[2], ref: urlMatch[3] }
  }

  // owner/repo or owner/repo@ref shorthand.
  const shortMatch = trimmed.match(/^([\w.-]+)\/([\w.-]+)(?:@([\w./-]+))?$/)
  if (shortMatch) {
    return { owner: shortMatch[1], repo: shortMatch[2], ref: shortMatch[3] }
  }

  return null
}

const MAX_FILES = 900
const MAX_FILE_BYTES = 400_000
const CONCURRENCY = 24

function ghHeaders(): HeadersInit {
  const headers: HeadersInit = {
    accept: "application/vnd.github+json",
    "user-agent": "ECDAT-Scanner",
    "x-github-api-version": "2022-11-28",
  }
  // Optional: lifts the 60/hr anonymous rate limit when the user supplies one.
  const token = process.env.GITHUB_TOKEN
  if (token) (headers as Record<string, string>).authorization = `Bearer ${token}`
  return headers
}

export interface FetchRepoResult {
  targets: ScanTarget[]
  filesDiscovered: number
  fetchMs: number
  ref: string
  label: string
  url: string
  warnings: string[]
  truncated: boolean
}

export async function fetchRepoTargets(parsed: ParsedRepo): Promise<FetchRepoResult> {
  const started = Date.now()
  const warnings: string[] = []
  const { owner, repo } = parsed

  let ref = parsed.ref
  if (!ref) {
    const metaResponse = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: ghHeaders(),
      cache: "no-store",
    })
    if (!metaResponse.ok) {
      throw new Error(
        metaResponse.status === 404
          ? `Repository ${owner}/${repo} not found or is private.`
          : metaResponse.status === 403
            ? "GitHub API rate limit reached. Add a GITHUB_TOKEN environment variable, or use the bundled demo repository."
            : `GitHub API error ${metaResponse.status} while resolving the default branch.`,
      )
    }
    const meta = (await metaResponse.json()) as { default_branch?: string }
    ref = meta.default_branch ?? "main"
  }

  const treeResponse = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`,
    { headers: ghHeaders(), cache: "no-store" },
  )
  if (!treeResponse.ok) {
    throw new Error(
      treeResponse.status === 404
        ? `Ref "${ref}" not found in ${owner}/${repo}.`
        : `GitHub API error ${treeResponse.status} while listing the repository tree.`,
    )
  }

  const tree = (await treeResponse.json()) as {
    tree?: { path: string; type: string; size?: number }[]
    truncated?: boolean
  }
  const blobs = (tree.tree ?? []).filter((entry) => entry.type === "blob")
  if (tree.truncated) {
    warnings.push("GitHub truncated the repository tree; some files were not enumerated.")
  }

  const candidates = blobs.filter((entry) => isScannable(entry.path) && (entry.size ?? 0) <= MAX_FILE_BYTES)
  const oversized = blobs.filter((entry) => isScannable(entry.path) && (entry.size ?? 0) > MAX_FILE_BYTES)
  if (oversized.length) {
    warnings.push(`${oversized.length} scannable file(s) skipped for exceeding ${MAX_FILE_BYTES / 1000} KB.`)
  }

  const selected = candidates.slice(0, MAX_FILES)
  const truncated = candidates.length > MAX_FILES
  if (truncated) {
    warnings.push(`Repository has ${candidates.length} scannable files; ECDAT scanned the first ${MAX_FILES}.`)
  }

  const targets: ScanTarget[] = []
  let cursor = 0

  async function worker() {
    while (cursor < selected.length) {
      const index = cursor++
      const entry = selected[index]
      try {
        const raw = await fetch(
          `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(ref!)}/${entry.path
            .split("/")
            .map(encodeURIComponent)
            .join("/")}`,
          { cache: "no-store" },
        )
        if (!raw.ok) continue
        const content = await raw.text()
        targets.push({
          path: entry.path,
          content,
          size: entry.size ?? content.length,
          sha: contentHash(content),
        })
      } catch {
        // A single unreachable blob must not fail the whole scan.
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, selected.length || 1) }, worker))

  if (!targets.length) {
    warnings.push("No scannable source files were retrieved from this repository.")
  }

  return {
    targets,
    filesDiscovered: blobs.length,
    fetchMs: Date.now() - started,
    ref,
    label: `${owner}/${repo}`,
    url: `https://github.com/${owner}/${repo}/tree/${ref}`,
    warnings,
    truncated,
  }
}

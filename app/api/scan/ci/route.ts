/**
 * POST /api/scan/ci — the endpoint the generated GitHub Action calls.
 *
 * Returns SARIF 2.1.0 directly so the workflow can pipe it straight into
 * `github/codeql-action/upload-sarif`.
 *
 * Body: { repo: "owner/name", ref?: string, failOn?: RiskTier }
 */

import { buildSarif } from "@/lib/ecdat/export/sarif"
import { fetchRepoTargets, parseRepoInput } from "@/lib/ecdat/github"
import { analyze } from "@/lib/ecdat/pipeline"
import { DEFAULT_MOSCA_PARAMS } from "@/lib/ecdat/risk"
import type { RiskTier } from "@/lib/ecdat/types"

export const maxDuration = 60

const TIER_RANK: Record<RiskTier, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 }

export async function POST(request: Request) {
  let body: Record<string, unknown>
  try {
    body = (await request.json()) as Record<string, unknown>
  } catch {
    return Response.json({ error: "Invalid JSON body." }, { status: 400 })
  }

  const repoInput = String(body.repo ?? "")
  const ref = body.ref ? String(body.ref) : undefined
  const failOn = (String(body.failOn ?? "High") as RiskTier) ?? "High"

  const parsed = parseRepoInput(ref ? `${repoInput}@${ref}` : repoInput)
  if (!parsed) {
    return Response.json({ error: "Provide `repo` as owner/name." }, { status: 400 })
  }

  try {
    const fetched = await fetchRepoTargets(parsed)
    const scan = analyze(fetched.targets, {
      source: { kind: "github", label: fetched.label, ref: fetched.ref, url: fetched.url },
      moscaParams: DEFAULT_MOSCA_PARAMS,
      filesDiscovered: fetched.filesDiscovered,
      fetchMs: fetched.fetchMs,
      extraWarnings: fetched.warnings,
    })

    const gateThreshold = TIER_RANK[failOn] ?? TIER_RANK.High
    const blocking = scan.assets.filter((asset) => TIER_RANK[asset.riskTier] <= gateThreshold)
    const sarif = buildSarif(scan)

    return new Response(JSON.stringify(sarif, null, 2), {
      headers: {
        "content-type": "application/sarif+json",
        "x-ecdat-gate": blocking.length > 0 ? "fail" : "pass",
        "x-ecdat-blocking-findings": String(blocking.length),
        "x-ecdat-files-scanned": String(scan.metrics.filesScanned),
      },
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed."
    return Response.json({ error: message }, { status: 502 })
  }
}

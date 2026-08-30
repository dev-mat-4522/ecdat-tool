/**
 * SARIF 2.1.0 export + a ready-to-paste GitHub Actions gate.
 *
 * This is what turns ECDAT from a report into a control: GitHub code scanning
 * ingests SARIF natively, so a PR that introduces new quantum-vulnerable crypto
 * shows the finding inline on the diff and can fail the build.
 */

import type { CryptoAsset, RiskTier, ScanResult } from "../types"

const LEVEL: Record<RiskTier, "error" | "warning" | "note"> = {
  Critical: "error",
  High: "error",
  Medium: "warning",
  Low: "note",
}

/** SARIF wants a 0-1 rank; map the tier onto the standard security-severity. */
const SECURITY_SEVERITY: Record<RiskTier, string> = {
  Critical: "9.5",
  High: "7.5",
  Medium: "5.0",
  Low: "2.0",
}

function ruleId(asset: CryptoAsset) {
  return `ECDAT-${asset.family.toUpperCase()}-${asset.primitive.toUpperCase().replace(/[^A-Z]/g, "")}`
}

export function buildSarif(scan: ScanResult) {
  const rules = new Map<string, Record<string, unknown>>()

  for (const asset of scan.assets) {
    const id = ruleId(asset)
    if (rules.has(id)) continue
    rules.set(id, {
      id,
      name: `${asset.family}${asset.primitive.replace(/(^|-)(\w)/g, (_, __, c) => c.toUpperCase())}`,
      shortDescription: { text: `${asset.family} ${asset.primitive} is ${asset.quantumVulnerable ? "quantum-vulnerable" : "in scope for PQC review"}` },
      fullDescription: {
        text:
          `${asset.name} — ${asset.nistStatus}. ` +
          (asset.quantumVulnerable
            ? "Broken by Shor's algorithm on a cryptographically relevant quantum computer."
            : asset.groverWeakened
              ? "Effective strength halved by Grover's algorithm; resize rather than replace."
              : "Reported for completeness of the cryptographic inventory."),
      },
      help: {
        text: asset.recommendation
          ? `Migrate to ${asset.recommendation.primary} (${asset.recommendation.standard}). ${asset.recommendation.notes}`
          : "Review this usage against your PQC migration policy.",
      },
      properties: {
        tags: [
          "cryptography",
          "post-quantum",
          asset.quantumVulnerable ? "quantum-vulnerable" : "quantum-safe-review",
          ...(asset.classicallyBroken ? ["classically-broken"] : []),
        ],
        "security-severity": SECURITY_SEVERITY[asset.riskTier],
      },
    })
  }

  const results = scan.assets.flatMap((asset) =>
    asset.locations.map((location) => {
      const [file, line] = location.split(/:(?=\d+$)/)
      return {
        ruleId: ruleId(asset),
        level: LEVEL[asset.riskTier],
        message: {
          text:
            `${asset.riskTier} — ${asset.name} (${asset.nistStatus}). ` +
            `Mosca: X=${asset.mosca.x}y + Y=${asset.mosca.y}y vs Z=${asset.mosca.z}y (margin ${asset.mosca.margin > 0 ? "+" : ""}${asset.mosca.margin}y). ` +
            (asset.recommendation ? `Recommended: ${asset.recommendation.primary} per ${asset.recommendation.standard}.` : "") +
            // U5 — the scope caveat is part of the finding text, so it survives
            // into GitHub code scanning where the ECDAT UI is not present.
            (asset.scopeNote ? ` Scope: ${asset.scopeNote}.` : ""),
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: file },
              region: { startLine: Number(line) || asset.line, snippet: { text: asset.snippet } },
            },
          },
        ],
        partialFingerprints: { ecdatAssetId: asset.id },
        properties: {
          riskTier: asset.riskTier,
          businessCriticality: asset.classification.businessCriticality,
          moscaMargin: asset.mosca.margin,
          artefactType: asset.type,
          mode: asset.mode,
          sensitiveData: asset.classification.sensitiveData,
          facing: asset.classification.facing,
          system: asset.systemKey,
          evidenceKind: asset.evidence,
          ...(asset.scopeNote ? { scopeNote: asset.scopeNote } : {}),
          ...(asset.recommendation?.performanceNote ? { performanceNote: asset.recommendation.performanceNote } : {}),
        },
      }
    }),
  )

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "ECDAT",
            fullName: "Enhanced Cryptographic Discovery & Assessment Tool",
            version: "1.0.0",
            informationUri: "https://github.com/",
            rules: [...rules.values()],
          },
        },
        automationDetails: { id: `ecdat/${scan.scanId}` },
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: scan.startedAt,
            properties: {
              filesScanned: scan.metrics.filesScanned,
              durationMs: scan.metrics.durationMs,
            },
          },
        ],
      },
    ],
  }
}

/** The CI gate snippet shown in the export panel. */
export function githubActionWorkflow(threshold: RiskTier = "High"): string {
  return `# .github/workflows/ecdat-pqc-gate.yml
# Fails the build when new quantum-vulnerable cryptography is introduced.
name: ECDAT PQC Gate

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to code scanning

jobs:
  cbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run ECDAT scan
        run: |
          curl -sSf -X POST "$ECDAT_URL/api/scan/ci" \\
            -H 'content-type: application/json' \\
            -d "{\\"repo\\": \\"\${{ github.repository }}\\", \\"ref\\": \\"\${{ github.sha }}\\", \\"failOn\\": \\"${threshold}\\"}" \\
            -o ecdat.sarif
        env:
          ECDAT_URL: \${{ vars.ECDAT_URL }}

      - name: Upload SARIF to code scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ecdat.sarif
          category: ecdat-pqc

      - name: Enforce gate
        run: |
          COUNT=$(jq '[.runs[0].results[] | select(.level == "error")] | length' ecdat.sarif)
          echo "ECDAT findings at or above ${threshold}: $COUNT"
          if [ "$COUNT" -gt 0 ]; then
            echo "::error::ECDAT gate failed - $COUNT quantum-vulnerable finding(s) at or above ${threshold}."
            exit 1
          fi
`
}

"use client"

/**
 * Methodology and honest limitations.
 *
 * A discovery tool that does not state its false-negative modes is not
 * trustworthy, so the limits are a first-class part of the product surface
 * rather than a footnote in a README.
 */

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { SIGNATURE_DB_STATS } from "@/lib/ecdat/signatures"

const PIPELINE = [
  {
    step: "1",
    title: "Discover",
    body: "Walk the source tree, filter to scannable extensions and manifests, cap file size, and skip vendored directories. Every visited path is recorded so coverage is provable, not asserted.",
  },
  {
    step: "2",
    title: "Detect",
    body: "Python goes through a hand-written tokenizer that tracks import aliases and resolves attribute chains, so `from hashlib import md5 as h; h(x)` is caught. Java, JavaScript/TypeScript, Go and C# use comment-stripped pattern matching. Configs, dependency manifests and PEM certificates each get a dedicated reader.",
  },
  {
    step: "3",
    title: "Classify",
    body: "Each finding is matched against the algorithm database for primitive, NIST status and quantum exposure, then the file path assigns business criticality and a data shelf-life. The rationale string is kept so the heuristic can be argued with.",
  },
  {
    step: "4",
    title: "Assess",
    body: "Mosca's inequality — (X + Y) − Z — produces the risk tier. Vulnerability and urgency stay separate signals: a strong RSA key is quantum-vulnerable but may not be urgent, and MD5 is urgent for reasons unrelated to quantum computing.",
  },
  {
    step: "5",
    title: "Recommend",
    body: "Each family maps to a NIST-standardised replacement (FIPS 203/204/205) with a hybrid transition option and a conservative alternative where one exists.",
  },
  {
    step: "6",
    title: "Report",
    body: "The same asset objects project into CycloneDX 1.6 CBOM, SARIF 2.1.0, CSV and a wave-ordered migration roadmap. Nothing is re-derived for export, so the report cannot drift from the analysis.",
  },
]

const LIMITATIONS = [
  {
    title: "Static analysis only",
    body: "ECDAT reads source. It does not observe a running process, inspect TLS handshakes on the wire, or disassemble compiled binaries. Crypto reached only at runtime — a driver selected from a database column, an algorithm name assembled from string fragments — will be missed.",
  },
  {
    title: "Dynamic dispatch is reported, not resolved",
    body: "Calls like `getattr(hashlib, name)(data)` are counted as dynamic-call degradations and surfaced in diagnostics rather than silently dropped, but the concrete algorithm cannot be recovered statically.",
  },
  {
    title: "Key sizes are best-effort",
    body: "A literal argument (`RSA.generate(2048)`) is recovered. A key size read from configuration or computed at runtime is not, so the algorithm default is used and the asset is marked medium confidence.",
  },
  {
    title: "Non-Python languages use pattern matching",
    body: "Java, JS/TS, Go and C# are matched after comment stripping, without a full parse. This is deliberately biased toward recall: expect occasional false positives in string-heavy code, and treat those findings as leads.",
  },
  {
    title: "Certificate parsing is structural",
    body: "PEM blocks are base64-decoded and the signature-algorithm OID is read out of the DER. ECDAT does not verify chains, check revocation, or validate expiry.",
  },
  {
    title: "Z is a forecast",
    body: "No one knows when a cryptographically relevant quantum computer arrives. The default of 2033 follows the CNSA 2.0 mandate date; the explorer exists so you can test your own assumption instead of inheriting ours.",
  },
  {
    title: "Effort estimates are planning inputs",
    body: "The day estimates come from a disclosed multiplicative model, not from historical project data. Use them to rank work, not to sign a contract.",
  },
]

const REFERENCES = [
  { label: "FIPS 203 — ML-KEM", detail: "Module-Lattice Key Encapsulation, Aug 2024" },
  { label: "FIPS 204 — ML-DSA", detail: "Module-Lattice Digital Signature, Aug 2024" },
  { label: "FIPS 205 — SLH-DSA", detail: "Stateless Hash-Based Signature, Aug 2024" },
  { label: "NIST IR 8547", detail: "Transition to PQC standards — 2030 deprecate, 2035 disallow" },
  { label: "NSA CNSA 2.0", detail: "PQC exclusive for national-security systems by 2033" },
  { label: "NIST SP 800-131A Rev. 2", detail: "Transitioning the use of cryptographic algorithms" },
  { label: "CycloneDX 1.6 / ECMA-424", detail: "Cryptographic bill of materials schema" },
  { label: "Mosca, 2015", detail: "Cybersecurity in an era with quantum computers" },
]

export function MethodPanel() {
  const stats = [
    ["Algorithm specifications", SIGNATURE_DB_STATS.algorithms],
    ["Python import signatures", SIGNATURE_DB_STATS.pythonImports],
    ["Python call signatures", SIGNATURE_DB_STATS.pythonCalls],
    ["Cross-language patterns", SIGNATURE_DB_STATS.regexSignatures],
    ["Configuration directives", SIGNATURE_DB_STATS.configSignatures],
    ["Dependency manifest tokens", SIGNATURE_DB_STATS.dependencySignatures],
  ] as const

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Detection pipeline</CardTitle>
          <CardDescription>Six stages, each one auditable in isolation.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {PIPELINE.map((stage) => (
            <div key={stage.step} className="flex gap-4">
              <span className="tabular mt-0.5 shrink-0 font-mono text-xs text-primary">{stage.step}</span>
              <div className="flex flex-col gap-1">
                <span className="text-sm font-medium text-foreground">{stage.title}</span>
                <p className="text-xs leading-relaxed text-muted-foreground">{stage.body}</p>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Signature database</CardTitle>
            <CardDescription>{SIGNATURE_DB_STATS.total} detection rules across six readers.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {stats.map(([label, value]) => (
              <div key={label} className="flex items-baseline justify-between gap-3 border-b border-border pb-1.5 last:border-0">
                <span className="text-xs text-muted-foreground">{label}</span>
                <span className="tabular font-mono text-xs text-foreground">{value}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Standards referenced</CardTitle>
            <CardDescription>Every recommendation and deadline in the tool traces to one of these.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {REFERENCES.map((reference) => (
              <div key={reference.label} className="flex flex-col gap-0.5 border-b border-border pb-1.5 last:border-0">
                <span className="font-mono text-xs text-foreground">{reference.label}</span>
                <span className="text-[11px] leading-relaxed text-muted-foreground">{reference.detail}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Known limitations</CardTitle>
          <CardDescription>
            What ECDAT cannot see. A discovery tool that hides its false-negative modes is worse than one that states them.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {LIMITATIONS.map((limitation, index) => (
            <div key={limitation.title} className="flex flex-col gap-1">
              {index > 0 ? <Separator className="mb-2" /> : null}
              <span className="text-sm font-medium text-foreground">{limitation.title}</span>
              <p className="text-xs leading-relaxed text-muted-foreground">{limitation.body}</p>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

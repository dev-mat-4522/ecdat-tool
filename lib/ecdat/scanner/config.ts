/**
 * ECDAT configuration + dependency-manifest scanner.
 *
 * Configuration files are where a lot of real cryptographic policy lives
 * (TLS versions, cipher suites, SSH key-exchange lists) and where a code-only
 * scanner is blind. Manifests give library-level inventory even for files the
 * scanner never opens.
 */

import { CONFIG_SIGNATURES, DEPENDENCY_SIGNATURES, getAlgorithm, keySizeFromString, modeFromString } from "../signatures"
import type { RawFinding } from "../types"
import { lineAt, lineIndex, stripComments } from "./regex-langs"

/**
 * F2 — TLS/SSH protocol cataloguing.
 *
 * The signature pass below already flags individual weak tokens (`RC4`,
 * `TLSv1`). What it cannot express is the thing an auditor actually asks about:
 * *which protocol configurations are negotiable here*. A `ssl_protocols` line
 * and an `ssl_ciphers` line together declare a set of version × suite
 * combinations, and each combination is a first-class protocol artefact with its
 * own quantum exposure.
 */
interface VersionToken {
  pattern: RegExp
  algorithmId: string
  name: string
}

const TLS_VERSIONS: VersionToken[] = [
  { pattern: /\bSSLv2\b/gi, algorithmId: "tls1.0", name: "SSL 2.0" },
  { pattern: /\bSSLv3\b/gi, algorithmId: "tls1.0", name: "SSL 3.0" },
  { pattern: /\bTLS[_ v]?1[._]3\b/gi, algorithmId: "tls1.3", name: "TLS 1.3" },
  { pattern: /\bTLS[_ v]?1[._]2\b/gi, algorithmId: "tls1.2", name: "TLS 1.2" },
  { pattern: /\bTLS[_ v]?1[._]1\b/gi, algorithmId: "tls1.1", name: "TLS 1.1" },
  { pattern: /\bTLS[_ v]?1[._]0\b|\bTLSv?1(?![._\d])/gi, algorithmId: "tls1.0", name: "TLS 1.0" },
]

const CIPHER_DIRECTIVE =
  /^[ \t]*(?:ssl_ciphers|sslciphersuite|ciphers|ciphersuites?|ssl\.cipher(?:\.suites?)?|ssl\.ciphersuites?|ssl\.enabled\.ciphers|cipher\.suites?|tls_ciphers)[ \t]*[:=]?[ \t]*(.+)$/gim

const SSH_DIRECTIVE = /^[ \t]*(KexAlgorithms|HostKeyAlgorithms|Ciphers|MACs)[ \t]+(.+)$/gim

const SUITE_SHAPE = /(AES|DES|RC4|CHACHA|CAMELLIA|SEED|ARIA|IDEA|NULL|GCM|CBC|MD5|SHA)/i

function suiteTokens(raw: string): string[] {
  return raw
    .split(/[\s:,;]+/)
    .map((t) => t.trim().replace(/^[+!@]/, ""))
    .filter((t) => t.length >= 8 && /[A-Z]/.test(t) && SUITE_SHAPE.test(t) && !/^!/.test(t))
}

/** Distinct protocol version tokens present in the file, in declaration order. */
function versionsIn(text: string): { token: VersionToken; index: number }[] {
  const hits: { token: VersionToken; index: number }[] = []
  const claimed = new Set<string>()
  for (const token of TLS_VERSIONS) {
    const re = new RegExp(token.pattern.source, token.pattern.flags)
    const m = re.exec(text)
    if (m && !claimed.has(token.name)) {
      claimed.add(token.name)
      hits.push({ token, index: m.index })
    }
  }
  return hits.sort((a, b) => a.index - b.index)
}

const MAX_PROTOCOL_ASSETS = 24

export function scanProtocols(file: string, source: string): { findings: RawFinding[] } {
  const cleaned = stripComments(source, "config")
  const offsets = lineIndex(source)
  const lines = source.split("\n")
  const findings: RawFinding[] = []
  const seen = new Set<string>()

  const push = (algorithmId: string, label: string, line: number, detail: string, mode?: string) => {
    if (seen.has(label) || findings.length >= MAX_PROTOCOL_ASSETS) return
    seen.add(label)
    const spec = getAlgorithm(algorithmId)
    findings.push({
      file,
      line,
      kind: "config",
      matched: label,
      snippet: (lines[line - 1] ?? "").trim().slice(0, 220),
      language: "config",
      algorithmId,
      keySize: keySizeFromString(label) ?? spec.defaultKeySize,
      mode,
      detail,
      confidence: "medium",
      detector: "protocol:config",
      assetType: "protocol",
      label,
    })
  }

  // ---------------------------------------------------------------- TLS / SSL
  const versions = versionsIn(cleaned)
  const suites: { value: string; line: number }[] = []
  let m: RegExpExecArray | null
  const cipherRe = new RegExp(CIPHER_DIRECTIVE.source, CIPHER_DIRECTIVE.flags)
  while ((m = cipherRe.exec(cleaned)) !== null) {
    const line = lineAt(offsets, m.index)
    for (const token of suiteTokens(m[1])) suites.push({ value: token, line })
  }
  // IANA-style suite names can appear without a recognised directive (Java
  // properties, Go/JS config objects, Helm values).
  const ianaRe = /\bTLS_[A-Z0-9_]{8,}\b/g
  while ((m = ianaRe.exec(cleaned)) !== null) {
    suites.push({ value: m[0], line: lineAt(offsets, m.index) })
  }

  const uniqueSuites = suites.filter((s, i) => suites.findIndex((o) => o.value === s.value) === i)

  if (versions.length && uniqueSuites.length) {
    for (const { token } of versions) {
      for (const suite of uniqueSuites) {
        push(
          token.algorithmId,
          `${token.name} — ${suite.value}`,
          suite.line,
          `negotiable protocol configuration declared in ${file.split("/").pop()}`,
          modeFromString(suite.value),
        )
      }
    }
  } else if (versions.length) {
    for (const { token, index } of versions) {
      push(
        token.algorithmId,
        `${token.name} — default suite set`,
        lineAt(offsets, index),
        `protocol version enabled in ${file.split("/").pop()}; cipher suites left to the library default`,
      )
    }
  }

  // ------------------------------------------------------------------- SSH
  const sshRe = new RegExp(SSH_DIRECTIVE.source, SSH_DIRECTIVE.flags)
  while ((m = sshRe.exec(cleaned)) !== null) {
    const line = lineAt(offsets, m.index)
    const directive = m[1]
    for (const token of m[2].split(/[\s,]+/).filter(Boolean).slice(0, 8)) {
      push(
        "ssh",
        `SSH ${directive} — ${token}`,
        line,
        `SSH transport parameter declared in ${file.split("/").pop()}`,
        modeFromString(token),
      )
    }
  }

  return { findings }
}

export function scanConfig(file: string, source: string): { findings: RawFinding[] } {
  const findings: RawFinding[] = []
  const cleaned = stripComments(source, "config")
  const offsets = lineIndex(source)
  const lines = source.split("\n")
  const seen = new Set<string>()

  for (const sig of CONFIG_SIGNATURES) {
    const re = new RegExp(sig.pattern.source, sig.pattern.flags.includes("g") ? sig.pattern.flags : sig.pattern.flags + "g")
    let m: RegExpExecArray | null
    while ((m = re.exec(cleaned)) !== null) {
      if (!m[0]) {
        re.lastIndex++
        continue
      }
      const line = lineAt(offsets, m.index)
      const dedupe = `${sig.algorithmId}:${line}:${m[0]}`
      if (seen.has(dedupe)) continue
      seen.add(dedupe)
      const spec = getAlgorithm(sig.algorithmId)
      findings.push({
        file,
        line,
        kind: "config",
        matched: m[0].trim(),
        snippet: (lines[line - 1] ?? "").trim().slice(0, 220),
        language: "config",
        algorithmId: sig.algorithmId,
        keySize: keySizeFromString(m[0]) ?? spec.defaultKeySize,
        detail: sig.library,
        confidence: "medium",
        detector: `config:${sig.id}`,
      })
    }
  }

  return { findings: [...findings, ...scanProtocols(file, source).findings] }
}

export function scanManifest(file: string, source: string): { findings: RawFinding[] } {
  const findings: RawFinding[] = []
  const lines = source.split("\n")
  const seen = new Set<string>()

  lines.forEach((raw, idx) => {
    const line = raw.trim()
    if (!line || line.startsWith("#") || line.startsWith("<!--")) return
    for (const dep of DEPENDENCY_SIGNATURES) {
      if (!dep.token.test(line)) continue
      const key = `${dep.library}`
      if (seen.has(key)) continue
      seen.add(key)
      const spec = getAlgorithm(dep.algorithmId)
      findings.push({
        file,
        line: idx + 1,
        kind: "dependency",
        matched: line.slice(0, 120),
        snippet: line.slice(0, 220),
        language: "manifest",
        algorithmId: dep.algorithmId,
        keySize: spec.defaultKeySize,
        detail: `declared dependency: ${dep.library}`,
        confidence: "medium",
        detector: "manifest:dependency",
      })
    }
  })

  return { findings }
}

/**
 * ECDAT secondary-language scanner (Java, JavaScript/TypeScript, Go, C#).
 *
 * Scoped down honestly: this is statement/library-level detection plus
 * `getInstance("...")`-style literal resolution. It is NOT call-graph precise
 * like the Python path, and every finding it produces is tagged
 * `confidence: "medium"` so the dashboard can show the difference instead of
 * hiding it.
 *
 * Comments are stripped (line-count preserving) before matching so that
 * "// TODO: replace RSA" never becomes a finding.
 */

import { REGEX_SIGNATURES, getAlgorithm, keySizeFromString, modeFromString, resolveAlgorithmString } from "../signatures"
import type { Language, RawFinding } from "../types"

/** Replace comment bodies with spaces, preserving offsets and line numbers. */
export function stripComments(source: string, language: Language): string {
  const out = source.split("")
  let i = 0
  const n = source.length
  let state: "code" | "line" | "block" | "single" | "double" | "backtick" = "code"

  while (i < n) {
    const c = source[i]
    const next = source[i + 1]
    if (state === "code") {
      if (c === "/" && next === "/") {
        state = "line"
        out[i] = " "
        out[i + 1] = " "
        i += 2
        continue
      }
      if (c === "/" && next === "*") {
        state = "block"
        out[i] = " "
        out[i + 1] = " "
        i += 2
        continue
      }
      if (c === "#" && (language === "config" || language === "manifest" || language === "python")) {
        state = "line"
        out[i] = " "
        i++
        continue
      }
      if (c === "'") state = "single"
      else if (c === '"') state = "double"
      else if (c === "`") state = "backtick"
      i++
      continue
    }
    if (state === "line") {
      if (c === "\n") state = "code"
      else out[i] = " "
      i++
      continue
    }
    if (state === "block") {
      if (c === "*" && next === "/") {
        out[i] = " "
        out[i + 1] = " "
        state = "code"
        i += 2
        continue
      }
      if (c !== "\n") out[i] = " "
      i++
      continue
    }
    // inside a string literal
    if (c === "\\") {
      i += 2
      continue
    }
    if ((state === "single" && c === "'") || (state === "double" && c === '"') || (state === "backtick" && c === "`")) {
      state = "code"
    }
    i++
  }

  return out.join("")
}

export function lineIndex(source: string): number[] {
  const offsets: number[] = [0]
  for (let i = 0; i < source.length; i++) if (source[i] === "\n") offsets.push(i + 1)
  return offsets
}

export function lineAt(offsets: number[], index: number): number {
  let lo = 0
  let hi = offsets.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1
    if (offsets[mid] <= index) lo = mid
    else hi = mid - 1
  }
  return lo + 1
}

export function scanWithRegex(file: string, source: string, language: Language): { findings: RawFinding[] } {
  const findings: RawFinding[] = []
  const cleaned = stripComments(source, language)
  const offsets = lineIndex(source)
  const lines = source.split("\n")
  const signatures = REGEX_SIGNATURES.filter((s) => s.language === language)

  for (const sig of signatures) {
    const re = new RegExp(sig.pattern.source, sig.pattern.flags.includes("g") ? sig.pattern.flags : sig.pattern.flags + "g")
    let m: RegExpExecArray | null
    while ((m = re.exec(cleaned)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++
        continue
      }
      const line = lineAt(offsets, m.index)
      let algorithmId = sig.algorithmId
      let keySize: number | undefined
      // F11 — the mode of operation is right there in the transformation string
      // (`AES/GCM/NoPadding`, `aes-256-cbc`); it used to be dropped when the
      // string was resolved down to an algorithm id.
      let mode: string | undefined

      if (sig.algorithmGroup !== undefined && m[sig.algorithmGroup]) {
        const resolved = resolveAlgorithmString(m[sig.algorithmGroup])
        if (resolved) algorithmId = resolved
        keySize = keySizeFromString(m[sig.algorithmGroup])
        mode = modeFromString(m[sig.algorithmGroup])
      }
      if (sig.keySizeGroup !== undefined && m[sig.keySizeGroup]) {
        keySize = Number(m[sig.keySizeGroup]) || keySize
      }
      if (algorithmId === "crypto-library" && sig.kind === "call") {
        // A getInstance string we could not resolve — keep it, but as a library.
        algorithmId = "crypto-library"
      }

      const spec = getAlgorithm(algorithmId)
      findings.push({
        file,
        line,
        kind: sig.kind === "import" ? "import" : "call",
        matched: m[0].trim().slice(0, 160),
        snippet: (lines[line - 1] ?? "").trim().slice(0, 220),
        language,
        algorithmId,
        keySize: keySize ?? spec.defaultKeySize,
        mode,
        detail: sig.library,
        confidence: sig.kind === "import" ? "medium" : "medium",
        detector: `${language}:regex/${sig.id}`,
      })
    }
  }

  return { findings }
}

/**
 * ECDAT Python scanner.
 *
 * Why not regex: a regex over raw source matches algorithm names inside
 * comments, docstrings and log messages, and misses calls that are split over
 * several lines. The PRD calls for AST-grade precision; because ECDAT runs in a
 * TypeScript runtime (no CPython `ast` module available in the request path),
 * this module implements the equivalent guarantees with a real Python
 * **token-stream parser**:
 *
 *   1. A lexer that understands comments, all string prefixes (r/b/u/f and
 *      combinations), triple-quoted strings, escapes and line continuations.
 *      Comments and string *contents* can never produce a finding.
 *   2. A statement-level import parser that builds a binding table
 *      (`import Crypto.PublicKey.RSA as R` -> `R` = `Crypto.PublicKey.RSA`).
 *   3. A call-expression matcher that reconstructs the fully-qualified dotted
 *      callee (equivalent to `ast.unparse(node.func)`), resolves it through the
 *      binding table, and matches it against the signature database.
 *   4. Argument extraction for statically-known key sizes and algorithm-name
 *      strings (`RSA.generate(2048)`, `key_size=4096`, `jwt.encode(..., algorithm="RS256")`).
 *
 * Known limitation (shared with every static analyser, including IBM Hyperion):
 * dynamically constructed calls such as `getattr(RSA, "generate")` are not
 * resolvable. These are reported in the scan warnings, not silently dropped.
 */

import {
  PYTHON_CALLS,
  PYTHON_IMPORTS,
  getAlgorithm,
  keySizeFromString,
  resolveAlgorithmString,
} from "../signatures"
import type { RawFinding } from "../types"

type TokKind = "name" | "string" | "number" | "op" | "newline"

interface Token {
  kind: TokKind
  value: string
  line: number
}

const STRING_PREFIXES = new Set(["r", "b", "u", "f", "rb", "br", "fr", "rf", "bf", "fb"])

export function tokenizePython(src: string): { tokens: Token[]; dynamicCalls: number } {
  const tokens: Token[] = []
  let i = 0
  let line = 1
  let dynamicCalls = 0
  const n = src.length

  const isIdStart = (c: string) => /[A-Za-z_]/.test(c)
  const isIdPart = (c: string) => /[A-Za-z0-9_]/.test(c)

  while (i < n) {
    const c = src[i]

    if (c === "\n") {
      tokens.push({ kind: "newline", value: "\n", line })
      line++
      i++
      continue
    }
    if (c === "\r") {
      i++
      continue
    }
    if (c === " " || c === "\t" || c === "\f") {
      i++
      continue
    }
    // Explicit line continuation.
    if (c === "\\" && src[i + 1] === "\n") {
      line++
      i += 2
      continue
    }
    // Comment — consumed without emitting a token.
    if (c === "#") {
      while (i < n && src[i] !== "\n") i++
      continue
    }

    // String literal, optionally prefixed.
    let prefixLen = 0
    if (isIdStart(c)) {
      let j = i
      let ident = ""
      while (j < n && isIdPart(src[j])) {
        ident += src[j]
        j++
      }
      if ((src[j] === '"' || src[j] === "'") && STRING_PREFIXES.has(ident.toLowerCase())) {
        prefixLen = ident.length
      } else {
        tokens.push({ kind: "name", value: ident, line })
        i = j
        continue
      }
    }

    if (c === '"' || c === "'" || prefixLen > 0) {
      const qStart = i + prefixLen
      const quote = src[qStart]
      const triple = src.slice(qStart, qStart + 3) === quote.repeat(3)
      const delim = triple ? quote.repeat(3) : quote
      const startLine = line
      let k = qStart + delim.length
      let value = ""
      const raw = prefixLen > 0 && /r/i.test(src.slice(i, i + prefixLen))
      while (k < n) {
        if (!raw && src[k] === "\\") {
          if (src[k + 1] === "\n") line++
          value += src[k + 1] ?? ""
          k += 2
          continue
        }
        if (src.slice(k, k + delim.length) === delim) {
          k += delim.length
          break
        }
        if (src[k] === "\n") line++
        value += src[k]
        k++
      }
      tokens.push({ kind: "string", value, line: startLine })
      i = k
      continue
    }

    if (/[0-9]/.test(c)) {
      let j = i
      let num = ""
      while (j < n && /[0-9a-fA-FxXoObB_.]/.test(src[j])) {
        num += src[j]
        j++
      }
      tokens.push({ kind: "number", value: num, line })
      i = j
      continue
    }

    tokens.push({ kind: "op", value: c, line })
    i++
  }

  // Count `getattr(` occurrences on the token stream for the honest-limitation warning.
  for (let t = 0; t < tokens.length - 1; t++) {
    if (tokens[t].kind === "name" && tokens[t].value === "getattr" && tokens[t + 1].value === "(") {
      dynamicCalls++
    }
  }

  return { tokens, dynamicCalls }
}

interface ImportBinding {
  /** Local name in scope. */
  alias: string
  /** Fully-qualified dotted module path. */
  full: string
  line: number
}

function parseImports(tokens: Token[]): { bindings: ImportBinding[]; statements: { full: string; line: number }[] } {
  const bindings: ImportBinding[] = []
  const statements: { full: string; line: number }[] = []

  const readDotted = (start: number): { name: string; next: number } => {
    let idx = start
    let name = ""
    while (idx < tokens.length) {
      const t = tokens[idx]
      if (t.kind === "name") {
        name += t.value
        idx++
      } else if (t.kind === "op" && t.value === ".") {
        name += "."
        idx++
      } else break
    }
    return { name, next: idx }
  }

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]
    const atStatementStart = i === 0 || tokens[i - 1].kind === "newline" || tokens[i - 1].value === ";"
    if (t.kind !== "name" || !atStatementStart) continue

    // `import a.b as c, d`
    if (t.value === "import") {
      let idx = i + 1
      while (idx < tokens.length && tokens[idx].kind !== "newline") {
        const { name, next } = readDotted(idx)
        if (!name) break
        idx = next
        let alias = name.split(".")[0]
        if (tokens[idx]?.kind === "name" && tokens[idx].value === "as") {
          alias = tokens[idx + 1]?.value ?? alias
          idx += 2
        }
        statements.push({ full: name, line: t.line })
        bindings.push({ alias, full: name, line: t.line })
        if (tokens[idx]?.value === ",") idx++
        else break
      }
      i = idx
      continue
    }

    // `from a.b import c as d, e`
    if (t.value === "from") {
      const { name: moduleName, next } = readDotted(i + 1)
      let idx = next
      if (tokens[idx]?.kind === "name" && tokens[idx].value === "import") {
        idx++
        if (tokens[idx]?.value === "(") idx++
        while (idx < tokens.length && tokens[idx].kind !== "newline") {
          if (tokens[idx].value === ")") {
            idx++
            break
          }
          const target = tokens[idx]
          if (target.kind !== "name") {
            idx++
            continue
          }
          idx++
          let alias = target.value
          if (tokens[idx]?.kind === "name" && tokens[idx].value === "as") {
            alias = tokens[idx + 1]?.value ?? alias
            idx += 2
          }
          const full = target.value === "*" ? moduleName : `${moduleName}.${target.value}`
          statements.push({ full, line: t.line })
          bindings.push({ alias, full, line: t.line })
          if (tokens[idx]?.value === ",") idx++
        }
      }
      i = idx
      continue
    }
  }

  return { bindings, statements }
}

interface CallSite {
  /** Dotted callee exactly as written. */
  raw: string
  /** Callee after alias resolution. */
  resolved: string
  line: number
  args: Token[][]
  /** `keyword=` pairs collected from the argument list. */
  keywords: Record<string, Token[]>
}

function collectCalls(tokens: Token[], bindings: ImportBinding[]): CallSite[] {
  const bindingMap = new Map<string, string>()
  for (const b of bindings) bindingMap.set(b.alias, b.full)

  const calls: CallSite[] = []

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]
    if (t.kind !== "name") continue
    // Only start an atom when the previous token can't continue a dotted chain.
    const prev = tokens[i - 1]
    if (prev && ((prev.kind === "op" && prev.value === ".") || prev.kind === "name")) {
      if (prev?.kind === "name" && ["import", "from", "as", "def", "class"].includes(prev.value)) {
        // keep going: `def foo(` should not be treated as a call
        continue
      }
      if (prev?.kind === "op" && prev.value === ".") continue
    }

    // Read the dotted chain.
    let idx = i
    const parts: string[] = []
    while (idx < tokens.length) {
      if (tokens[idx].kind === "name") {
        parts.push(tokens[idx].value)
        idx++
        if (tokens[idx]?.kind === "op" && tokens[idx].value === "." ) {
          idx++
          continue
        }
        break
      }
      break
    }
    if (!parts.length) continue
    if (tokens[idx]?.value !== "(") {
      i = idx - 1
      continue
    }

    const raw = parts.join(".")
    // Resolve through the import binding table.
    let resolved = raw
    const head = parts[0]
    if (bindingMap.has(head)) {
      const full = bindingMap.get(head)!
      resolved = [full, ...parts.slice(1)].join(".")
    }

    // Argument scan to the matching close paren.
    const args: Token[][] = []
    const keywords: Record<string, Token[]> = {}
    let depth = 0
    let current: Token[] = []
    let j = idx
    for (; j < tokens.length; j++) {
      const a = tokens[j]
      if (a.kind === "op" && (a.value === "(" || a.value === "[" || a.value === "{")) {
        depth++
        if (depth === 1) continue
      }
      if (a.kind === "op" && (a.value === ")" || a.value === "]" || a.value === "}")) {
        depth--
        if (depth === 0) {
          if (current.length) args.push(current)
          break
        }
      }
      if (depth === 1 && a.kind === "op" && a.value === ",") {
        if (current.length) args.push(current)
        current = []
        continue
      }
      if (depth >= 1) current.push(a)
    }

    for (const arg of args) {
      if (arg.length >= 3 && arg[0].kind === "name" && arg[1].value === "=") {
        keywords[arg[0].value] = arg.slice(2)
      }
    }

    calls.push({ raw, resolved, line: t.line, args, keywords })
    i = j
  }

  return calls
}

function numberFrom(tokens: Token[] | undefined): number | undefined {
  if (!tokens) return undefined
  const t = tokens.find((x) => x.kind === "number")
  if (!t) return undefined
  const v = Number(t.value.replace(/_/g, ""))
  return Number.isFinite(v) ? v : undefined
}

function stringFrom(tokens: Token[] | undefined): string | undefined {
  return tokens?.find((x) => x.kind === "string")?.value
}

const KEY_SIZE_KEYWORDS = ["key_size", "bits", "modulus_length", "keysize", "length", "generator_size"]
const ALGORITHM_KEYWORDS = ["algorithm", "algorithms", "name", "hash_name", "digestmod", "digest"]

/** Match a resolved dotted callee against the signature DB (longest suffix wins). */
function matchCallSignature(resolved: string, raw: string) {
  const candidates = new Set<string>([resolved, raw])
  const push = (s: string) => {
    const seg = s.split(".")
    for (let take = seg.length; take >= 1; take--) candidates.add(seg.slice(seg.length - take).join("."))
  }
  push(resolved)
  push(raw)

  let best: (typeof PYTHON_CALLS)[number] | undefined
  let bestLen = -1
  for (const sig of PYTHON_CALLS) {
    if (candidates.has(sig.call)) {
      const len = sig.call.split(".").length
      if (len > bestLen) {
        best = sig
        bestLen = len
      }
    }
  }
  return best
}

export function scanPython(file: string, source: string): { findings: RawFinding[]; warnings: string[] } {
  const findings: RawFinding[] = []
  const warnings: string[] = []
  const lines = source.split("\n")
  const snippet = (line: number) => (lines[line - 1] ?? "").trim().slice(0, 220)

  const { tokens, dynamicCalls } = tokenizePython(source)
  const { bindings, statements } = parseImports(tokens)

  // ---------------------------------------------------------------- imports
  for (const stmt of statements) {
    const root = stmt.full.split(".")[0]
    const sig = PYTHON_IMPORTS.find((s) => s.module === root || stmt.full.startsWith(`${s.module}.`))
    if (!sig) continue
    findings.push({
      file,
      line: stmt.line,
      kind: "import",
      matched: stmt.full,
      snippet: snippet(stmt.line),
      language: "python",
      algorithmId: sig.algorithmId,
      detail: sig.note ? `${sig.library} — ${sig.note}` : sig.library,
      confidence: "high",
      detector: "python:token-import",
    })
  }

  // ------------------------------------------------------------------ calls
  const calls = collectCalls(tokens, bindings)
  for (const call of calls) {
    const sig = matchCallSignature(call.resolved, call.raw)
    if (!sig) continue

    let algorithmId = sig.algorithmId
    let keySize: number | undefined

    // Algorithm-name arguments (hashlib.new("md5"), jwt.encode(..., algorithm="RS256")).
    let algString: string | undefined
    if (sig.algorithmArg !== undefined) algString = stringFrom(call.args[sig.algorithmArg])
    for (const kw of ALGORITHM_KEYWORDS) {
      if (!algString && call.keywords[kw]) algString = stringFrom(call.keywords[kw])
    }
    if (algString) {
      const resolvedAlg = resolveAlgorithmString(algString)
      if (resolvedAlg) algorithmId = resolvedAlg
      keySize = keySizeFromString(algString)
    }

    // Key size: positional then keyword.
    if (sig.keySizeArg !== undefined && sig.keySizeArg >= 0) {
      keySize = numberFrom(call.args[sig.keySizeArg]) ?? keySize
    }
    for (const kw of KEY_SIZE_KEYWORDS) {
      if (call.keywords[kw]) keySize = numberFrom(call.keywords[kw]) ?? keySize
    }
    // `ec.generate_private_key(ec.SECP256R1())` — curve implies the key size.
    const curveTok = call.args.flat().find((t) => t.kind === "name" && /^SECP(\d{3})R1$/.test(t.value))
    if (curveTok) keySize = Number(curveTok.value.match(/\d{3}/)![0])

    const spec = getAlgorithm(algorithmId)
    findings.push({
      file,
      line: call.line,
      kind: "call",
      matched: call.resolved === call.raw ? call.raw : `${call.raw} → ${call.resolved}`,
      snippet: snippet(call.line),
      language: "python",
      algorithmId,
      keySize: keySize ?? spec.defaultKeySize,
      detail: sig.library,
      confidence: "high",
      detector: "python:token-call",
    })
  }

  if (dynamicCalls > 0) {
    warnings.push(
      `${file}: ${dynamicCalls} dynamic \`getattr(...)\` call site(s) cannot be statically resolved (documented limitation of static analysis).`,
    )
  }

  return { findings, warnings }
}

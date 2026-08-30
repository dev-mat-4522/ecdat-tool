/**
 * ECDAT scanner dispatcher — routes each file to the right detector.
 *
 * The routing table is the only place that knows which detectors apply to which
 * files. New artefact classes (F1 keys, F3/F4 references, F9 JARs) are wired in
 * here rather than inside the language scanners, which keeps the language
 * scanners free of cross-imports.
 */

import type { Language, RawFinding } from "../types"
import { scanCertificate } from "./certificate"
import { scanConfig, scanManifest } from "./config"
import { isJarPath, scanJar } from "./jar"
import { isKeyFile, scanKeyFile, scanKeyLiterals } from "./keys"
import { scanReferences } from "./references"
import { scanWithRegex, stripComments } from "./regex-langs"
import { scanPython } from "./python"

const MANIFEST_NAMES = new Set([
  "requirements.txt",
  "requirements-dev.txt",
  "pyproject.toml",
  "pipfile",
  "setup.py",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "package.json",
  "go.mod",
  "cargo.toml",
  "gemfile",
])

/** F10 — a Dockerfile is scanned as configuration text, never built or pulled. */
const DOCKER_NAMES = /^(dockerfile|containerfile)(\..+)?$|\.dockerfile$/i

const CONFIG_EXT = new Set([".yaml", ".yml", ".conf", ".cfg", ".ini", ".properties", ".toml", ".xml", ".env", ".tf", ".tfvars"])
/** `.key` moved out of here in F1: a key file is a key artefact, not a cert. */
const CERT_EXT = new Set([".pem", ".crt", ".cer", ".pub"])

const LANG_BY_EXT: Record<string, Language> = {
  ".py": "python",
  ".pyi": "python",
  ".java": "java",
  ".kt": "java",
  ".scala": "java",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "javascript",
  ".tsx": "javascript",
  ".go": "go",
  ".cs": "csharp",
}

export function extensionOf(path: string): string {
  const base = path.split("/").pop() ?? path
  const dot = base.lastIndexOf(".")
  return dot <= 0 ? "" : base.slice(dot).toLowerCase()
}

export function classifyFile(path: string): Language | null {
  const base = (path.split("/").pop() ?? path).toLowerCase()
  const ext = extensionOf(path)
  if (MANIFEST_NAMES.has(base)) return "manifest"
  if (DOCKER_NAMES.test(base)) return "config"
  if (isKeyFile(path)) return "key"
  if (isJarPath(path)) return "binary"
  if (CERT_EXT.has(ext)) return "certificate"
  if (LANG_BY_EXT[ext]) return LANG_BY_EXT[ext]
  if (CONFIG_EXT.has(ext)) return "config"
  return null
}

/** True when ECDAT knows how to scan this path at all. */
export function isScannable(path: string): boolean {
  if (/(^|\/)(node_modules|\.git|dist|build|\.next|venv|\.venv|__pycache__|vendor|site-packages)\//.test(path)) {
    return false
  }
  return classifyFile(path) !== null
}

/** True when the file must reach the scanner byte-preserved (latin1), not UTF-8. */
export function isBinaryTarget(path: string): boolean {
  return isJarPath(path)
}

export interface FileScanOutcome {
  findings: RawFinding[]
  warnings: string[]
  language: Language
  error?: string
}

/** PEM private-key material can arrive in a `.pem`/`.crt` file too. */
const PEM_PRIVATE = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/
const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----/

export function scanFile(path: string, content: string): FileScanOutcome {
  const language = classifyFile(path) ?? "unknown"
  try {
    switch (language) {
      case "python": {
        const { findings, warnings } = scanPython(path, content)
        const cleaned = stripComments(content, "python")
        return {
          findings: [...findings, ...scanReferences(path, content, "python"), ...scanKeyLiterals(path, content, cleaned)],
          warnings,
          language,
        }
      }
      case "key": {
        const { findings, warnings } = scanKeyFile(path, content)
        return { findings, warnings, language }
      }
      case "binary": {
        const { findings, warnings } = scanJar(path, content)
        return { findings, warnings, language }
      }
      case "certificate": {
        // A `.pem` holding only a private key is key material, not a certificate.
        if (PEM_PRIVATE.test(content) && !PEM_CERTIFICATE.test(content)) {
          const { findings, warnings } = scanKeyFile(path, content)
          return { findings, warnings, language: "key" }
        }
        const { findings, warnings } = scanCertificate(path, content)
        const keys = PEM_PRIVATE.test(content) ? scanKeyLiterals(path, content) : []
        return { findings: [...findings, ...keys], warnings, language }
      }
      case "config": {
        const cleaned = stripComments(content, "config")
        return {
          findings: [
            ...scanConfig(path, content).findings,
            ...scanReferences(path, content, "config"),
            ...scanKeyLiterals(path, content, cleaned),
          ],
          warnings: [],
          language,
        }
      }
      case "manifest": {
        const manifest = scanManifest(path, content)
        // package.json / pom.xml also benefit from the language regexes.
        const extra = path.toLowerCase().endsWith(".xml") ? scanWithRegex(path, content, "java").findings : []
        return {
          findings: [...manifest.findings, ...extra, ...scanReferences(path, content, "manifest")],
          warnings: [],
          language,
        }
      }
      case "java":
      case "javascript":
      case "go":
      case "csharp": {
        const cleaned = stripComments(content, language)
        return {
          findings: [
            ...scanWithRegex(path, content, language).findings,
            ...scanReferences(path, content, language),
            ...scanKeyLiterals(path, content, cleaned),
          ],
          warnings: [],
          language,
        }
      }
      default:
        return { findings: [], warnings: [], language }
    }
  } catch (error) {
    return {
      findings: [],
      warnings: [],
      language,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

export {
  scanPython,
  scanCertificate,
  scanConfig,
  scanManifest,
  scanWithRegex,
  scanReferences,
  scanKeyFile,
  scanKeyLiterals,
  scanJar,
  isKeyFile,
  isJarPath,
}

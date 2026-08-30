/**
 * ECDAT container image input (F10).
 *
 * This is an *input extraction* step, not a new detector. It turns a
 * `docker save` tarball (Docker v1 layout or OCI layout) into the same
 * `{ path, content }` targets the GitHub and Local Files paths already produce,
 * then hands them to the existing file-walk and the existing detectors.
 *
 * Scope, stated in the UI on every finding it produces:
 *   - only files inside the image's filesystem layers are read
 *   - container runtime configuration, base-image provenance and registry
 *     metadata are not inspected
 *   - a `Dockerfile` on its own is scanned as configuration text; ECDAT does not
 *     pull or build the base image it references
 *
 * Both the tar parser and the gzip step are standard-library only: `tar` is a
 * 512-byte-header format and `DecompressionStream` ships in Node 18+ and every
 * current browser.
 */

const BLOCK = 512
const MAX_FILES = 600
const MAX_FILE_BYTES = 400_000
const MAX_LAYER_BYTES = 64 * 1024 * 1024

export interface ExtractedFile {
  path: string
  content: string
  size: number
}

export interface ContainerExtraction {
  files: ExtractedFile[]
  warnings: string[]
  layers: number
  entriesSeen: number
}

function isGzip(bytes: Uint8Array): boolean {
  return bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b
}

async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes as unknown as BlobPart]).stream().pipeThrough(new DecompressionStream("gzip"))
  const buffer = await new Response(stream).arrayBuffer()
  return new Uint8Array(buffer)
}

const ascii = new TextDecoder("utf-8", { fatal: false })
const latin1 = new TextDecoder("latin1")

function readString(bytes: Uint8Array, offset: number, length: number): string {
  let end = offset
  const limit = Math.min(offset + length, bytes.length)
  while (end < limit && bytes[end] !== 0) end++
  return ascii.decode(bytes.subarray(offset, end))
}

/** Tar sizes are octal, except GNU's base-256 encoding for very large files. */
function readSize(bytes: Uint8Array, offset: number): number {
  if (bytes[offset] & 0x80) {
    let value = 0
    for (let i = offset + 1; i < offset + 12; i++) value = value * 256 + bytes[i]
    return value
  }
  const raw = readString(bytes, offset, 12).trim()
  const parsed = Number.parseInt(raw, 8)
  return Number.isFinite(parsed) ? parsed : 0
}

export interface TarEntry {
  name: string
  type: string
  bytes: Uint8Array
}

/** Minimal ustar/GNU reader: regular files and GNU long names only. */
export function readTar(bytes: Uint8Array): TarEntry[] {
  const entries: TarEntry[] = []
  let offset = 0
  let longName: string | null = null

  while (offset + BLOCK <= bytes.length) {
    // Two consecutive zero blocks terminate the archive.
    if (bytes[offset] === 0) {
      offset += BLOCK
      continue
    }
    const name = readString(bytes, offset, 100)
    const size = readSize(bytes, offset + 124)
    const type = String.fromCharCode(bytes[offset + 156] || 0x30)
    const prefix = readString(bytes, offset + 345, 155)
    const dataStart = offset + BLOCK
    const dataEnd = Math.min(dataStart + size, bytes.length)

    if (type === "L") {
      longName = ascii.decode(bytes.subarray(dataStart, dataEnd)).replace(/\0+$/, "")
    } else if (type === "0" || type === "\0" || type === "7") {
      const full = longName ?? (prefix ? `${prefix}/${name}` : name)
      longName = null
      entries.push({ name: full, type, bytes: bytes.subarray(dataStart, dataEnd) })
    } else {
      longName = null
    }

    offset = dataStart + Math.ceil(size / BLOCK) * BLOCK
    if (size === 0 && type !== "L" && type !== "0" && type !== "\0") offset = dataStart
  }

  return entries
}

/** Docker v1 (`<id>/layer.tar`) and OCI (`blobs/sha256/<digest>`) both land here. */
function looksLikeLayer(name: string): boolean {
  if (/(^|\/)layer\.tar$/i.test(name)) return true
  if (/\.tar(\.gz)?$/i.test(name)) return true
  if (/^blobs\/sha256\/[0-9a-f]{16,}$/i.test(name)) return true
  return false
}

const SKIP_METADATA = /^(manifest\.json|repositories|oci-layout|index\.json|[0-9a-f]{64}\.json)$/i

export async function extractContainerImage(
  bytes: Uint8Array,
  isScannablePath: (path: string) => boolean,
  isBinaryPath: (path: string) => boolean = () => false,
): Promise<ContainerExtraction> {
  const warnings: string[] = []
  const files: ExtractedFile[] = []
  const seen = new Set<string>()
  let layers = 0
  let entriesSeen = 0

  let outer: Uint8Array
  try {
    outer = isGzip(bytes) ? await gunzip(bytes) : bytes
  } catch {
    return { files, warnings: ["Could not decompress the uploaded archive (expected a tar or tar.gz)."], layers, entriesSeen }
  }

  const outerEntries = readTar(outer)
  if (!outerEntries.length) {
    return {
      files,
      warnings: ["No tar entries found — expected the output of `docker save` or an OCI image layout."],
      layers,
      entriesSeen,
    }
  }

  for (const entry of outerEntries) {
    entriesSeen++
    const base = entry.name.split("/").pop() ?? entry.name
    if (SKIP_METADATA.test(base)) continue
    if (!looksLikeLayer(entry.name)) continue
    if (entry.bytes.length > MAX_LAYER_BYTES) {
      warnings.push(`Layer ${base} skipped: ${(entry.bytes.length / 1024 / 1024).toFixed(0)} MB exceeds the 64 MB limit.`)
      continue
    }

    let layerBytes: Uint8Array
    try {
      layerBytes = isGzip(entry.bytes) ? await gunzip(entry.bytes) : entry.bytes
    } catch {
      continue
    }
    const inner = readTar(layerBytes)
    if (!inner.length) continue
    layers++

    for (const file of inner) {
      if (files.length >= MAX_FILES) break
      // Whiteout markers record deletions in the layer above; they are not files.
      if (file.name.includes(".wh.")) continue
      const path = file.name.replace(/^\.\//, "")
      if (!path || path.endsWith("/")) continue
      if (!isScannablePath(path)) continue
      if (file.bytes.length === 0 || file.bytes.length > MAX_FILE_BYTES) continue
      if (seen.has(path)) continue
      seen.add(path)
      files.push({
        path,
        content: isBinaryPath(path) ? latin1.decode(file.bytes) : ascii.decode(file.bytes),
        size: file.bytes.length,
      })
    }
  }

  if (!layers) {
    warnings.push("No filesystem layers could be read from the archive; nothing was scanned.")
  }
  if (files.length >= MAX_FILES) {
    warnings.push(`Extraction capped at ${MAX_FILES} scannable files from the image layers.`)
  }

  return { files, warnings, layers, entriesSeen }
}

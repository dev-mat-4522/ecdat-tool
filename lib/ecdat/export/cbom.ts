/**
 * CycloneDX 1.6 CBOM export.
 *
 * ECDAT emits a real `cryptographic-asset` component per finding using the
 * ECMA-424 / CycloneDX 1.6 `cryptoProperties` block, so the output loads in any
 * CycloneDX-aware tool (including IBM CBOMkit and Dependency-Track) rather than
 * being an ECDAT-only JSON shape. ECDAT-specific analysis (Mosca inputs, the
 * risk tier, the PQC recommendation) is attached as namespaced `properties`,
 * which is the spec-sanctioned extension point.
 */

import type { CryptoAsset, ScanResult } from "../types"

const NS = "ecdat"

function bomRef(asset: CryptoAsset) {
  return `crypto/${asset.algorithmId}/${asset.id}`
}

/** CycloneDX `assetType` enum is a small closed set — map ours onto it. */
function cdxAssetType(asset: CryptoAsset): string {
  switch (asset.type) {
    case "certificate":
      return "certificate"
    case "protocol":
      return "protocol"
    case "related-crypto-material":
    // F1 keys are key material; F3/F4 references have no closer enum member, so
    // they ride on `related-crypto-material` with the precise kind kept in the
    // namespaced `ecdat:artefact-type` property rather than inventing an enum value.
    case "key":
    case "hardware-module":
    case "cloud-service":
      return "related-crypto-material"
    case "library":
      return "algorithm"
    default:
      return "algorithm"
  }
}

/** CycloneDX `relatedCryptoMaterialType` enum. */
function cdxMaterialType(asset: CryptoAsset): string {
  if (asset.type === "hardware-module" || asset.type === "cloud-service") return "other"
  const name = `${asset.name} ${asset.detail ?? ""}`.toLowerCase()
  if (name.includes("private")) return "private-key"
  if (name.includes("public")) return "public-key"
  if (asset.algorithmId === "hardcoded-key") return "secret-key"
  if (asset.algorithmId === "keystore" || name.includes("keystore") || name.includes("truststore")) return "key"
  return "key"
}

/** F11 — CycloneDX `algorithmProperties.mode` enum. */
function cdxMode(mode: string): string | undefined {
  switch (mode.toUpperCase()) {
    case "GCM":
    case "GCM-SIV":
      return "gcm"
    case "CBC":
      return "cbc"
    case "ECB":
      return "ecb"
    case "CTR":
      return "ctr"
    case "CCM":
      return "ccm"
    case "CFB":
    case "CFB8":
      return "cfb"
    case "OFB":
      return "ofb"
    case "UNSPECIFIED":
      return undefined
    default:
      return "other"
  }
}

/** CycloneDX `primitive` enum. */
function cdxPrimitive(asset: CryptoAsset): string {
  const allowed = new Set([
    "drbg",
    "mac",
    "block-cipher",
    "stream-cipher",
    "signature",
    "hash",
    "pke",
    "xof",
    "kdf",
    "key-agree",
    "kem",
    "ae",
    "combiner",
    "other",
    "unknown",
  ])
  const map: Record<string, string> = {
    signature: "signature",
    "key-agreement": "key-agree",
    "key-encapsulation": "kem",
    "public-key-encryption": "pke",
    encryption: "block-cipher",
    hash: "hash",
    mac: "mac",
    kdf: "kdf",
    drbg: "drbg",
    protocol: "other",
    other: "other",
  }
  const value = map[asset.primitive] ?? "unknown"
  return allowed.has(value) ? value : "unknown"
}

function cryptoFunctions(asset: CryptoAsset): string[] {
  switch (asset.primitive) {
    case "signature":
      return ["sign", "verify", "keygen"]
    case "key-agreement":
      return ["keygen", "key-derive"]
    case "key-encapsulation":
      return ["encapsulate", "decapsulate", "keygen"]
    case "public-key-encryption":
      return ["encrypt", "decrypt", "keygen"]
    case "encryption":
      return ["encrypt", "decrypt"]
    case "hash":
      return ["digest"]
    case "mac":
      return ["tag", "verify"]
    case "kdf":
      return ["key-derive"]
    case "drbg":
      return ["generate"]
    default:
      return ["other"]
  }
}

function prop(name: string, value: string | number | boolean) {
  return { name: `${NS}:${name}`, value: String(value) }
}

function assetToComponent(asset: CryptoAsset) {
  const properties = [
    prop("risk-tier", asset.riskTier),
    prop("quantum-vulnerable", asset.quantumVulnerable),
    prop("grover-weakened", asset.groverWeakened),
    prop("classically-broken", asset.classicallyBroken),
    prop("mosca:x-data-lifetime-years", asset.mosca.x),
    prop("mosca:y-migration-years", asset.mosca.y),
    prop("mosca:z-crqc-years", asset.mosca.z),
    prop("mosca:margin-years", asset.mosca.margin),
    prop("mosca:explanation", asset.mosca.explanation),
    prop("business-criticality", asset.classification.businessCriticality),
    prop("classification-rationale", asset.classification.rationale),
    // F11 / F7 / F5 / F6 — schema fields promoted out of free text.
    prop("mode", asset.mode),
    prop("artefact-type", asset.type),
    prop("sensitive-data", asset.classification.sensitiveData),
    prop("sensitive-data-rationale", asset.classification.sensitiveDataRationale || "no sensitive-data indicator in path"),
    prop("facing", asset.classification.facing),
    prop("facing-source", asset.classification.facingSource),
    prop("system", asset.systemKey),
    prop("detector", asset.detector),
    prop("detection-confidence", asset.confidence),
    prop("evidence-kind", asset.evidence),
    prop("occurrences", asset.occurrences),
    prop("locations", asset.locations.join(", ")),
  ]

  // U5 — the scope caveat travels with the export, not just the dashboard.
  if (asset.scopeNote) properties.push(prop("scope-note", asset.scopeNote))

  if (asset.detail) properties.push(prop("detail", asset.detail))
  if (asset.recommendation) {
    properties.push(prop("recommendation:primary", asset.recommendation.primary))
    properties.push(prop("recommendation:standard", asset.recommendation.standard))
    if (asset.recommendation.hybrid) properties.push(prop("recommendation:hybrid", asset.recommendation.hybrid))
    if (asset.recommendation.conservative)
      properties.push(prop("recommendation:conservative", asset.recommendation.conservative))
    properties.push(prop("recommendation:notes", asset.recommendation.notes))
    properties.push(prop("recommendation:complexity", asset.recommendation.complexity))
    // F8 — the latency/size trade-off and whether it changed the choice.
    if (asset.recommendation.performanceNote)
      properties.push(prop("recommendation:performance-note", asset.recommendation.performanceNote))
    if (asset.recommendation.latencyWeighted)
      properties.push(prop("recommendation:latency-weighted", true))
  }

  const algorithmProperties: Record<string, unknown> = {
    primitive: cdxPrimitive(asset),
    executionEnvironment: "software-plain-ram",
    implementationPlatform: "generic",
    cryptoFunctions: cryptoFunctions(asset),
    nistQuantumSecurityLevel: asset.quantumVulnerable ? 0 : asset.family === "PQC" ? 3 : 1,
  }
  if (asset.keySize) {
    algorithmProperties.parameterSetIdentifier = String(asset.keySize)
    algorithmProperties.classicalSecurityLevel = asset.classicallyBroken ? 0 : Math.min(256, asset.keySize)
  }
  // F11 — mode of operation as a first-class CycloneDX field.
  const mode = cdxMode(asset.mode)
  if (mode) algorithmProperties.mode = mode

  const cryptoProperties: Record<string, unknown> = {
    assetType: cdxAssetType(asset),
    oid: undefined,
  }

  if (cdxAssetType(asset) === "algorithm") {
    cryptoProperties.algorithmProperties = algorithmProperties
  } else if (cdxAssetType(asset) === "certificate") {
    cryptoProperties.certificateProperties = {
      subjectName: asset.detail?.split(";")[0]?.replace(/^subject:\s*/i, "") ?? asset.name,
      certificateAlgorithm: asset.name,
      certificateFormat: "X.509",
      certificateExtension: asset.file.split(".").pop() ?? "pem",
    }
  } else if (cdxAssetType(asset) === "protocol") {
    cryptoProperties.protocolProperties = {
      type: asset.family.toLowerCase() === "tls" ? "tls" : "other",
      version: asset.name.replace(/^[^\d]*/, "") || undefined,
    }
  } else {
    cryptoProperties.relatedCryptoMaterialProperties = {
      type: cdxMaterialType(asset),
      size: asset.keySize,
      state: undefined,
    }
  }

  return {
    type: "cryptographic-asset",
    "bom-ref": bomRef(asset),
    name: asset.name,
    description: `${asset.family} ${asset.primitive} detected by ${asset.detector} (${asset.nistStatus})`,
    evidence: {
      occurrences: asset.locations.map((location) => {
        const [file, line] = location.split(/:(?=\d+$)/)
        return { location: file, line: Number(line) || asset.line }
      }),
    },
    cryptoProperties,
    properties,
  }
}

export function buildCbom(scan: ScanResult) {
  const serial = `urn:uuid:${uuidFrom(scan.scanId)}`
  const components = scan.assets.map(assetToComponent)

  // Dependency edges: every asset depends on nothing, but the root component
  // depends on all of them. This is what Dependency-Track expects.
  const dependencies = [
    { ref: "root-application", dependsOn: components.map((c) => c["bom-ref"]) },
    ...components.map((c) => ({ ref: c["bom-ref"], dependsOn: [] as string[] })),
  ]

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: serial,
    version: 1,
    metadata: {
      timestamp: scan.startedAt,
      tools: {
        components: [
          {
            type: "application",
            name: "ECDAT",
            version: "1.0.0",
            description: "Enhanced Cryptographic Discovery & Assessment Tool",
          },
        ],
      },
      component: {
        type: "application",
        "bom-ref": "root-application",
        name: scan.source.label,
        version: scan.source.ref ?? "unversioned",
      },
      properties: [
        prop("scan-id", scan.scanId),
        prop("source-kind", scan.source.kind),
        prop("files-scanned", scan.metrics.filesScanned),
        prop("files-discovered", scan.metrics.filesDiscovered),
        prop("scan-duration-ms", scan.metrics.durationMs),
        prop("crqc-horizon-years", scan.moscaParams.z),
        prop("crqc-target-year", new Date().getFullYear() + scan.moscaParams.z),
        prop("facing", scan.facing),
      ],
    },
    components,
    dependencies,
  }
}

/** Deterministic UUIDv4-shaped identifier derived from the scan id. */
function uuidFrom(seed: string): string {
  let h = 0x2545f491
  const bytes: number[] = []
  for (let i = 0; i < 16; i++) {
    h ^= seed.charCodeAt(i % seed.length) + i * 31
    h = Math.imul(h, 0x01000193) >>> 0
    bytes.push((h >>> (i % 4) * 8) & 0xff)
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join("")
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

# ECDAT TOOL

Enterprise Cryptography Discovery & Analysis Tool.

ECDAT discovers cryptographic assets across source code, dependency manifests, configuration, and certificates. It classifies each asset, evaluates post-quantum exposure using the Mosca inequality, recommends NIST-aligned replacements, and generates migration and compliance artifacts.

## What is implemented

- Python `ast`-based scanning with lexical fallback
- Java, JavaScript/TypeScript, Go, and C# signature scanning
- NGINX/OpenSSL and generic config detection
- `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, Gradle, and pyproject detection
- PEM/CRT/DER certificate inventory with public-key metadata when available
- Deduplicated cryptographic asset inventory with auditable evidence
- Mosca model: `X + Y > Z`, with live X/Y/Z sensitivity sliders
- Quantum-vulnerable, classically broken, and Grover-weakened flags
- NIST PQC recommendations: ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384/512
- CycloneDX 1.6 CBOM JSON export
- SARIF 2.1.0 export and GitHub Actions CI gate snippet
- Prioritized migration roadmap with effort and cost estimates
- NSA CNSA 2.0 / NIST IR 8547 posture scoring
- Interactive file-to-library-to-algorithm dependency graph
- Diff-aware scan cache and throughput/performance panel
- Bundled `vulnbank` demo repository for reliable offline judging
- Public GitHub repository URL scans and local file/folder uploads

## Architecture

The project is a Next.js 16 App Router application. The scanner and analysis engine are pure TypeScript modules shared by server route handlers and the browser. Scans execute through `POST /api/scan`; CI integrations can call `POST /api/scan/ci`. The dashboard re-scores an existing result in the browser when Mosca parameters change, so sensitivity analysis does not trigger a second repository scan.

## Judge flow

1. Open the app.
2. Keep **Demo repo** selected.
3. Select **Run scan**.
4. Review Overview, Asset inventory, Risk explorer, Dependency graph, Roadmap, Compliance, and Performance.
5. Open Exports to download CBOM or SARIF artifacts.
6. Switch to GitHub URL or Local files to test additional sources.

## Methodology

Detection is evidence-first. Every asset stores the source file, line, snippet, detector, confidence, occurrence count, and normalized algorithm identifier. High-confidence Python calls/imports are resolved with a lightweight lexer/AST-style scanner; other supported languages use maintained signature patterns and line-aware matching. Results are deduplicated by normalized algorithm and source location, then classified using transparent path, file, and detector heuristics.

Mosca exposure uses inferred data confidentiality lifetime `X`, migration time `Y`, and the CRQC horizon `Z`. A positive margin means the protection window is already exceeded. The default CRQC horizon is the CNSA 2.0 planning year, but it is intentionally adjustable so judges can inspect assumptions rather than treating a forecast as a fact.

## Performance approach

- One-pass source analysis with normalized target metadata.
- SHA-256 file fingerprints for cache keys.
- Cache reuse for unchanged files on repeat scans.
- Server-side timings for fetch, analysis, parse errors, bytes, files/second, and KB/second.
- Browser-only Mosca recomputation for responsive what-if analysis.

## Future roadmap

- GitHub App / pull-request annotations using SARIF.
- Organization-wide historical posture and trend tracking.
- Deeper binary and container image extraction.
- Language-server integrations for developer-time remediation.
- Hardware-backed key and HSM inventory connectors.
- Human-approved migration ticket generation.

## Scope note

ECDAT is a static discovery and assessment tool. It is not a replacement for formal cryptographic validation, penetration testing, certificate authority operations, or a complete software composition analysis platform. Findings should be reviewed by a security engineer before production migration decisions.

## License

Add the project license before publication.

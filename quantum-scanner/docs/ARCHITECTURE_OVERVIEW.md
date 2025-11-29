# Architecture Overview

This document explains what the Quantum Vulnerability Scanner does end-to-end, covering components, data flow, detection logic, and output.

## High-Level Goals

- Detect quantum-vulnerable asymmetric cryptography (RSA, ECDSA/ECDH, DSA, DH, ElGamal) across languages.
- Recognize quantum-safe algorithms (Kyber, Dilithium, SPHINCS+, FALCON, NTRU, Classic McEliece, FrodoKEM).
- Provide actionable recommendations and severity ratings.
- Support both source scanning and Windows system scanning (agent-style).

## Components

- `src/vulnerability_db.py`
  - Central database of signatures: algorithm name, severity, description, recommendation, and regex patterns.
  - Severity levels: CRITICAL, HIGH, MEDIUM, LOW, SAFE (PQC recognized).

- `src/scanner.py`
  - Orchestrates scanning.
  - `Finding`: represents a detection. Fields include `algorithm`, `severity`, `matched_pattern`, `line_content`, `description`, `recommendation`, plus `key_size` and `confidence`.
  - `ScanResult`: aggregates findings, errors, and summary.

- `src/detectors/*`
  - Language-specific detectors that combine regex (and AST for Python) to detect vulnerabilities.
  - Enhanced key-size extraction:
    - Generic extractor in BaseDetector for patterns like `generate(2048)`, `initialize(4096)`, `modulusLength: 3072`, `RSA_generate_key_ex(..., 2048, ...)`.
    - Python detector also parses AST calls (e.g., `rsa.generate_private_key(key_size=2048)`).
  - Deduplication prefers entries with `key_size` and higher `confidence` when duplicates exist for the same file/line/algorithm.

- `src/windows_system_scanner.py`
  - Windows-only scanner that crawls common system directories for certificates, keys, and configurations.
  - Uses `cryptography` to parse certs/keys and to extract algorithm and key size.
  - Emits findings with `line_number=0` and an empty `line_content`.

- `src/cli.py`
  - CLI with subcommands:
    - `scan`: source scanning
    - `scan-openssl`: OpenSSL cipher suite analysis (Excel/Text reports)
    - `scan-system`: new Windows system scan (agent-style)

- `src/reporters/*`
  - CLI, JSON, and HTML reporters. Now display `key_size` and `confidence` where available.

## Detection Flow

1. Collect targets (files or directories).
2. For source scan:
   - Determine language by extension.
   - Run the associated detector:
     - Regex search using patterns from the vulnerability DB.
     - Language-specific logic (e.g., AST for Python, OpenSSL patterns for C/C++).
   - Attempt to extract key size from matched lines or nearby context.
   - Compute `confidence`:
     - `high` if algorithm and key size are known.
     - `low` if only algorithm is detected.
3. For system scan (Windows):
   - Locate artifacts by extension/filename.
   - Parse certificates and keys; infer algorithm and size.
   - If parsing fails, scan text configs for hints.
4. Aggregate `ScanResult` and render via selected reporter.

## Output Contract

- `scan_summary`: counts per severity and total files scanned.
- `findings`: array of findings with fields:
  - `file_path`, `line_number`, `algorithm`, `severity`, `matched_pattern`, `line_content`, `description`, `recommendation`, `key_size`, `confidence`.
- `errors`: list of `{file, error}` entries.

## Confidence and Key Size

- Key size drives confidence and reduces false positives.
- Common extraction patterns:
  - Java: `keyGen.initialize(2048)`; Node: `{ modulusLength: 2048 }`.
  - Python: `rsa.generate_private_key(..., key_size=4096)`.
  - C/OpenSSL: `RSA_generate_key_ex(..., 3072, ...)`.
  - Go: `rsa.GenerateKey(rand.Reader, 2048)`.

### Severity Adjustment by Key Size

All classical asymmetric algorithms are quantum-vulnerable, but severity reflects near-term vs long-term risk:

**RSA:**
- < 2048: CRITICAL (weak classically + quantum-vulnerable)
- 2048: HIGH (current standard, quantum-vulnerable)
- 3072-4096: MEDIUM (harder for early quantum computers)
- \> 4096: LOW (delays attack; still vulnerable)

**ECDSA/ECDH:**
- < 256: CRITICAL (weak curves)
- 256: HIGH (P-256, quantum-vulnerable)
- \> 256: MEDIUM (P-384, P-521; still vulnerable)

**DSA:**
- < 2048: CRITICAL (deprecated)
- ≥ 2048: HIGH (quantum-vulnerable)

**DH:**
- < 2048: CRITICAL (weak parameters)
- ≥ 2048: HIGH (quantum-vulnerable)

This classification helps prioritize remediation: CRITICAL findings need immediate action (weak even without quantum computers), while MEDIUM/LOW findings have more time before quantum computers pose a practical threat.

## Performance Considerations

- Parallel scanning via thread pool.
- Exclude patterns to skip large/vendor dirs.
- Max file size control to avoid huge binaries.
- System scan skips known heavy directories.

## Error Handling

- Scanner continues on per-file errors and records them in `errors`.
- System scan gracefully handles encrypted/unsupported key containers.

## Extensibility

- Add signatures to `vulnerability_db.py`.
- Implement new detectors in `src/detectors/` and register in `QuantumScanner._initialize_detectors`.
- Extend reporters or add new formats under `src/reporters/`.

## Security Notes

- Read-only scanning; does not modify files.
- Avoids collecting secrets; does not exfiltrate data.
- Treats private keys as sensitive—parses locally without exporting.

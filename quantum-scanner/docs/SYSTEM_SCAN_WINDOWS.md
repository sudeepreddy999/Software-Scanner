# Windows System Scan (Agent-Style)

The system scan inspects local Windows machines for static cryptographic artifacts and flags quantum-vulnerable algorithms. It complements source scanning by auditing certificates, keys, and common configuration files already present on the system.

## What It Scans

- Certificates and keys: `.pem`, `.crt`, `.cer`, `.der`, `.key`, `.pfx`, `.p12`
- SSH keys (by filename): `id_rsa`, `id_dsa`, `id_ecdsa`, etc.
- Config files: `.cfg`, `.conf`, `.ini`, and `*.config`

Default search roots (recursively):

- `C:\\ProgramData`
- `C:\\Program Files`
- `C:\\Program Files (x86)`
- `C:\\Windows\\System32`
- `C:\\Users`

You can override these with `--paths`.

## How It Works

1. Discovers files by extension/filename heuristics.
2. Parses certificates and (unencrypted) private keys using the Python `cryptography` library.
   - Extracts algorithm (RSA, ECDSA, DSA) and key size when available.
3. For PKCS#12 (PFX/P12): attempts to load key and/or cert if unencrypted; skips encrypted stores (reported with low confidence if only algorithm hints are found).
4. For config text: searches for algorithm mentions and key size hints (e.g., `modulusLength: 2048`, `key_size=4096`, `2048-bit RSA`).
5. Produces findings with a `confidence` score:
   - `high`: algorithm + key size detected
   - `low`: only algorithm detected (size unknown)

## Usage

```bash
# Default system scan (Windows only)
python -m src.cli scan-system

# JSON output
python -m src.cli scan-system --format json --output system_report.json

# Specify custom root directories
python -m src.cli scan-system --paths C:\\ProgramData C:\\Users --format html --output system_report.html
```

Notes:

- The system scan requires the `cryptography` library (added to `requirements.txt`).
- Runs only on Windows. On other OSes, the command exits with an informative error.
- Findings have `line_number=0` and `line_content=""` because they refer to system files rather than source lines.

## Output Fields

Each finding includes:

- `algorithm`: e.g., `RSA`, `ECDSA`, `DSA`
- `key_size`: integer bits when known (e.g., 2048)
- `confidence`: `high` if both algorithm and size detected; `low` otherwise
- `severity`: adjusted based on key size:
  - RSA < 2048: CRITICAL; 2048: HIGH; 3072-4096: MEDIUM; > 4096: LOW
  - ECDSA < 256: CRITICAL; 256: HIGH; > 256: MEDIUM
  - DSA < 2048: CRITICAL; ≥ 2048: HIGH
  - DH < 2048: CRITICAL; ≥ 2048: HIGH
- `description`, `recommendation`: derived from the vulnerability database

**Note:** All classical asymmetric algorithms are quantum-vulnerable regardless of key size. Severity reflects the timeline of risk (near-term vs long-term quantum threat).

## False Positives and Limitations

- Encrypted private keys and PFX stores may not expose key sizes; these typically result in `low` confidence.
- Config-based detections depend on textual hints and may require manual validation.
- This scan focuses on asymmetric cryptography. Symmetric ciphers and hashes are out of scope.

## Security Considerations

- The scanner reads files with best-effort safety and does not modify them.
- Paths like `Windows\\WinSxS`, `System Volume Information`, recycle bins, and very large directories are skipped to keep runtime reasonable.

## Implementation Reference

See `src/windows_system_scanner.py` for the implementation and integration with `scan-system` CLI.

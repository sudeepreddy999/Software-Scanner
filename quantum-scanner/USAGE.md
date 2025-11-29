# Quantum Vulnerability Scanner - Usage Guide

## Quick Start Guide

### 1. Installation

```bash
cd quantum-scanner

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Basic Usage

#### Scan a Directory
```bash
python -m src.cli scan /path/to/your/project
```

#### Scan with Verbose Output
```bash
python -m src.cli scan /path/to/your/project --verbose
```

#### Generate JSON Report
```bash
python -m src.cli scan /path/to/your/project --format json --output report.json
```

#### Generate HTML Report
```bash
python -m src.cli scan /path/to/your/project --format html --output report.html
```

### 2.1 Windows System Scan (Agent-Style)

Scan local Windows system files (certificates, keys, configs) for quantum-vulnerable algorithms.

Requirements: Windows host and `cryptography` installed.

```bash
# Default system scan (Windows only)
python -m src.cli scan-system

# Custom roots and JSON output
python -m src.cli scan-system --paths C:\\ProgramData C:\\Users --format json --output system_report.json

# HTML report
python -m src.cli scan-system --format html --output system_report.html
```

Notes:
- `scan-system` only runs on Windows. On other OSes, it exits with an error.
- Findings include `key_size` and `confidence`:
  - `confidence = high` when algorithm and key size are detected (e.g., RSA 2048)
  - `confidence = low` when only algorithm is detected

### 3. Testing the Scanner

Test the scanner on the included vulnerable code samples:

```bash
# From the project root directory
python -m src.cli scan quantum-scanner/tests/test_samples --verbose

# Or use the demo script
python demo.py
```

## Understanding the Results

### Severity Levels

1. **CRITICAL**: Algorithms completely broken by quantum computers OR weak by classical standards
   - RSA < 2048 bits (deprecated by NIST)
   - ECDSA < 256 bits (weak curves)
   - DSA < 2048 bits (deprecated)
   - DH < 2048 bits (weak parameters)

2. **HIGH**: Current-standard algorithms that are quantum-vulnerable
   - RSA 2048 bits
   - ECDSA/ECDH 256 bits (P-256)
   - DSA ≥ 2048 bits
   - DH ≥ 2048 bits

3. **MEDIUM**: Larger keys that delay quantum attacks but remain vulnerable
   - RSA 3072-4096 bits
   - ECDSA/ECDH > 256 bits (P-384, P-521)

4. **LOW**: Very large keys that significantly delay quantum attacks
   - RSA > 4096 bits

**Important:** No classical asymmetric algorithm is quantum-safe regardless of key size. Severity indicates the timeline of risk, not immunity to quantum attacks.

### Output Formats

#### CLI Output
- Colored, formatted output for terminal
- Summary statistics
- Detailed findings with line numbers
- Recommendations for each vulnerability

#### JSON Output
- Machine-readable format
- Suitable for CI/CD integration
- Complete vulnerability data
- Example:
```json
{
  "scan_summary": {
    "files_scanned": 5,
    "vulnerabilities_found": 15,
    "critical": 12,
    "high": 3,
    "medium": 0,
    "low": 0
  },
  "findings": [...]
}
```

#### HTML Output
- Visual report with styling
- Color-coded severity levels
- Easy to share with stakeholders
- Professional appearance

## Supported Languages and Libraries

### Python
- **Libraries**: PyCrypto, PyCryptodome, cryptography
- **Patterns**: RSA, ECDSA, DSA, DH key generation and usage
- **Detection**: AST parsing + regex

### Java
- **Libraries**: JCE (Java Cryptography Extension)
- **Patterns**: KeyPairGenerator, Cipher, Signature
- **Detection**: Regex pattern matching

### JavaScript/TypeScript
- **Libraries**: Node.js crypto module, node-rsa, elliptic
- **Patterns**: generateKeyPair, createSign, createECDH
- **Detection**: Regex pattern matching

### C/C++
- **Libraries**: OpenSSL
- **Patterns**: RSA_generate_key, EC_KEY_generate_key
- **Detection**: Regex pattern matching

### Go
- **Libraries**: crypto/rsa, crypto/ecdsa, crypto/dsa
- **Patterns**: rsa.GenerateKey, ecdsa.GenerateKey
- **Detection**: Regex pattern matching

## Configuration

### Custom Configuration File

Create a `custom_config.yaml`:

```yaml
exclude_patterns:
  - "*/node_modules/*"
  - "*/venv/*"
  - "*/test/*"
  - "*/vendor/*"

max_file_size_mb: 10

parallel_scanning: true
max_workers: 4
```

Use it with:
```bash
python -m src.cli scan /path/to/project --config custom_config.yaml
```

## Post-Quantum Cryptography Recommendations

### Key Encapsulation (Replace RSA/DH)
- **CRYSTALS-Kyber** (NIST selected)
- NTRU
- SABER

### Digital Signatures (Replace RSA/ECDSA/DSA)
- **CRYSTALS-Dilithium** (NIST selected)
- **FALCON** (NIST selected)
- **SPHINCS+** (NIST selected)

### Implementation Libraries

#### Python
```bash
pip install liboqs-python
```

#### C/C++
```bash
# liboqs - Open Quantum Safe
git clone https://github.com/open-quantum-safe/liboqs.git
```

#### Go
```bash
go get github.com/open-quantum-safe/liboqs-go
```

#### Java
```bash
# Bouncy Castle with PQC support
implementation 'org.bouncycastle:bcprov-jdk15on:1.70'
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Quantum Vulnerability Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      
      - name: Install scanner
        run: |
          pip install -r requirements.txt
      
      - name: Run quantum vulnerability scan
        run: |
          python -m src.cli . --format json --output scan-results.json
      
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: scan-results
          path: scan-results.json
      
      - name: Check for critical vulnerabilities
        run: |
          # Exit with error if critical vulnerabilities found
          python -c "import json; data=json.load(open('scan-results.json')); exit(1 if data['scan_summary']['critical'] > 0 else 0)"
```

## Exit Codes

- `0`: Success, no high/critical vulnerabilities
- `1`: High vulnerabilities found
- `2`: Critical vulnerabilities found

## Troubleshooting

### Large Codebases
- Increase `max_workers` in config
- Use `exclude_patterns` to skip large dependency folders
- Scan subdirectories separately

### False Positives
- Review the matched pattern and line content
- Some cryptographic hashing (SHA-256, etc.) is safe
- The scanner focuses on asymmetric cryptography

### Performance
- Enable parallel scanning (default)
- Exclude unnecessary directories
- Adjust `max_file_size_mb` limit

## Examples

### Example 1: Scan Python Project
```bash
python -m src.cli ~/my-python-app --verbose
```

### Example 2: Generate Report for Compliance
```bash
python -m src.cli ~/enterprise-app --format html --output compliance-report.html
```

### Example 3: Scan with Custom Config
```bash
python -m src.cli ~/app --config custom_config.yaml --format json --output results.json
```

## Getting Help

```bash
python -m src.cli --help
```

For more information about post-quantum cryptography:
- NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
- Open Quantum Safe: https://openquantumsafe.org/

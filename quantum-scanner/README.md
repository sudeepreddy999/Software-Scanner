# Quantum Vulnerability Scanner

A comprehensive security scanner that detects quantum-vulnerable cryptographic algorithms and recognizes post-quantum cryptography (PQC) implementations in your codebase.

## 🎯 Overview

This tool scans your source code to:

### Detect Quantum-Vulnerable Algorithms ❌
- **RSA** encryption and signatures
- **Elliptic Curve Cryptography (ECC/ECDSA/ECDH)**
- **Diffie-Hellman** key exchange
- **DSA** (Digital Signature Algorithm)
- Other pre-quantum cryptographic primitives

### Recognize Quantum-Safe Algorithms ✅
- **CRYSTALS-Kyber** (Key Encapsulation)
- **CRYSTALS-Dilithium** (Digital Signatures)
- **SPHINCS+** (Hash-Based Signatures)
- **FALCON** (Compact Lattice Signatures)
- **NTRU**, **Classic McEliece**, **FrodoKEM**

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd quantum-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan a directory
python -m src.cli scan /path/to/your/project

# Scan with JSON output
python -m src.cli scan /path/to/your/project --format json --output results.json

# Scan with HTML report
python -m src.cli scan /path/to/your/project --format html --output report.html

# Verbose output
python -m src.cli scan /path/to/your/project --verbose

# Test PQC recognition
python -m src.cli scan test_pqc_recognition.py --format cli

# Analyze OpenSSL cipher suites (generates Excel + Text summary)
python -m src.cli scan-openssl -o openssl_report.xlsx

# Windows system scan (agent-style)
# Scans local system certs/keys/configs for vulnerable algorithms
python -m src.cli scan-system --format json --output system_report.json
```

## 📋 Features

- ✅ **Multi-language support**: Python, Java, JavaScript/TypeScript, C/C++, Go
- ✅ **Comprehensive detection**: Identifies vulnerable algorithms across multiple libraries
- ✅ **Severity classification**: CRITICAL, HIGH, MEDIUM, LOW
- ✅ **Multiple output formats**: CLI table, JSON, HTML
- ✅ **Actionable recommendations**: Suggests Post-Quantum Cryptography alternatives
- ✅ **CI/CD integration**: JSON output and exit codes for automation
- ✅ **Configurable**: Custom rules and exclude patterns
- ✅ **Windows System Scan (Agent)**: Inspects system certificates, keys, and configs for quantum-vulnerable algorithms with confidence scoring and key size extraction

## 🔍 Detected Vulnerabilities

### Quantum-Vulnerable Algorithms

All classical asymmetric algorithms are quantum-vulnerable, but severity is adjusted based on key size to reflect near-term vs long-term risk:

**RSA:**
- < 2048 bits: **CRITICAL** (weak classically + quantum-vulnerable; NIST deprecated)
- 2048 bits: **HIGH** (current standard; quantum-vulnerable)
- 3072-4096 bits: **MEDIUM** (harder for early quantum computers; still vulnerable)
- \> 4096 bits: **LOW** (delays quantum attack; still not quantum-safe)

**ECDSA/ECDH/ECC:**
- < 256 bits (e.g., P-192): **CRITICAL** (weak curves; vulnerable classically)
- 256 bits (P-256): **HIGH** (current standard; quantum-vulnerable)
- \> 256 bits (P-384, P-521): **MEDIUM** (larger curves; still quantum-vulnerable)

**DSA:**
- < 2048 bits: **CRITICAL** (deprecated by NIST)
- ≥ 2048 bits: **HIGH** (quantum-vulnerable)

**DH (Diffie-Hellman):**
- < 2048 bits: **CRITICAL** (weak parameters)
- ≥ 2048 bits: **HIGH** (quantum-vulnerable)

**Note:** No classical asymmetric algorithm is quantum-safe regardless of key size. Even RSA-4096 will be broken by sufficiently large quantum computers running Shor's algorithm.

### Recommended Alternatives (Post-Quantum Cryptography)

- **CRYSTALS-Kyber**: Key encapsulation (replacement for RSA/ECDH)
- **CRYSTALS-Dilithium**: Digital signatures (replacement for RSA/ECDSA/DSA)
- **SPHINCS+**: Hash-based signatures
- **FALCON**: Lattice-based signatures
- **NTRU**: Lattice-based encryption

## 📊 Output Formats

### CLI Table Output
```
╔══════════════════════════════════════════════════════════════╗
║     Quantum Vulnerability Security Scan Report               ║
╠══════════════════════════════════════════════════════════════╣
║ Files Scanned: 247                                          ║
║ Vulnerabilities Found: 12                                   ║
║ Critical: 8 | High: 3 | Medium: 1 | Low: 0                 ║
╚══════════════════════════════════════════════════════════════╝
```

### JSON Output
```json
{
  "scan_summary": {
    "files_scanned": 247,
    "vulnerabilities_found": 12,
    "critical": 8,
    "high": 3,
    "medium": 1,
    "low": 0,
    "safe": 5
  },
  "findings": [
    {
      "file_path": ".../VulnerableJavaCode.java",
      "line_number": 15,
      "algorithm": "RSA",
      "severity": "CRITICAL",
      "matched_pattern": "KeyPairGenerator.getInstance('RSA')",
      "line_content": "KeyPairGenerator keyGen = KeyPairGenerator.getInstance(\"RSA\");",
      "description": "RSA is quantum-vulnerable.",
      "recommendation": "Replace with CRYSTALS-Kyber or CRYSTALS-Dilithium.",
      "key_size": 2048,
      "confidence": "high"
    }
  ]
}
```

Key fields added:
- `key_size` (bits): Extracted when possible (e.g., RSA 2048)
- `confidence`: "high" when both algorithm and key size are identified; "low" when only algorithm is detected

## ✅ Post-Quantum Cryptography (PQC) Recognition

The scanner now positively identifies quantum-safe algorithms:

- **CRYSTALS-Kyber**: NIST-standardized KEM (ML-KEM)
- **CRYSTALS-Dilithium**: NIST-standardized signatures (ML-DSA)
- **SPHINCS+**: Hash-based signatures (SLH-DSA)
- **FALCON**: Compact lattice signatures
- **NTRU**, **Classic McEliece**, **FrodoKEM**: Alternative PQC schemes

See [PQC Recognition Documentation](docs/PQC_RECOGNITION.md) for details.

## 🛠️ Configuration

Create a `scanner_config.yaml` file to customize scanning behavior:

```yaml
exclude_patterns:
  - "*/node_modules/*"
  - "*/venv/*"
  - "*/test/*"
  
file_extensions:
  python: [".py"]
  java: [".java"]
  javascript: [".js", ".ts"]
  
severity_levels:
  RSA: "CRITICAL"
  ECDSA: "CRITICAL"
  DH: "HIGH"
```

## 📖 Documentation

For detailed documentation, see the [docs](docs/) directory:
- [PQC Recognition Guide](docs/PQC_RECOGNITION.md)
- [OpenSSL Analysis](docs/OPENSSL_ANALYSIS.md)
- [Output Format Guide](docs/OUTPUT_FORMAT_GUIDE.md)
- [Detector Explanation](docs/DETECTOR_EXPLANATION.md)
- [Windows System Scan](docs/SYSTEM_SCAN_WINDOWS.md)
- [Architecture Overview](docs/ARCHITECTURE_OVERVIEW.md)

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines.

## 📄 License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

This tool is provided for security assessment purposes. Always consult with security experts when implementing cryptographic changes.

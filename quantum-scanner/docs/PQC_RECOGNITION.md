# Post-Quantum Cryptography (PQC) Recognition

## Overview

The Quantum Vulnerability Scanner now includes **positive recognition** of Post-Quantum Cryptography (PQC) algorithms. This means the scanner not only detects quantum-vulnerable algorithms but also identifies and acknowledges quantum-safe implementations with a `SAFE` severity level.

## Supported PQC Algorithms

The scanner recognizes the following NIST-standardized and well-established post-quantum cryptographic algorithms:

### 1. **CRYSTALS-Kyber** ✅
- **Type**: Key Encapsulation Mechanism (KEM)
- **Security Basis**: Module Learning With Errors (MLWE)
- **Status**: NIST Standard (ML-KEM)
- **Use Case**: Secure key exchange
- **Detection Patterns**: `kyber`, `ML-KEM`, `pqcrypto.kem.kyber`, `OQS_KEM_kyber`

### 2. **CRYSTALS-Dilithium** ✅
- **Type**: Digital Signature Algorithm
- **Security Basis**: Module Learning With Errors (MLWE)
- **Status**: NIST Standard (ML-DSA)
- **Use Case**: Quantum-safe digital signatures
- **Detection Patterns**: `dilithium`, `ML-DSA`, `pqcrypto.sign.dilithium`, `OQS_SIG_dilithium`

### 3. **SPHINCS+** ✅
- **Type**: Digital Signature Algorithm
- **Security Basis**: Hash functions (stateless)
- **Status**: NIST Standard (SLH-DSA)
- **Use Case**: Conservative signature scheme with minimal assumptions
- **Detection Patterns**: `sphincs`, `SPHINCS+`, `SLH-DSA`, `pqcrypto.sign.sphincs`

### 4. **FALCON** ✅
- **Type**: Digital Signature Algorithm
- **Security Basis**: NTRU lattices
- **Status**: NIST Standard
- **Use Case**: Compact signatures with fast verification
- **Detection Patterns**: `falcon`, `pqcrypto.sign.falcon`, `OQS_SIG_falcon`

### 5. **NTRU** ✅
- **Type**: Encryption/Key Encapsulation
- **Security Basis**: Lattice problems
- **Status**: Well-established algorithm
- **Use Case**: Efficient key encapsulation
- **Detection Patterns**: `ntru`, `NTRUEncrypt`, `pqcrypto.kem.ntru`

### 6. **Classic McEliece** ✅
- **Type**: Key Encapsulation Mechanism
- **Security Basis**: Code-based cryptography
- **Status**: NIST Standard finalist
- **Use Case**: Strong security with conservative assumptions (note: large key sizes)
- **Detection Patterns**: `mceliece`, `McEliece`, `classic_mceliece`

### 7. **FrodoKEM** ✅
- **Type**: Key Encapsulation Mechanism
- **Security Basis**: Learning With Errors (LWE) over generic lattices
- **Status**: Conservative alternative
- **Use Case**: Key exchange with minimal security assumptions
- **Detection Patterns**: `frodo`, `FrodoKEM`, `pqcrypto.kem.frodo`

## How It Works

### Detection Process

1. **Pattern Matching**: The scanner uses regex patterns to identify PQC algorithm usage in source code
2. **Multi-Language Support**: Detects PQC implementations across Python, Java, JavaScript, C/C++, and Go
3. **Library Recognition**: Recognizes common PQC libraries:
   - `pqcrypto` (Python)
   - `liboqs` (C/C++)
   - `liboqs-go` (Go)
   - `circl` (Go)

### Severity Classification

When PQC algorithms are detected, they are classified as:
- **Severity**: `SAFE`
- **Icon**: ✅ (green checkmark)
- **Message**: Positive acknowledgment with recommendation to continue using

### Example Detection

```python
# Vulnerable Code - Detected as CRITICAL ❌
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Quantum-Safe Code - Detected as SAFE ✅
from pqcrypto.kem.kyber512 import generate_keypair
public_key, secret_key = generate_keypair()
```

## Output Formats

### CLI Output

```
═══════════════════════════════════════════════════════════════════
       Quantum Vulnerability Security Scan Report
═══════════════════════════════════════════════════════════════════

SCAN SUMMARY
────────────────────────────────────────────────────────────────────
Files Scanned: 1
Vulnerabilities Found: 3
Quantum-Safe Algorithms: 2 ✓

  ● CRITICAL: 3
  ● HIGH:     0
  ● MEDIUM:   0
  ● LOW:      0

DETECTED VULNERABILITIES
────────────────────────────────────────────────────────────────────

[CRITICAL] RSA
  File: crypto.py:10
  Code: private_key = rsa.generate_private_key(...)
  Issue: RSA encryption/signatures are vulnerable to Shor's algorithm
  → Recommendation: Replace with CRYSTALS-Kyber or CRYSTALS-Dilithium

QUANTUM-SAFE ALGORITHMS DETECTED ✓
────────────────────────────────────────────────────────────────────

✓ [SAFE] CRYSTALS-Kyber
  File: crypto.py:25
  Code: from pqcrypto.kem.kyber512 import generate_keypair
  ✓ CRYSTALS-Kyber is a NIST-standardized post-quantum KEM
  → This algorithm is quantum-safe. Continue using for secure key exchange.
```

### JSON Output

```json
{
  "scan_summary": {
    "files_scanned": 1,
    "vulnerabilities_found": 3,
    "critical": 3,
    "high": 0,
    "medium": 0,
    "low": 0,
    "safe": 2,
    "errors": 0
  },
  "findings": [
    {
      "file_path": "crypto.py",
      "line_number": 25,
      "algorithm": "CRYSTALS-Kyber",
      "severity": "SAFE",
      "matched_pattern": "kyber",
      "line_content": "from pqcrypto.kem.kyber512 import generate_keypair",
      "description": "CRYSTALS-Kyber is a NIST-standardized post-quantum key encapsulation mechanism (KEM) based on Module Learning With Errors (MLWE).",
      "recommendation": "This algorithm is quantum-safe. Continue using for secure key exchange."
    }
  ]
}
```

## Testing

Use the provided test file to verify PQC recognition:

```bash
# Activate virtual environment
source venv/bin/activate

# Run scan on PQC test file
python -m src.cli scan test_pqc_recognition.py --format cli
```

The test file (`test_pqc_recognition.py`) contains both:
- ❌ **Vulnerable algorithms**: RSA, ECDSA, DSA (detected as CRITICAL)
- ✅ **Quantum-safe algorithms**: Kyber, Dilithium, SPHINCS+, FALCON, NTRU, McEliece, FrodoKEM (detected as SAFE)

## Benefits

### 1. **Positive Reinforcement**
- Acknowledges good security practices
- Encourages adoption of quantum-safe algorithms

### 2. **Migration Tracking**
- Track progress from vulnerable to quantum-safe implementations
- Measure cryptographic migration success

### 3. **Compliance**
- Demonstrate use of NIST-approved post-quantum standards
- Audit quantum-readiness of codebases

### 4. **Education**
- Learn which algorithms are quantum-safe
- Reference links to official standards and documentation

## References

Each PQC signature includes reference links to:
- Official algorithm websites
- NIST Post-Quantum Cryptography standardization project
- Implementation guides and best practices

## Migration Guide

### From RSA to Kyber (Key Exchange)

**Before (Vulnerable):**
```python
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
```

**After (Quantum-Safe):**
```python
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
public_key, secret_key = generate_keypair()
ciphertext, shared_secret = encrypt(public_key)
```

### From ECDSA to Dilithium (Signatures)

**Before (Vulnerable):**
```python
from cryptography.hazmat.primitives.asymmetric import ec
private_key = ec.generate_private_key(ec.SECP256R1())
signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
```

**After (Quantum-Safe):**
```python
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
public_key, secret_key = generate_keypair()
signature = sign(secret_key, message)
```

## Future Enhancements

- **Hybrid Cryptography Detection**: Identify hybrid schemes combining classical + PQC
- **Algorithm Parameter Analysis**: Check security levels (e.g., Kyber512 vs Kyber1024)
- **Performance Profiling**: Suggest optimal PQC algorithms based on use case
- **Migration Recommendations**: Automated suggestions for replacing vulnerable code with PQC equivalents

## Technical Implementation

### Severity Enum

```python
class Severity(Enum):
    CRITICAL = 'CRITICAL'  # Quantum-vulnerable
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    SAFE = 'SAFE'  # Quantum-safe (PQC)
```

### Signature Structure

```python
VulnerabilitySignature(
    algorithm="CRYSTALS-Kyber",
    severity=Severity.SAFE,
    description="NIST-standardized post-quantum KEM",
    recommendation="Continue using for secure key exchange",
    patterns=[r"kyber", r"ML-KEM", r"pqcrypto\.kem\.kyber"],
    language="all",
    references=[
        "https://pq-crystals.org/kyber/",
        "https://csrc.nist.gov/projects/post-quantum-cryptography"
    ]
)
```

---

**Last Updated**: October 30, 2025  
**Version**: 1.0.0

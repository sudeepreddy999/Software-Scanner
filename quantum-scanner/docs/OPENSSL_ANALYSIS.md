# OpenSSL Cipher Suite Analysis

## Overview

The `scan-openssl` command analyzes your system's OpenSSL installation to identify available cipher suites and assess their resistance to quantum computing attacks. This feature provides comprehensive analysis without requiring a target application.

## Features

- **Complete Cipher Suite Enumeration**: Lists all cipher suites available in your OpenSSL installation
- **Algorithm Breakdown**: Extracts key exchange, authentication, encryption, and MAC algorithms
- **Key Size Detection**: Identifies encryption key sizes (e.g., AES-128, AES-256) and hash output sizes (SHA-256, SHA-384, etc.)
- **Component-Level Quantum Analysis**: Assesses quantum vulnerability for each cipher suite component:
  - **Key Exchange**: Simple Quantum-Safe/Quantum-Vulnerable classification (no deep categorization)
  - **Authentication**: Simple Quantum-Safe/Quantum-Vulnerable classification (no deep categorization)
  - **Encryption**: Quantum status based on n/2 ≥ 128 threshold with key size extraction
  - **Hash**: Quantum status based on n/2 ≥ 128 threshold with output size extraction
- **Quantum Strength Assessment**: Evaluates each cipher suite's overall resistance to quantum attacks
- **Excel Report Generation**: Creates detailed, color-coded Excel reports with quantum status for each component
- **Text Summary Report**: Frequency analysis and categorized cipher lists with component-level quantum details

## Usage

### Basic Command

```bash
python -m src.cli scan-openssl -o report.xlsx
```

### Verbose Output

```bash
python -m src.cli scan-openssl -o report.xlsx --verbose
```

## Report Structure

The generated reports include:

### Excel Report
- **Component-Level Analysis**: Each cipher suite shows quantum status for KX, Auth, Encryption, and Hash
- Columns include:
  - Cipher Suite Name
  - Protocol (TLSv1.2, TLSv1.3, etc.)
  - Key Exchange Algorithm + Quantum Status
  - Authentication Algorithm + Quantum Status
  - Encryption Algorithm + Key Size (bits) + Quantum Status
  - Hash Algorithm + Output Size (bits) + Quantum Status
  - Overall Quantum Strength Level
  - Strength Score (0-100)
  - Detailed Description
  - Recommendations
- Color-coded quantum status indicators:
  - Green: Quantum-Safe components
  - Red: Quantum-Vulnerable components
- Sortable and filterable data

### Text Summary Report
- Quantum strength frequency distribution
- Categorized cipher suite lists by overall strength
- For each cipher suite:
  - Key Exchange: [Algorithm] [Quantum Status]
  - Authentication: [Algorithm] [Quantum Status]
  - Encryption: [Algorithm] ([Key Size]-bit) [Quantum Status]
  - Hash: [Algorithm] ([Output Size]-bit) [Quantum Status]
- Statistical breakdowns
- Migration recommendations

## Component-Level Quantum Analysis

### Key Exchange (KX) Classification
**Simple Binary Classification**: Quantum-Safe or Quantum-Vulnerable

**Quantum-Vulnerable Algorithms**:
- RSA (vulnerable to Shor's algorithm)
- ECDH/ECDHE (vulnerable to Shor's algorithm)
- DH/DHE (vulnerable to Shor's algorithm)

**Quantum-Safe Algorithms**:
- CRYSTALS-Kyber (NIST standardized)
- NTRU, FrodoKEM, McEliece (alternatives)

**Note**: KX algorithms are classified without deep categorization or key size analysis.

### Authentication Classification
**Simple Binary Classification**: Quantum-Safe or Quantum-Vulnerable

**Quantum-Vulnerable Algorithms**:
- RSA (vulnerable to Shor's algorithm)
- ECDSA (vulnerable to Shor's algorithm)
- DSA (vulnerable to Shor's algorithm)

**Quantum-Safe Algorithms**:
- CRYSTALS-Dilithium (NIST primary standard)
- FALCON (NIST alternative standard)
- SPHINCS+ (stateless hash-based)

**Note**: Auth algorithms are classified without deep categorization or key size analysis.

### Encryption Classification
**Key Size-Based Analysis with n/2 ≥ 128 Threshold**

For symmetric encryption, Grover's algorithm halves the effective security:
- **Formula**: n/2 ≥ 128 bits (where n = key size in bits)
- **Threshold**: n ≥ 256 bits for Quantum-Safe classification

**Classification**:
- AES-128 (128 bits): 128/2 = 64 → **Quantum-Vulnerable**
- AES-192 (192 bits): 192/2 = 96 → **Quantum-Vulnerable**
- AES-256 (256 bits): 256/2 = 128 → **Quantum-Safe** ✓
- AES-512 (512 bits): 512/2 = 256 → **Quantum-Safe** ✓
- 3DES (168 bits): 168/2 = 84 → **Quantum-Vulnerable**

**Note**: AES-256 and larger provide adequate quantum security (≥128 bits effective) against Grover's algorithm.

### Hash Classification
**Output Size-Based Analysis with n/2 ≥ 128 Threshold**

For hash functions, Grover's algorithm affects collision resistance:
- **Formula**: n/2 ≥ 128 bits (where n = hash output size in bits)
- **Threshold**: n ≥ 256 bits for Quantum-Safe classification

**Classification**:
- MD5 (128 bits): 128/2 = 64 → **Quantum-Vulnerable**
- SHA-1 (160 bits): 160/2 = 80 → **Quantum-Vulnerable**
- SHA-224 (224 bits): 224/2 = 112 → **Quantum-Vulnerable**
- SHA-256 (256 bits): 256/2 = 128 → **Quantum-Safe** ✓
- SHA-384 (384 bits): 384/2 = 192 → **Quantum-Safe** ✓
- SHA-512 (512 bits): 512/2 = 256 → **Quantum-Safe** ✓

**Note**: SHA-256 and larger hash functions provide adequate quantum security (≥128 bits effective) against Grover's algorithm.

## Quantum Strength Levels (Overall Assessment)

### CRITICAL (Red)
- **Security**: Completely vulnerable to quantum computers
- **Algorithms**: RSA, ECDSA, ECDH, DH, DHE
- **Vulnerability**: Shor's algorithm breaks these in polynomial time
- **Action**: Disable immediately, migrate to post-quantum alternatives
- **Timeline**: Already vulnerable

### LOW (Orange)
- **Security**: Limited quantum resistance
- **Examples**: AES-128 (provides 64-bit quantum security)
- **Vulnerability**: Grover's algorithm reduces effective key size by half
- **Action**: Replace within 1-2 years
- **Timeline**: 5-10 years protection

### MEDIUM (Yellow)
- **Security**: Moderate quantum resistance
- **Examples**: AES-192 (provides 96-bit quantum security)
- **Action**: Plan upgrade within 3-5 years
- **Timeline**: 10-20 years protection

### HIGH (Light Green)
- **Security**: Good quantum resistance
- **Examples**: AES-256 (provides 128-bit quantum security)
- **Action**: Acceptable for current use, monitor developments
- **Timeline**: 20+ years protection

### QUANTUM_SAFE (Green)
- **Security**: Post-quantum algorithms
- **Examples**: CRYSTALS-Kyber, CRYSTALS-Dilithium, FALCON, SPHINCS+
- **Action**: Recommended for new deployments
- **Timeline**: Secure against both classical and quantum attacks

## Algorithm Analysis

### Key Exchange Algorithms

#### Vulnerable to Quantum Attacks
- **RSA**: Broken by Shor's algorithm (number factorization)
- **ECDH/ECDHE**: Broken by Shor's algorithm (elliptic curve discrete logarithm)
- **DH/DHE**: Broken by Shor's algorithm (discrete logarithm)

#### Quantum-Resistant Alternatives
- **CRYSTALS-Kyber**: NIST standardized, lattice-based
- **NTRU**: Lattice-based alternative
- **SIKE**: Isogeny-based (withdrawn due to attack)

### Authentication Algorithms

#### Vulnerable to Quantum Attacks
- **RSA**: Signature forgery possible with Shor's algorithm
- **ECDSA**: Broken by Shor's algorithm
- **DSA**: Broken by Shor's algorithm

#### Quantum-Resistant Alternatives
- **CRYSTALS-Dilithium**: Primary NIST standard for signatures
- **FALCON**: Compact signatures, alternative to Dilithium
- **SPHINCS+**: Stateless hash-based signatures

### Symmetric Encryption

#### Impact of Grover's Algorithm
Grover's algorithm reduces the effective security level of symmetric algorithms by half:

- **AES-128**: 128-bit classical → 64-bit quantum (WEAK)
- **AES-192**: 192-bit classical → 96-bit quantum (MODERATE)
- **AES-256**: 256-bit classical → 128-bit quantum (STRONG)
- **3DES**: 112-bit classical → 56-bit quantum (BROKEN)

#### Recommendations
- **Minimum**: Use AES-256 for quantum resistance
- **Avoid**: 3DES, DES, RC4 (already broken classically)
- **Consider**: AES-128 only for low-value, short-term data

### Hash Algorithms

#### Quantum Impact
Grover's algorithm affects collision resistance:

- **MD5**: Already broken classically, do not use
- **SHA-1**: Deprecated, vulnerable to classical attacks
- **SHA-256**: 128-bit classical collision resistance → 85-bit quantum (adequate for 10-15 years)
- **SHA-384**: 192-bit classical collision resistance → 128-bit quantum (secure for 20+ years)
- **SHA-512**: 256-bit classical collision resistance → 170-bit quantum (excellent long-term)

## Understanding the Report

### Strength Score
The strength score (0-100) provides a quick assessment:
- **0-20**: Critical, immediate replacement required
- **21-40**: Low, replace within 1-2 years
- **41-60**: Medium, upgrade within 3-5 years
- **61-80**: High, acceptable for near-term use
- **81-100**: Quantum-safe or excellent resistance

### Timeline Guidance

#### Immediate (0-6 months)
1. Run this analysis tool
2. Audit all systems for cipher suite usage
3. Disable all CRITICAL cipher suites
4. Document current cryptographic inventory

#### Short-term (6-12 months)
1. Implement hybrid classical+PQC solutions
2. Test post-quantum algorithms in non-production
3. Update security policies
4. Train development teams

#### Medium-term (1-2 years)
1. Migrate critical systems to PQC
2. Replace RSA with CRYSTALS-Dilithium/FALCON
3. Replace ECDH with CRYSTALS-Kyber
4. Upgrade symmetric encryption to AES-256

#### Long-term (2-5 years)
1. Complete organizational PQC migration
2. Deprecate all quantum-vulnerable algorithms
3. Regular PQC security audits
4. Stay current with NIST PQC standards

## Example Analysis Results

### Sample Output
```
Quantum OpenSSL Cipher Suite Analyzer
==================================================

OpenSSL Version: OpenSSL 3.5.2 5 Aug 2025

Found 158 cipher suites

Quantum Strength Distribution:
  CRITICAL       :  131 ( 82.9%)
  LOW            :   18 ( 11.4%)
  MEDIUM         :    0 (  0.0%)
  HIGH           :    9 (  5.7%)
  QUANTUM_SAFE   :    0 (  0.0%)

⚠️  WARNING: 131 CRITICAL cipher suites found!
   These are vulnerable to quantum attacks and should be disabled.
```

### Interpretation
- **82.9% Critical**: Most cipher suites use RSA/ECDH/DH (quantum-vulnerable)
- **11.4% Low**: Primarily AES-128 based ciphers (reduced quantum security)
- **5.7% High**: AES-256 ciphers (good quantum resistance for symmetric encryption)
- **0% Quantum-Safe**: No post-quantum algorithms detected (OpenSSL 3.x doesn't include PQC by default)

## Prerequisites

### Required Software
- OpenSSL installed on your system
- Python 3.8+
- openpyxl library

### Installation
```bash
# macOS (Homebrew)
brew install openssl

# Ubuntu/Debian
sudo apt-get install openssl

# Windows
Download from https://slproweb.com/products/Win32OpenSSL.html

# Install Python dependencies
pip install openpyxl
```

### Verification
```bash
openssl version
# Should output: OpenSSL 3.x.x or similar
```

## Troubleshooting

### OpenSSL Not Found
```
Error: OpenSSL not found on system
```
**Solution**: Install OpenSSL using your package manager (see Prerequisites)

### Permission Denied
```
Error: Permission denied writing to output file
```
**Solution**: Ensure you have write permissions in the target directory

### Import Error (openpyxl)
```
Error: Required library not installed
```
**Solution**: Install openpyxl with `pip install openpyxl`

### No Cipher Suites Found
```
Found 0 cipher suites
```
**Solution**: Your OpenSSL installation may be corrupted. Reinstall OpenSSL.

## Best Practices

1. **Regular Analysis**: Run this analysis quarterly to track changes in your OpenSSL configuration
2. **Version Control**: Keep historical reports to track migration progress
3. **Share Reports**: Distribute Excel reports to security teams and management
4. **Action Items**: Use the Critical Ciphers sheet to create remediation tickets
5. **Configuration Management**: Use findings to update TLS/SSL configuration files
6. **Compliance**: Include reports in security audits and compliance documentation

## Integration with CI/CD

You can integrate this analysis into your CI/CD pipeline:

```bash
# In your CI script
python -m src.cli scan-openssl -o openssl_report_$(date +%Y%m%d).xlsx --verbose

# Check exit code
if [ $? -eq 2 ]; then
    echo "CRITICAL: Quantum-vulnerable cipher suites detected!"
    # Optionally fail the build
    exit 1
fi
```

## Further Reading

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Quantum Computing Threat Timeline](https://globalriskinstitute.org/publications/quantum-threat-timeline-report-2020/)

## Support

For issues or questions:
1. Check this documentation
2. Review the Excel report's Recommendations sheet
3. Consult NIST PQC guidelines
4. Contact your security team for organizational guidance

# Quantum Vulnerability Scanner - Quick Reference

## 🚀 Quick Start Commands

```bash
# 1. Navigate to the scanner
cd "/Users/sudeepogireddy/projects/Software Scanner/quantum-scanner"

# 2. Activate virtual environment
source venv/bin/activate

# 3. Run a basic scan
python -m src.cli tests/test_samples

# 4. Scan your own project
python -m src.cli /path/to/your/project --verbose

# 5. Generate JSON report
python -m src.cli /path/to/project --format json --output report.json

# 6. Generate HTML report
python -m src.cli /path/to/project --format html --output report.html
```

## 📋 Command Options

```bash
python -m src.cli TARGET [OPTIONS]

Options:
  -f, --format {cli,json,html}  Output format (default: cli)
  -o, --output PATH             Output file path (required for json/html)
  -c, --config PATH             Custom configuration file
  -v, --verbose                 Enable verbose output
  --no-color                    Disable colored output
  --version                     Show version
  --help                        Show help message
```

## 🎯 Common Use Cases

### 1. Quick Security Check
```bash
python -m src.cli . --verbose
```

### 2. CI/CD Integration
```bash
python -m src.cli . --format json --output results.json
# Exit code 0 = no critical issues
# Exit code 1 = high vulnerabilities
# Exit code 2 = critical vulnerabilities
```

### 3. Generate Report for Team
```bash
python -m src.cli . --format html --output security-report.html
```

### 4. Custom Configuration
```bash
python -m src.cli . --config my_config.yaml --verbose
```

## 🔍 What Gets Detected

### Quantum-Vulnerable Algorithms:
- ❌ **RSA** (all key sizes)
- ❌ **ECDSA/ECDH** (all curves: P-256, P-384, P-521, secp256k1)
- ❌ **DSA** (Digital Signature Algorithm)
- ❌ **Diffie-Hellman** (DH/DHE)
- ❌ **ElGamal**

### Safe Alternatives (Post-Quantum):
- ✅ **CRYSTALS-Kyber** (key encapsulation)
- ✅ **CRYSTALS-Dilithium** (signatures)
- ✅ **SPHINCS+** (hash-based signatures)
- ✅ **FALCON** (lattice signatures)

## 📊 Understanding Results

### Severity Levels:
- 🔴 **CRITICAL**: Completely broken by quantum computers (RSA, ECDSA, DSA)
- 🟠 **HIGH**: Significantly weakened (DH, ElGamal)
- 🟡 **MEDIUM**: Reduced security
- 🔵 **LOW**: Potential concerns

### Exit Codes:
- `0` = Success (no high/critical issues)
- `1` = High vulnerabilities found
- `2` = Critical vulnerabilities found

## 🛠️ Configuration Example

Create `custom_config.yaml`:
```yaml
exclude_patterns:
  - "*/node_modules/*"
  - "*/venv/*"
  - "*/test/*"
  - "*/build/*"

max_file_size_mb: 10
parallel_scanning: true
max_workers: 4
```

## 📁 Project Structure

```
quantum-scanner/
├── src/                    # Source code
│   ├── scanner.py         # Core scanner
│   ├── vulnerability_db.py # Vulnerability database
│   ├── cli.py             # CLI interface
│   ├── detectors/         # Language detectors
│   └── reporters/         # Output formatters
├── tests/test_samples/    # Sample vulnerable code
├── config/                # Configuration files
├── venv/                  # Virtual environment
└── requirements.txt       # Dependencies
```

## 🌐 Supported Languages

| Language | File Extensions | Libraries Detected |
|----------|----------------|-------------------|
| Python | `.py` | PyCrypto, cryptography |
| Java | `.java` | JCE (Java Crypto) |
| JavaScript | `.js`, `.ts` | Node.js crypto, npm packages |
| C/C++ | `.c`, `.cpp`, `.h` | OpenSSL |
| Go | `.go` | crypto/rsa, crypto/ecdsa |

## 📖 Documentation

- **README.md** - Overview and installation
- **USAGE.md** - Comprehensive usage guide
- **PROJECT_SUMMARY.md** - Complete project details
- **This file** - Quick reference

## 💡 Tips

### Speed Up Scans:
```yaml
# In config file
parallel_scanning: true
max_workers: 8  # Adjust based on CPU cores
```

### Reduce False Positives:
```yaml
exclude_patterns:
  - "*/vendor/*"     # Third-party code
  - "*/legacy/*"     # Old code you can't change
```

### For Large Projects:
```bash
# Scan specific directories
python -m src.cli src/ --verbose
python -m src.cli lib/ --verbose
```

## 🔗 Integration Examples

### GitHub Actions:
```yaml
- name: Run quantum scan
  run: |
    cd quantum-scanner
    source venv/bin/activate
    python -m src.cli .. --format json --output ../scan.json
```

### Pre-commit Hook:
```bash
#!/bin/bash
cd quantum-scanner
source venv/bin/activate
python -m src.cli ../src --format json --output /tmp/scan.json
if [ $? -eq 2 ]; then
    echo "❌ Critical quantum vulnerabilities detected!"
    exit 1
fi
```

## 🆘 Troubleshooting

### Import Errors:
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### No Detections:
- Check file extensions are supported
- Verify files aren't in excluded directories
- Run with `--verbose` to see what's being scanned

### Performance Issues:
- Reduce `max_workers` if system is slow
- Add more `exclude_patterns`
- Increase `max_file_size_mb` limit

## 📞 Support

For issues or questions:
1. Check the USAGE.md file
2. Review PROJECT_SUMMARY.md
3. Run with `--verbose` flag
4. Check the configuration file

---

**🎉 Happy Scanning! Protect your code from quantum threats!**

# OpenSSL Scanner - Modified Output Format

## Overview

The `scan-openssl` command now generates **TWO output files** automatically:
1. **Excel Report** (.xlsx) - Detailed cipher suite data
2. **Text Summary** (_summary.txt) - Frequency analysis and categorized lists

## Usage

```bash
python -m src.cli scan-openssl -o report.xlsx
```

**Output Files:**
- `report.xlsx` - Excel file with all cipher details
- `report_summary.txt` - Text summary automatically generated

## Excel Report Format

### Single Comprehensive Sheet: "All Cipher Suites"

The Excel file contains ONE worksheet with ALL cipher suites and their complete attributes:

| Column | Content | Description |
|--------|---------|-------------|
| A | Cipher Suite Name | Full cipher suite identifier (e.g., ECDHE-RSA-AES256-GCM-SHA384) |
| B | Protocol | TLS/SSL version (TLSv1.2, TLSv1.3, etc.) |
| C | Key Exchange | Algorithm used for key negotiation (ECDH, DH, RSA) |
| D | Authentication | Server authentication method (RSA, ECDSA) |
| E | Encryption | Symmetric encryption algorithm (AESGCM, AES, etc.) |
| F | MAC | Message Authentication Code (AEAD, SHA256, etc.) |
| G | Key Size (bits) | Encryption key size (128, 192, 256) |
| H | Hash Algorithm | Hash function used (SHA256, SHA384, AEAD) |
| I | **Quantum Strength** | **Color-coded strength level** |
| J | Strength Score | Numeric score 0-100 |
| K | Description | Human-readable cipher details |
| L | Recommendation | Actionable security advice |

### Features
- ✅ **Color-coded Quantum Strength column** (Red=CRITICAL, Green=HIGH)
- ✅ **Sortable and filterable** data
- ✅ **Auto-filter enabled** on all columns
- ✅ **Frozen header rows** for easy scrolling
- ✅ **Optimized column widths** for readability

### Example Data
```
Cipher: ECDHE-RSA-AES256-GCM-SHA384
Protocol: TLSv1.2
Key Exchange: ECDH
Authentication: RSA
Encryption: AESGCM(256)
Key Size: 256 bits
Quantum Strength: CRITICAL (Red background)
Score: 10/100
Description: Key Exchange: ECDH, Authentication: RSA, Encryption: AESGCM (256-bit)
Recommendation: URGENT: Replace immediately. Vulnerable to quantum attacks...
```

## Text Summary Format

### File Structure

The text summary file contains **4 main sections**:

#### **Section 1: Quantum Strength Frequency Distribution**

Shows the count and percentage of each quantum strength level:

```
SECTION 1: QUANTUM STRENGTH FREQUENCY DISTRIBUTION
================================================================================

Quantum Strength     Count      Percentage   Status
--------------------------------------------------------------------------------
CRITICAL             131          82.9%      🔴 IMMEDIATE ACTION REQUIRED
LOW                  18           11.4%      🟠 HIGH PRIORITY
MEDIUM               0             0.0%      🟡 MEDIUM PRIORITY
HIGH                 9             5.7%      🟢 LOW PRIORITY
QUANTUM_SAFE         0             0.0%      ✅ SAFE
```

#### **Section 2: Cipher Suites by Quantum Strength Category**

For each strength level, shows:
- Category description and risk explanation
- Complete list of all cipher suites in that category
- Detailed attributes for each cipher

```
CATEGORY: CRITICAL
Count: 131
================================================================================

These cipher suites are CRITICALLY vulnerable to quantum attacks.
They use RSA, ECDH, or DH key exchange which can be broken by Shor's algorithm.
ACTION: Disable immediately and migrate to post-quantum alternatives.

--------------------------------------------------------------------------------
Cipher Suites in this category:
--------------------------------------------------------------------------------

1. ECDHE-RSA-AES256-GCM-SHA384
   Protocol: TLSv1.2
   Key Exchange: ECDH
   Authentication: RSA
   Encryption: AESGCM(256)
   Key Size: 256 bits
   Hash: AEAD
   Quantum Strength Score: 10/100

2. DHE-RSA-AES256-SHA256
   Protocol: TLSv1.2
   Key Exchange: DH
   Authentication: RSA
   ...
```

#### **Section 3: Additional Statistics**

Breakdown by:
- Protocol version (TLSv1.2, TLSv1.3, etc.)
- Key exchange algorithm (DH, ECDH, RSA, etc.)
- Encryption algorithm (AES, AESGCM, etc.)

```
Distribution by Protocol Version:
--------------------------------------------------------------------------------
  SSLv3             33 cipher suites ( 20.9%)
  TLSv1             36 cipher suites ( 22.8%)
  TLSv1.2           86 cipher suites ( 54.4%)
  TLSv1.3            3 cipher suites (  1.9%)

Distribution by Key Exchange Algorithm:
--------------------------------------------------------------------------------
  DH                39 cipher suites ( 24.7%)
  ECDH              31 cipher suites ( 19.6%)
  RSA               19 cipher suites ( 12.0%)
  ...
```

#### **Section 4: Recommendations**

- Urgent warnings for critical ciphers
- Migration timeline
- Post-quantum algorithm recommendations

```
⚠️  URGENT: 131 CRITICAL cipher suites detected!

IMMEDIATE ACTIONS REQUIRED:
  1. Disable all cipher suites marked as CRITICAL
  2. Configure TLS to prefer HIGH or QUANTUM_SAFE cipher suites
  3. Plan migration to post-quantum cryptography

POST-QUANTUM MIGRATION TIMELINE:
  • Immediate (0-6 months): Audit and disable weak ciphers
  • Short-term (6-12 months): Implement hybrid classical+PQC
  • Medium-term (1-2 years): Migrate critical systems to PQC
  • Long-term (2-5 years): Complete organizational PQC deployment
```

## Key Differences from Previous Version

| Aspect | Old Version | New Version |
|--------|-------------|-------------|
| Excel Sheets | 5 sheets (Summary, Details, Critical, Recommendations, Statistics) | **1 sheet** (All Cipher Suites) |
| Text Output | None | **New:** Comprehensive text summary |
| Data Format | Spread across multiple sheets | **Flat table** with all data in one place |
| Filtering | Limited | **Full filtering** on all 12 columns |
| Categorization | Separate sheet for critical only | **Text file** with all categories |
| Frequency Analysis | Chart-based in Excel | **Text-based** clear table |

## Benefits of New Format

### Excel Benefits
1. **Easier Analysis**: All data in one place, no switching sheets
2. **Better Filtering**: Filter by ANY attribute combination
3. **Simpler Navigation**: No confusion about which sheet to check
4. **Faster Sorting**: Sort by quantum strength, protocol, key size, etc.
5. **Complete Context**: See all attributes at once

### Text Summary Benefits
1. **Quick Overview**: See frequency distribution immediately
2. **Easy Sharing**: Plain text readable anywhere (no Excel needed)
3. **Report Generation**: Copy-paste into documents/emails
4. **Command-line Friendly**: Can grep, sed, awk the text file
5. **Version Control**: Text diffs work perfectly

## Common Use Cases

### Use Case 1: Find All AES-256 Ciphers
**Excel**: Filter column E (Encryption) for "AESGCM(256)" or "AES(256)"  
**Text**: Search for "Key Size: 256 bits"

### Use Case 2: Check TLSv1.3 Quantum Strength
**Excel**: Filter column B (Protocol) = "TLSv1.3", check column I  
**Text**: Search for "Protocol: TLSv1.3" in categorized sections

### Use Case 3: Count Critical Ciphers
**Excel**: Filter column I = "CRITICAL", see row count  
**Text**: Look at Section 1 frequency table

### Use Case 4: Generate Management Report
**Text**: Copy Section 1 (Frequency) + Section 4 (Recommendations)  
**Excel**: Export filtered HIGH/QUANTUM_SAFE ciphers

### Use Case 5: Identify Deprecated Protocols
**Text**: Section 3 shows SSLv3/TLSv1 counts  
**Excel**: Filter Protocol column, see which ciphers use old versions

## File Sizes

Typical output for OpenSSL 3.x:
- **Excel**: ~15-20 KB (158 cipher suites)
- **Text**: ~35-40 KB (includes all descriptions)

## Command Output

```bash
$ python -m src.cli scan-openssl -o analysis.xlsx --verbose

Quantum OpenSSL Cipher Suite Analyzer
==================================================

OpenSSL Version: OpenSSL 3.5.2 5 Aug 2025
Found 158 cipher suites

Quantum Strength Distribution:
  CRITICAL       :  131 ( 82.9%)
  LOW            :   18 ( 11.4%)
  HIGH           :    9 (  5.7%)

Generating Excel report...
Excel report saved to: analysis.xlsx
✓ Excel report successfully generated: analysis.xlsx

Generating text summary report...
Text summary saved to: analysis_summary.txt
✓ Text summary successfully generated: analysis_summary.txt

Report Summary:
  Excel Report:
    • All cipher suites with complete details (12 columns)
    • Color-coded quantum strength indicators
    • Sortable and filterable data
  Text Summary:
    • Frequency distribution of quantum strengths
    • Categorized lists of cipher suites by strength level
    • Statistical breakdowns and recommendations

⚠️  WARNING: 131 CRITICAL cipher suites found!
   These are vulnerable to quantum attacks and should be disabled.
```

## Exit Codes

- **0**: Success, no critical vulnerabilities
- **2**: Critical vulnerabilities found (131 in typical OpenSSL 3.x)

## Tips

1. **Excel Power Users**: Use "Format as Table" feature for even better filtering
2. **Text Analysis**: Use `grep "CATEGORY:" analysis_summary.txt` to jump between sections
3. **Automation**: Parse the text file with scripts for CI/CD integration
4. **Presentations**: Screenshot Excel color-coded column for visual impact
5. **Audits**: Include both files in security audit packages

## Example Workflow

```bash
# Step 1: Run analysis
python -m src.cli scan-openssl -o monthly_audit_2025-10.xlsx

# Step 2: Open Excel file
# - Sort by Quantum Strength (Column I)
# - Filter for CRITICAL
# - Review cipher names (Column A)

# Step 3: Read text summary
# - Check frequency distribution (Section 1)
# - Review categorized lists (Section 2)
# - Copy recommendations (Section 4) to email

# Step 4: Take action
# - Disable CRITICAL ciphers in server config
# - Prefer HIGH strength ciphers
# - Plan PQC migration based on timeline
```

## Questions?

- **Q: Can I get just the Excel without text?**  
  A: No, both are generated automatically. Just ignore the .txt file if not needed.

- **Q: Can I customize which columns appear in Excel?**  
  A: After generation, hide columns you don't need using Excel's column hide feature.

- **Q: Can I get CSV instead of Excel?**  
  A: Open the Excel file and "Save As" → CSV format.

- **Q: How do I integrate this into my CI/CD?**  
  A: Parse the text file! It's structured and grep-friendly. Exit code 2 = fail the build.

- **Q: Can I see historical trends?**  
  A: Run monthly and compare text files with `diff` or track counts in a spreadsheet.

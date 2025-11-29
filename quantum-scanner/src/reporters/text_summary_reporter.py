"""
Text Summary Reporter for OpenSSL Cipher Suite Analysis

Generates a text file summary with frequency analysis and categorized cipher lists.
"""

from typing import List, Dict
from datetime import datetime
from ..openssl_analyzer import CipherSuite, QuantumStrength


class TextSummaryReporter:
    """Generate text summary reports for OpenSSL cipher suite analysis"""
    
    def __init__(self):
        pass
    
    def generate_report(
        self,
        cipher_suites: List[CipherSuite],
        statistics: Dict,
        openssl_version: str,
        output_file: str
    ):
        """Generate text summary report with frequency and categorization"""
        
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("OPENSSL CIPHER SUITE ANALYSIS - QUANTUM STRENGTH SUMMARY")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"OpenSSL Version: {openssl_version}")
        lines.append(f"Total Cipher Suites Analyzed: {len(cipher_suites)}")
        lines.append("")
        lines.append("=" * 80)
        
        # Get strength counts for later use
        strength_counts = statistics.get('by_strength', {})
        total = len(cipher_suites)
        
        # Define order for display (most critical first)
        strength_order = ['CRITICAL', 'LOW', 'MEDIUM', 'HIGH', 'QUANTUM_SAFE']
        
        # Categorized Cipher Suite Lists
        lines.append("")
        lines.append("CIPHER SUITES BY QUANTUM STRENGTH CATEGORY")
        lines.append("=" * 80)
        
        # Group cipher suites by strength
        categorized = {}
        for cipher in cipher_suites:
            strength = cipher.quantum_strength.value
            if strength not in categorized:
                categorized[strength] = []
            categorized[strength].append(cipher)
        
        # Display each category
        for strength in strength_order:
            if strength not in categorized or len(categorized[strength]) == 0:
                continue
            
            lines.append("")
            lines.append(f"\n{'=' * 80}")
            lines.append(f"CATEGORY: {strength}")
            lines.append(f"Count: {len(categorized[strength])}")
            lines.append(f"{'=' * 80}")
            lines.append("")
            
            # Description of category
            descriptions = {
                'CRITICAL': (
                    "These cipher suites are CRITICALLY vulnerable to quantum attacks.\n"
                    "They use RSA, ECDH, or DH key exchange which can be broken by Shor's algorithm.\n"
                    "ACTION: Disable immediately and migrate to post-quantum alternatives."
                ),
                'LOW': (
                    "These cipher suites have LIMITED quantum resistance.\n"
                    "Typically AES-128 based (reduced to 64-bit security with Grover's algorithm).\n"
                    "ACTION: Plan migration within 1-2 years."
                ),
                'MEDIUM': (
                    "These cipher suites have MODERATE quantum resistance.\n"
                    "Typically AES-192 based (reduced to 96-bit security with Grover's algorithm).\n"
                    "ACTION: Plan upgrade within 3-5 years."
                ),
                'HIGH': (
                    "These cipher suites have GOOD quantum resistance.\n"
                    "Typically AES-256 based (provides 128-bit quantum security).\n"
                    "ACTION: Acceptable for current use, monitor developments."
                ),
                'QUANTUM_SAFE': (
                    "These cipher suites use POST-QUANTUM algorithms.\n"
                    "Safe against both classical and quantum attacks.\n"
                    "ACTION: Recommended for all new deployments."
                )
            }
            
            lines.append(descriptions.get(strength, ""))
            lines.append("")
            lines.append("-" * 80)
            lines.append("Cipher Suites in this category:")
            lines.append("-" * 80)
            
            # List cipher suites with details
            for idx, cipher in enumerate(sorted(categorized[strength], key=lambda x: x.name), start=1):
                lines.append(f"\n{idx}. {cipher.name}")
                lines.append(f"   Protocol: {cipher.protocol}")
                
                # Show quantum status for each component
                lines.append(f"   Key Exchange: {cipher.kx_algorithm} [{cipher.kx_quantum_status}]")
                lines.append(f"   Authentication: {cipher.auth_algorithm} [{cipher.auth_quantum_status}]")
                
                # Show encryption with key size and quantum status
                enc_detail = f"{cipher.enc_algorithm}"
                if cipher.enc_key_size:
                    enc_detail += f" ({cipher.enc_key_size}-bit)"
                enc_detail += f" [{cipher.enc_quantum_status}]"
                lines.append(f"   Encryption: {enc_detail}")
                
                # Show hash with key size and quantum status
                if cipher.hash_algorithm:
                    hash_detail = f"{cipher.hash_algorithm}"
                    if cipher.hash_key_size:
                        hash_detail += f" ({cipher.hash_key_size}-bit)"
                    hash_detail += f" [{cipher.hash_quantum_status}]"
                    lines.append(f"   Hash: {hash_detail}")
                
                lines.append(f"   Quantum Strength Score: {cipher.strength_score}/100")
        
        # Recommendations
        lines.append(f"\n\n{'=' * 80}")
        lines.append("RECOMMENDATIONS")
        lines.append("=" * 80)
        lines.append("")
        
        critical_count = strength_counts.get('CRITICAL', 0)
        if critical_count > 0:
            lines.append(f"⚠️  URGENT: {critical_count} CRITICAL cipher suites detected!")
            lines.append("")
            lines.append("IMMEDIATE ACTIONS REQUIRED:")
            lines.append("  1. Disable all cipher suites marked as CRITICAL")
            lines.append("  2. Configure TLS to prefer HIGH or QUANTUM_SAFE cipher suites")
            lines.append("  3. Plan migration to post-quantum cryptography")
            lines.append("")
        
        lines.append("POST-QUANTUM MIGRATION TIMELINE:")
        lines.append("  • Immediate (0-6 months): Audit and disable weak ciphers")
        lines.append("  • Short-term (6-12 months): Implement hybrid classical+PQC")
        lines.append("  • Medium-term (1-2 years): Migrate critical systems to PQC")
        lines.append("  • Long-term (2-5 years): Complete organizational PQC deployment")
        lines.append("")
        
        lines.append("RECOMMENDED POST-QUANTUM ALGORITHMS:")
        lines.append("  • CRYSTALS-Kyber: Key encapsulation mechanism")
        lines.append("  • CRYSTALS-Dilithium: Digital signatures")
        lines.append("  • FALCON: Compact signatures")
        lines.append("  • SPHINCS+: Hash-based signatures")
        lines.append("")
        
        # Footer
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Report generated by Quantum Vulnerability Scanner v1.0.0")
        lines.append(f"For detailed analysis, refer to the Excel report.")
        lines.append("")
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"Text summary saved to: {output_file}")

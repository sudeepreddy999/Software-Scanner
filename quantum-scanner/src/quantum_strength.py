"""
Quantum Strength Assessment Module

Provides detailed quantum security strength assessment for cryptographic algorithms
based on NIST Post-Quantum Cryptography standards and current research.
"""

from enum import Enum
from typing import Dict, Tuple
from dataclasses import dataclass


class SecurityLevel(Enum):
    """NIST Security Levels for Post-Quantum Cryptography"""
    LEVEL_1 = 1  # Equivalent to AES-128 (classical), AES-64 (quantum)
    LEVEL_2 = 2  # Equivalent to SHA-256/SHA3-256 collision resistance
    LEVEL_3 = 3  # Equivalent to AES-192 (classical), AES-96 (quantum)
    LEVEL_4 = 4  # Equivalent to SHA-384/SHA3-384 collision resistance
    LEVEL_5 = 5  # Equivalent to AES-256 (classical), AES-128 (quantum)


@dataclass
class QuantumStrengthAssessment:
    """Detailed quantum strength assessment"""
    algorithm_name: str
    classical_security_bits: int
    quantum_security_bits: int
    nist_level: SecurityLevel
    years_until_vulnerable: str
    vulnerability_type: str
    detailed_analysis: str


class QuantumStrengthEvaluator:
    """Evaluates cryptographic algorithm strength against quantum attacks"""
    
    # Grover's algorithm halves the security level of symmetric algorithms
    GROVER_REDUCTION_FACTOR = 2
    
    # Shor's algorithm breaks RSA/ECC/DH completely
    SHOR_BREAKS = ['RSA', 'ECDSA', 'ECDH', 'DSA', 'DH', 'DHE', 'ECDHE']
    
    def __init__(self):
        self.assessments_cache = {}
    
    def evaluate_rsa(self, key_size: int) -> QuantumStrengthAssessment:
        """Evaluate RSA quantum resistance"""
        
        # RSA is completely broken by Shor's algorithm
        # Classical security estimates
        classical_bits = {
            1024: 80,
            2048: 112,
            3072: 128,
            4096: 140,
            7680: 192,
            15360: 256
        }
        
        classical_security = classical_bits.get(
            key_size,
            min(256, max(80, int(key_size / 30)))  # Rough approximation
        )
        
        # Quantum security: RSA is broken by Shor's algorithm
        quantum_security = 0  # Completely vulnerable
        
        years_until_vulnerable = "Already vulnerable (quantum computers can break this)"
        vulnerability_type = "Shor's Algorithm (Number Factorization)"
        
        detailed_analysis = (
            f"RSA-{key_size} provides ~{classical_security} bits of classical security "
            f"but is completely vulnerable to quantum attacks using Shor's algorithm. "
            f"A sufficiently large quantum computer can factor the modulus and recover "
            f"the private key in polynomial time. "
            f"Current estimates suggest RSA-2048 could be broken by a quantum computer "
            f"with ~20 million qubits (within 10-20 years). "
            f"RECOMMENDATION: Migrate to post-quantum algorithms immediately."
        )
        
        return QuantumStrengthAssessment(
            algorithm_name=f"RSA-{key_size}",
            classical_security_bits=classical_security,
            quantum_security_bits=quantum_security,
            nist_level=SecurityLevel.LEVEL_1,
            years_until_vulnerable=years_until_vulnerable,
            vulnerability_type=vulnerability_type,
            detailed_analysis=detailed_analysis
        )
    
    def evaluate_ecc(self, key_size: int) -> QuantumStrengthAssessment:
        """Evaluate Elliptic Curve Cryptography quantum resistance"""
        
        # ECC classical security
        classical_bits = {
            160: 80,
            224: 112,
            256: 128,
            384: 192,
            521: 256
        }
        
        classical_security = classical_bits.get(
            key_size,
            min(256, max(80, key_size // 2))  # ECC key size ≈ 2x security bits
        )
        
        # Quantum security: ECC is broken by Shor's algorithm
        quantum_security = 0
        
        years_until_vulnerable = "Already vulnerable (quantum computers can break this)"
        vulnerability_type = "Shor's Algorithm (Discrete Logarithm)"
        
        detailed_analysis = (
            f"ECC-{key_size} (e.g., ECDSA, ECDH) provides ~{classical_security} bits "
            f"of classical security but is completely vulnerable to quantum attacks. "
            f"Shor's algorithm can solve the elliptic curve discrete logarithm problem "
            f"in polynomial time. ECC-256 (equivalent to AES-128 classically) could be "
            f"broken by a quantum computer with ~2,330 qubits (achievable within 10-15 years). "
            f"RECOMMENDATION: Replace with post-quantum key exchange (e.g., CRYSTALS-Kyber)."
        )
        
        return QuantumStrengthAssessment(
            algorithm_name=f"ECC-{key_size}",
            classical_security_bits=classical_security,
            quantum_security_bits=quantum_security,
            nist_level=SecurityLevel.LEVEL_1,
            years_until_vulnerable=years_until_vulnerable,
            vulnerability_type=vulnerability_type,
            detailed_analysis=detailed_analysis
        )
    
    def evaluate_aes(self, key_size: int) -> QuantumStrengthAssessment:
        """Evaluate AES quantum resistance"""
        
        classical_security = key_size
        
        # Grover's algorithm halves the effective key size
        quantum_security = key_size // 2
        
        # Determine NIST level
        if quantum_security >= 128:
            nist_level = SecurityLevel.LEVEL_5
            years = "20+ years"
            vulnerability = "Moderate (Grover's Algorithm)"
        elif quantum_security >= 96:
            nist_level = SecurityLevel.LEVEL_3
            years = "10-20 years"
            vulnerability = "Moderate (Grover's Algorithm)"
        else:
            nist_level = SecurityLevel.LEVEL_1
            years = "5-10 years"
            vulnerability = "Significant (Grover's Algorithm)"
        
        detailed_analysis = (
            f"AES-{key_size} provides {classical_security} bits of classical security. "
            f"Grover's algorithm reduces this to ~{quantum_security} bits of quantum security. "
        )
        
        if key_size == 128:
            detailed_analysis += (
                f"AES-128 provides only 64-bit quantum security, which is considered "
                f"borderline for long-term protection. A quantum computer with sufficient "
                f"qubits could break this in ~2^64 operations (feasible within 10-20 years). "
                f"RECOMMENDATION: Upgrade to AES-256 for better quantum resistance."
            )
        elif key_size == 192:
            detailed_analysis += (
                f"AES-192 provides 96-bit quantum security, offering moderate protection. "
                f"This should be secure for 10-20 years against quantum attacks. "
                f"RECOMMENDATION: Consider AES-256 for maximum security."
            )
        elif key_size == 256:
            detailed_analysis += (
                f"AES-256 provides 128-bit quantum security, which matches NIST PQC Level 5. "
                f"This is considered secure against quantum attacks for 20+ years. "
                f"AES-256 is recommended for quantum-resistant symmetric encryption."
            )
        
        return QuantumStrengthAssessment(
            algorithm_name=f"AES-{key_size}",
            classical_security_bits=classical_security,
            quantum_security_bits=quantum_security,
            nist_level=nist_level,
            years_until_vulnerable=years,
            vulnerability_type=vulnerability,
            detailed_analysis=detailed_analysis
        )
    
    def evaluate_3des(self) -> QuantumStrengthAssessment:
        """Evaluate 3DES quantum resistance"""
        
        classical_security = 112  # 3DES effective security
        quantum_security = 56  # Halved by Grover's algorithm
        
        detailed_analysis = (
            "3DES (Triple DES) provides only 112 bits of classical security due to "
            "meet-in-the-middle attacks. With Grover's algorithm, this is reduced to "
            "56 bits of quantum security, which is completely inadequate. "
            "3DES is deprecated and should not be used. "
            "RECOMMENDATION: Replace with AES-256 immediately."
        )
        
        return QuantumStrengthAssessment(
            algorithm_name="3DES",
            classical_security_bits=classical_security,
            quantum_security_bits=quantum_security,
            nist_level=SecurityLevel.LEVEL_1,
            years_until_vulnerable="Already vulnerable",
            vulnerability_type="Critical (Grover's Algorithm + Weak)",
            detailed_analysis=detailed_analysis
        )
    
    def evaluate_dh(self, key_size: int) -> QuantumStrengthAssessment:
        """Evaluate Diffie-Hellman quantum resistance"""
        
        classical_bits = {
            1024: 80,
            2048: 112,
            3072: 128,
            4096: 140,
            8192: 192
        }
        
        classical_security = classical_bits.get(
            key_size,
            min(192, max(80, key_size // 30))
        )
        
        quantum_security = 0  # Broken by Shor's algorithm
        
        detailed_analysis = (
            f"Diffie-Hellman {key_size}-bit provides ~{classical_security} bits of "
            f"classical security but is completely broken by Shor's algorithm. "
            f"The discrete logarithm problem can be solved in polynomial time on "
            f"a quantum computer. DH-2048 could be broken by a quantum computer "
            f"with ~20 million qubits (within 10-20 years). "
            f"RECOMMENDATION: Migrate to post-quantum key exchange (CRYSTALS-Kyber, NTRU)."
        )
        
        return QuantumStrengthAssessment(
            algorithm_name=f"DH-{key_size}",
            classical_security_bits=classical_security,
            quantum_security_bits=quantum_security,
            nist_level=SecurityLevel.LEVEL_1,
            years_until_vulnerable="Already vulnerable",
            vulnerability_type="Shor's Algorithm (Discrete Logarithm)",
            detailed_analysis=detailed_analysis
        )
    
    def evaluate_hash(self, algorithm: str, output_size: int) -> QuantumStrengthAssessment:
        """Evaluate hash algorithm quantum resistance"""
        
        classical_security = output_size // 2  # Collision resistance
        quantum_security = output_size // 3  # Grover's algorithm for collision finding
        
        if 'MD5' in algorithm.upper():
            detailed_analysis = (
                "MD5 is cryptographically broken even against classical attacks. "
                "It should never be used for security purposes. "
                "RECOMMENDATION: Replace with SHA-256 or SHA-3."
            )
            years = "Already broken"
            vulnerability = "Critical (Broken classically)"
        elif 'SHA1' in algorithm.upper() or algorithm.upper() == 'SHA':
            detailed_analysis = (
                "SHA-1 is deprecated and vulnerable to collision attacks. "
                "Quantum computers with Grover's algorithm would further reduce security. "
                "RECOMMENDATION: Upgrade to SHA-256 or SHA-3 immediately."
            )
            years = "Already vulnerable"
            vulnerability = "Critical (Weak + Grover's)"
        elif 'SHA256' in algorithm.upper() or 'SHA-256' in algorithm.upper():
            detailed_analysis = (
                "SHA-256 provides 128 bits of classical collision resistance, "
                "reduced to ~85 bits against quantum attacks. This is still adequate "
                "for most applications in the near-term (10-15 years). "
                "RECOMMENDATION: Acceptable for current use, monitor developments."
            )
            years = "10-15 years"
            vulnerability = "Low (Grover's Algorithm)"
        elif 'SHA384' in algorithm.upper() or 'SHA-384' in algorithm.upper():
            detailed_analysis = (
                "SHA-384 provides 192 bits of classical collision resistance, "
                "reduced to ~128 bits against quantum attacks. This provides excellent "
                "quantum resistance for 20+ years. "
                "RECOMMENDATION: Secure for long-term use."
            )
            years = "20+ years"
            vulnerability = "Very Low (Grover's Algorithm)"
        else:
            detailed_analysis = f"{algorithm} hash algorithm analysis."
            years = "Unknown"
            vulnerability = "Unknown"
        
        return QuantumStrengthAssessment(
            algorithm_name=algorithm,
            classical_security_bits=classical_security,
            quantum_security_bits=quantum_security,
            nist_level=SecurityLevel.LEVEL_3 if quantum_security >= 96 else SecurityLevel.LEVEL_1,
            years_until_vulnerable=years,
            vulnerability_type=vulnerability,
            detailed_analysis=detailed_analysis
        )
    
    def evaluate_cipher_suite(
        self,
        kx_algorithm: str,
        auth_algorithm: str,
        enc_algorithm: str,
        key_size: int = None
    ) -> Dict[str, QuantumStrengthAssessment]:
        """Evaluate complete cipher suite quantum resistance"""
        
        assessments = {}
        
        # Evaluate key exchange
        if 'ECDH' in kx_algorithm.upper():
            assessments['key_exchange'] = self.evaluate_ecc(256)  # Common size
        elif 'DH' in kx_algorithm.upper():
            assessments['key_exchange'] = self.evaluate_dh(2048)  # Common size
        elif 'RSA' in kx_algorithm.upper():
            assessments['key_exchange'] = self.evaluate_rsa(2048)
        
        # Evaluate authentication
        if 'RSA' in auth_algorithm.upper():
            assessments['authentication'] = self.evaluate_rsa(2048)
        elif 'ECDSA' in auth_algorithm.upper():
            assessments['authentication'] = self.evaluate_ecc(256)
        
        # Evaluate encryption
        if 'AES' in enc_algorithm.upper() and key_size:
            assessments['encryption'] = self.evaluate_aes(key_size)
        elif '3DES' in enc_algorithm.upper():
            assessments['encryption'] = self.evaluate_3des()
        
        return assessments

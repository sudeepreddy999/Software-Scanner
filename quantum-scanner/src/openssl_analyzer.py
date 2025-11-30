"""
OpenSSL Cipher Suite Analyzer

This module analyzes OpenSSL's available cipher suites and extracts detailed
information about algorithms, key sizes, hashing algorithms, and quantum resistance.
"""

import subprocess
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class QuantumStrength(Enum):
    """Quantum resistance strength levels"""
    CRITICAL = "CRITICAL"  # Broken by quantum computers
    LOW = "LOW"  # < 5 years protection
    MEDIUM = "MEDIUM"  # 5-10 years protection
    HIGH = "HIGH"  # 10-20 years protection
    QUANTUM_SAFE = "QUANTUM_SAFE"  # Post-quantum algorithms


@dataclass
class CipherSuite:
    """Represents a cipher suite with all its properties"""
    name: str
    protocol: str
    kx_algorithm: str  # Key exchange algorithm
    auth_algorithm: str  # Authentication algorithm
    enc_algorithm: str  # Encryption algorithm
    mac_algorithm: str  # MAC algorithm
    
    # Key sizes
    enc_key_size: Optional[int]  # Encryption key size in bits
    hash_key_size: Optional[int]  # Hash output size in bits
    
    # Quantum status for each component
    kx_quantum_status: str  # "Quantum-Safe" or "Quantum-Vulnerable"
    auth_quantum_status: str  # "Quantum-Safe" or "Quantum-Vulnerable"
    enc_quantum_status: str  # "Quantum-Safe" or "Quantum-Vulnerable" (based on √n ≥ 128)
    hash_quantum_status: str  # "Quantum-Safe" or "Quantum-Vulnerable" (based on √n ≥ 128)
    
    # Legacy fields for backward compatibility
    key_size: Optional[int]
    hash_algorithm: Optional[str]
    quantum_strength: QuantumStrength
    strength_score: int  # 0-100
    description: str
    recommendation: str


class OpenSSLAnalyzer:
    """Analyzes OpenSSL cipher suites and their quantum resistance"""
    
    def __init__(self):
        self.cipher_suites: List[CipherSuite] = []
        
    def check_openssl_available(self) -> bool:
        """Check if OpenSSL is available on the system"""
        try:
            result = subprocess.run(
                ['openssl', 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_openssl_version(self) -> str:
        """Get OpenSSL version"""
        try:
            result = subprocess.run(
                ['openssl', 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return "Unknown"
        except Exception:
            return "Unknown"
    
    def get_available_ciphers(self) -> List[str]:
        """Get list of all available cipher suites from OpenSSL"""
        try:
            result = subprocess.run(
                ['openssl', 'ciphers', '-v', 'ALL:COMPLEMENTOFALL'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                cipher_lines = result.stdout.strip().split('\n')
                return [line for line in cipher_lines if line.strip()]
            return []
        except Exception as e:
            print(f"Error getting cipher list: {e}")
            return []
    
    def parse_cipher_line(self, cipher_line: str) -> Optional[CipherSuite]:

        
        parts = cipher_line.split()
        if len(parts) < 5:
            return None
        
        name = parts[0]
        protocol = parts[1] if len(parts) > 1 else "Unknown"
        

        kx_match = re.search(r'Kx=(\S+)', cipher_line)
        kx_algorithm = kx_match.group(1) if kx_match else "Unknown"
        

        au_match = re.search(r'Au=(\S+)', cipher_line)
        auth_algorithm = au_match.group(1) if au_match else "Unknown"
        

        enc_match = re.search(r'Enc=(\S+)', cipher_line)
        enc_algorithm = enc_match.group(1) if enc_match else "Unknown"
        

        mac_match = re.search(r'Mac=(\S+)', cipher_line)
        mac_algorithm = mac_match.group(1) if mac_match else "Unknown"
        

        enc_key_size = self._extract_key_size(enc_algorithm, name)
        

        hash_algorithm = self._extract_hash_algorithm(name, mac_algorithm)
        hash_key_size = self._extract_hash_key_size(hash_algorithm)
        

        kx_quantum_status = self._classify_kx_quantum_status(kx_algorithm)
        auth_quantum_status = self._classify_auth_quantum_status(auth_algorithm)
        enc_quantum_status = self._classify_enc_quantum_status(enc_algorithm, enc_key_size)
        hash_quantum_status = self._classify_hash_quantum_status(hash_algorithm, hash_key_size)
        

        quantum_strength, strength_score = self._assess_quantum_strength(
            kx_algorithm, auth_algorithm, enc_algorithm, enc_key_size
        )
        

        description = self._generate_description(
            kx_algorithm, auth_algorithm, enc_algorithm, enc_key_size
        )
        recommendation = self._generate_recommendation(quantum_strength)
        
        return CipherSuite(
            name=name,
            protocol=protocol,
            kx_algorithm=kx_algorithm,
            auth_algorithm=auth_algorithm,
            enc_algorithm=enc_algorithm,
            mac_algorithm=mac_algorithm,
            enc_key_size=enc_key_size,
            hash_key_size=hash_key_size,
            kx_quantum_status=kx_quantum_status,
            auth_quantum_status=auth_quantum_status,
            enc_quantum_status=enc_quantum_status,
            hash_quantum_status=hash_quantum_status,
            key_size=enc_key_size,  # Legacy field
            hash_algorithm=hash_algorithm,
            quantum_strength=quantum_strength,
            strength_score=strength_score,
            description=description,
            recommendation=recommendation
        )
    
    def _extract_key_size(self, enc_algorithm: str, cipher_name: str) -> Optional[int]:

        match = re.search(r'\((\d+)\)', enc_algorithm)
        if match:
            return int(match.group(1))
        
  
        match = re.search(r'AES(\d+)', cipher_name, re.IGNORECASE)
        if match:
            return int(match.group(1))
        
        match = re.search(r'3DES|DES-CBC3', cipher_name, re.IGNORECASE)
        if match:
            return 168
        
        match = re.search(r'RC4', cipher_name, re.IGNORECASE)
        if match:
            return 128
        
        return None
    
    def _extract_hash_algorithm(self, cipher_name: str, mac_algorithm: str) -> Optional[str]:

        if 'AEAD' in mac_algorithm:
            return 'AEAD'
        

        if 'SHA384' in cipher_name:
            return 'SHA384'
        elif 'SHA256' in cipher_name:
            return 'SHA256'
        elif 'SHA' in cipher_name:
            return 'SHA1'
        elif 'MD5' in cipher_name:
            return 'MD5'
        
        return mac_algorithm
    
    def _extract_hash_key_size(self, hash_algorithm: Optional[str]) -> Optional[int]:

        if not hash_algorithm:
            return None
        
        hash_upper = hash_algorithm.upper()
        
        # SHA family
        if 'SHA512' in hash_upper:
            return 512
        elif 'SHA384' in hash_upper:
            return 384
        elif 'SHA256' in hash_upper:
            return 256
        elif 'SHA224' in hash_upper:
            return 224
        elif 'SHA1' in hash_upper or hash_upper == 'SHA':
            return 160
        
        # MD5
        elif 'MD5' in hash_upper:
            return 128
        

        elif 'AEAD' in hash_upper:
            return None
        
        return None
    
    def _classify_kx_quantum_status(self, kx_algorithm: str) -> str:

        kx_upper = kx_algorithm.upper()
        

        pq_algorithms = ['KYBER', 'DILITHIUM', 'FALCON', 'SPHINCS', 'NTRU', 'MCELIECE', 'FRODOKEM']
        if any(alg in kx_upper for alg in pq_algorithms):
            return "Quantum-Safe"
        

        vulnerable_patterns = ['RSA', 'ECDH', 'ECDHE', 'DH', 'DHE', 'DSS']
        if any(pattern in kx_upper for pattern in vulnerable_patterns):
            return "Quantum-Vulnerable"
        

        return "Quantum-Vulnerable"
    
    def _classify_auth_quantum_status(self, auth_algorithm: str) -> str:
       
        auth_upper = auth_algorithm.upper()
        

        pq_algorithms = ['DILITHIUM', 'FALCON', 'SPHINCS', 'KYBER']
        if any(alg in auth_upper for alg in pq_algorithms):
            return "Quantum-Safe"
        

        vulnerable_patterns = ['RSA', 'ECDSA', 'DSA', 'DSS']
        if any(pattern in auth_upper for pattern in vulnerable_patterns):
            return "Quantum-Vulnerable"
        

        return "Quantum-Vulnerable"
    
    def _classify_enc_quantum_status(self, enc_algorithm: str, key_size: Optional[int]) -> str:
        
        if not key_size:
            return "Quantum-Vulnerable"  
        

        quantum_security = key_size / 2
        
       
        if quantum_security >= 128:
            return "Quantum-Safe"
        else:
            return "Quantum-Vulnerable"
    
    def _classify_hash_quantum_status(self, hash_algorithm: Optional[str], hash_key_size: Optional[int]) -> str:
        
        if not hash_key_size:
            return "Quantum-Vulnerable"  
        
        
        quantum_security = hash_key_size / 2
        
        
        if quantum_security >= 128:
            return "Quantum-Safe"
        else:
            return "Quantum-Vulnerable"
    
    def _assess_quantum_strength(
        self, 
        kx_algorithm: str, 
        auth_algorithm: str, 
        enc_algorithm: str, 
        key_size: Optional[int]
    ) -> tuple[QuantumStrength, int]:
        
        pq_algorithms = ['KYBER', 'DILITHIUM', 'FALCON', 'SPHINCS', 'NTRU']
        if any(alg in kx_algorithm.upper() for alg in pq_algorithms):
            return QuantumStrength.QUANTUM_SAFE, 100
        
        
        critical_patterns = [
            'RSA', 'ECDH', 'ECDSA', 'DH', 'DHE', 'DSS', 'ECDHE'
        ]
        
        if any(pattern in kx_algorithm.upper() for pattern in critical_patterns):
         
            if 'RSA' in kx_algorithm.upper() or 'RSA' in auth_algorithm.upper():
                return QuantumStrength.CRITICAL, 10
            if 'ECDH' in kx_algorithm.upper() or 'ECDSA' in auth_algorithm.upper():
                return QuantumStrength.CRITICAL, 10
            if 'DHE' in kx_algorithm.upper() or 'DH' in kx_algorithm.upper():
                return QuantumStrength.CRITICAL, 15
        
        
        if key_size:
            if 'AES' in enc_algorithm.upper():
                if key_size >= 256:
                    return QuantumStrength.HIGH, 80  
                elif key_size >= 192:
                    return QuantumStrength.MEDIUM, 60
                elif key_size >= 128:
                    return QuantumStrength.LOW, 40  
            
            if '3DES' in enc_algorithm.upper():
                return QuantumStrength.CRITICAL, 20  
        
      
        return QuantumStrength.LOW, 25
    
    def _generate_description(
        self,
        kx_algorithm: str,
        auth_algorithm: str,
        enc_algorithm: str,
        key_size: Optional[int]
    ) -> str:
       
        parts = []
        
        if kx_algorithm != "Unknown":
            parts.append(f"Key Exchange: {kx_algorithm}")
        if auth_algorithm != "Unknown":
            parts.append(f"Authentication: {auth_algorithm}")
        if enc_algorithm != "Unknown":
            enc_str = f"Encryption: {enc_algorithm}"
            if key_size:
                enc_str += f" ({key_size}-bit)"
            parts.append(enc_str)
        
        return ", ".join(parts) if parts else "Cipher suite details"
    
    def _generate_recommendation(self, quantum_strength: QuantumStrength) -> str:
        
        recommendations = {
            QuantumStrength.CRITICAL: "URGENT: Replace immediately. Vulnerable to quantum attacks using Shor's algorithm. Migrate to post-quantum cryptography.",
            QuantumStrength.LOW: "HIGH PRIORITY: Replace soon. Limited quantum resistance. Plan migration to post-quantum algorithms within 1-2 years.",
            QuantumStrength.MEDIUM: "MEDIUM PRIORITY: Monitor and plan replacement. Provides moderate quantum resistance but should be upgraded within 3-5 years.",
            QuantumStrength.HIGH: "LOW PRIORITY: Acceptable for near-term use. AES-256 provides good quantum resistance but consider post-quantum alternatives for long-term security.",
            QuantumStrength.QUANTUM_SAFE: "RECOMMENDED: Post-quantum algorithm. Safe against both classical and quantum attacks."
        }
        return recommendations.get(quantum_strength, "Evaluate and consider alternatives.")
    
    def analyze(self) -> Dict[str, any]:
        
        if not self.check_openssl_available():
            return {
                'error': 'OpenSSL not found on system',
                'cipher_suites': []
            }
        
        version = self.get_openssl_version()
        cipher_lines = self.get_available_ciphers()
        
        self.cipher_suites = []
        for line in cipher_lines:
            cipher = self.parse_cipher_line(line)
            if cipher:
                self.cipher_suites.append(cipher)
        
        
        stats = self._generate_statistics()
        
        return {
            'openssl_version': version,
            'total_ciphers': len(self.cipher_suites),
            'cipher_suites': self.cipher_suites,
            'statistics': stats
        }
    
    def _generate_statistics(self) -> Dict[str, any]:
        
        if not self.cipher_suites:
            return {}
        
        strength_counts = {
            'CRITICAL': 0,
            'LOW': 0,
            'MEDIUM': 0,
            'HIGH': 0,
            'QUANTUM_SAFE': 0
        }
        
        protocol_counts = {}
        kx_counts = {}
        enc_counts = {}
        
        for cipher in self.cipher_suites:
            strength_counts[cipher.quantum_strength.value] += 1
            protocol_counts[cipher.protocol] = protocol_counts.get(cipher.protocol, 0) + 1
            kx_counts[cipher.kx_algorithm] = kx_counts.get(cipher.kx_algorithm, 0) + 1
            enc_counts[cipher.enc_algorithm] = enc_counts.get(cipher.enc_algorithm, 0) + 1
        
        return {
            'by_strength': strength_counts,
            'by_protocol': protocol_counts,
            'by_key_exchange': kx_counts,
            'by_encryption': enc_counts
        }

"""
Base Detector Class
Abstract base class for language-specific vulnerability detectors
"""

import re
from abc import ABC, abstractmethod
from typing import List
from ..vulnerability_db import VulnerabilityDatabase, VulnerabilitySignature
from ..scanner import Finding


class BaseDetector(ABC):
    """Abstract base class for language-specific detectors"""
    
    def __init__(self, vuln_db: VulnerabilityDatabase, language: str):
        self.vuln_db = vuln_db
        self.language = language
        self.signatures = vuln_db.get_signatures_by_language(language)
    
    @abstractmethod
    def detect(self, file_path: str, content: str) -> List[Finding]:
        """
        Detect vulnerabilities in file content
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of Finding objects
        """
        pass
    
    def _regex_search(self, file_path: str, content: str) -> List[Finding]:
        """
        Perform regex-based pattern matching on content
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of Finding objects
        """
        findings = []
        lines = content.split('\n')
        
        for signature in self.signatures:
            for pattern in signature.patterns:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                    
                    for line_num, line in enumerate(lines, start=1):
                        if regex.search(line):
                            # Try to extract key size from the same line context
                            key_size = self._extract_key_size_from_line(line)
                            confidence = 'high' if key_size else 'low'
                            # Adjust severity based on key size
                            severity = self.vuln_db.get_severity_for_algorithm_and_size(
                                signature.algorithm, key_size
                            )
                            finding = Finding(
                                file_path=file_path,
                                line_number=line_num,
                                algorithm=signature.algorithm,
                                severity=severity,
                                matched_pattern=pattern,
                                line_content=line,
                                description=signature.description,
                                recommendation=signature.recommendation,
                                key_size=key_size,
                                confidence=confidence
                            )
                            findings.append(finding)
                
                except re.error:
                    # Skip invalid regex patterns
                    continue
        
        return findings

    def _extract_key_size_from_line(self, line: str):
        """Best-effort extraction of key size from a code/config line.
        Looks for common patterns across ALL cryptographic algorithms and languages.
        Returns int key size if found, else None.
        """
        patterns = [
            # === Generic patterns (works for any algorithm) ===
            # 'xxxx bits' or 'xxx-bit' or 'xxx bit'
            r"\b(\d{3,5})\s*-?\s*bits?\b",
            
            # key_size/keySize/key-size parameter (Python, Go, general)
            r"key[_-]?size\s*[:=]\s*(\d{3,5})",
            
            # size/keylen/keylength parameter
            r"(?:key)?(?:len|length|size)\s*[:=]\s*(\d{3,5})",
            
            # === Algorithm-agnostic function patterns ===
            # generate/Generate functions: .generate(2048), .Generate(4096)
            r"\.?[Gg]enerate(?:Key)?(?:Pair)?\s*\(\s*(\d{3,5})\s*[,)]",
            
            # initialize/init: .initialize(2048), init(3072)
            r"\.?(?:initialize|init)\s*\(\s*(\d{3,5})\s*[,)]",
            
            # === JavaScript/Node.js patterns ===
            # modulusLength (RSA), namedCurve with size hints
            r"modulusLength\s*[:=]\s*(\d{3,5})",
            
            # === Java patterns ===
            # KeyPairGenerator.initialize(2048)
            r"initialize\s*\(\s*(\d{3,5})\s*\)",
            
            # KeyPairGenerator.getInstance(...).initialize(2048)
            r"getInstance\s*\([^)]+\)\s*\.initialize\s*\(\s*(\d{3,5})\s*\)",
            
            # === Python patterns ===
            # RSA.generate(2048), DSA.generate(2048), DH.generate(2048)
            r"(?:RSA|DSA|DH|ECC|ECDSA)\.generate\s*\(\s*(\d{3,5})\s*\)",
            
            # cryptography: rsa.generate_private_key(..., key_size=2048)
            r"generate_private_key\s*\([^)]*key_size\s*=\s*(\d{3,5})",
            
            # === Go patterns ===
            # rsa.GenerateKey(rand.Reader, 2048)
            r"GenerateKey\s*\([^,]+,\s*(\d{3,5})\s*[,)]",
            
            # rsa.GenerateMultiPrimeKey(rand.Reader, nprimes, 3072)
            r"GenerateMultiPrimeKey\s*\([^,]+,\s*\d+\s*,\s*(\d{3,5})\s*[,)]",
            
            # ecdsa.GenerateKey(elliptic.P256(), rand.Reader) - curve implies size
            # We'll try to extract from curve names in a separate pass
            
            # === C/C++/OpenSSL patterns ===
            # RSA_generate_key(2048, ...)
            r"RSA_generate_key\s*\(\s*(\d{3,5})\s*,",
            
            # RSA_generate_key_ex(rsa, 2048, ...)
            r"RSA_generate_key_ex\s*\([^,]+,\s*(\d{3,5})\s*,",
            
            # DH_generate_parameters(2048, ...)
            r"DH_generate_parameters(?:_ex)?\s*\([^,]*,?\s*(\d{3,5})\s*,",
            
            # DSA_generate_parameters(2048, ...)
            r"DSA_generate_parameters(?:_ex)?\s*\([^,]*,?\s*(\d{3,5})\s*,",
            
            # EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048)
            r"set_rsa_keygen_bits\s*\([^,]+,\s*(\d{3,5})\s*\)",
            
            # === .NET patterns ===
            # new RSACryptoServiceProvider(2048)
            r"(?:RSA|DSA)CryptoServiceProvider\s*\(\s*(\d{3,5})\s*\)",
            
            # RSA.Create(2048)
            r"(?:RSA|DSA|ECDsa)\.Create\s*\(\s*(\d{3,5})\s*\)",
            
            # === Config file patterns ===
            # key-size: 2048, keysize=2048
            r"key[-_]?size\s*[:=]\s*(\d{3,5})",
            
            # bits: 2048, bits=2048
            r"bits\s*[:=]\s*(\d{3,5})",
            
            # === Curve-based patterns (for ECC/ECDSA) ===
            # Extract size from curve names: P-256, P-384, P-521, secp256r1, prime256v1
            r"[Pp]-?(\d{3})",  # P-256, P256, p-384
            r"secp(\d{3})r1",  # secp256r1, secp384r1
            r"prime(\d{3})v1", # prime256v1
            
            # brainpool curves: brainpoolP256r1
            r"brainpool[Pp](\d{3})r1",
        ]
        
        # First pass: try all numeric patterns
        for pat in patterns:
            try:
                m = re.search(pat, line, flags=re.IGNORECASE)
                if m:
                    try:
                        size = int(m.group(1))
                        # Sanity check: key sizes typically between 128 and 16384
                        if 128 <= size <= 16384:
                            return size
                    except (ValueError, IndexError):
                        continue
            except re.error:
                continue
        
        # Second pass: extract from named curves (ECC/ECDSA)
        curve_sizes = {
            # NIST curves
            'p-192': 192, 'p192': 192, 'secp192r1': 192, 'prime192v1': 192,
            'p-224': 224, 'p224': 224, 'secp224r1': 224,
            'p-256': 256, 'p256': 256, 'secp256r1': 256, 'prime256v1': 256,
            'p-384': 384, 'p384': 384, 'secp384r1': 384,
            'p-521': 521, 'p521': 521, 'secp521r1': 521,
            # Brainpool curves
            'brainpoolp256r1': 256, 'brainpoolp384r1': 384, 'brainpoolp512r1': 512,
            # Other common curves
            'secp256k1': 256,  # Bitcoin curve
        }
        
        line_lower = line.lower()
        for curve_name, size in curve_sizes.items():
            if curve_name in line_lower:
                return size
        
        return None

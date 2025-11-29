"""
C/C++ Detector
Detects quantum-vulnerable cryptography in C/C++ code (primarily OpenSSL)
"""

from typing import List
from .base_detector import BaseDetector
from ..vulnerability_db import VulnerabilityDatabase
from ..scanner import Finding


class CCppDetector(BaseDetector):
    """Detector for C/C++ code"""
    
    def __init__(self, vuln_db: VulnerabilityDatabase):
        super().__init__(vuln_db, "c_cpp")
    
    def detect(self, file_path: str, content: str) -> List[Finding]:
        """
        Detect vulnerabilities in C/C++ code
        """
        findings = self._regex_search(file_path, content)
        findings.extend(self._detect_openssl_usage(file_path, content))
        
        return self._deduplicate_findings(findings)
    
    def _detect_openssl_usage(self, file_path: str, content: str) -> List[Finding]:
        """Detect OpenSSL API usage patterns"""
        findings = []
        lines = content.split('\n')
        
        import re
        from ..vulnerability_db import Severity
        
        # OpenSSL function patterns
        openssl_patterns = {
            'RSA': [
                r'RSA_new\s*\(',
                r'RSA_generate_key\s*\(',
                r'RSA_generate_key_ex\s*\(',
                r'RSA_public_encrypt\s*\(',
                r'RSA_private_decrypt\s*\(',
                r'RSA_sign\s*\(',
                r'PEM_read_RSAPrivateKey\s*\(',
            ],
            'ECDSA': [
                r'EC_KEY_new\s*\(',
                r'EC_KEY_generate_key\s*\(',
                r'ECDSA_sign\s*\(',
                r'ECDSA_verify\s*\(',
                r'EC_KEY_new_by_curve_name\s*\(',
            ],
            'DSA': [
                r'DSA_new\s*\(',
                r'DSA_generate_parameters\s*\(',
                r'DSA_generate_key\s*\(',
                r'DSA_sign\s*\(',
            ],
            'DH': [
                r'DH_new\s*\(',
                r'DH_generate_parameters\s*\(',
                r'DH_generate_key\s*\(',
                r'DH_compute_key\s*\(',
            ]
        }
        
        for algorithm, patterns in openssl_patterns.items():
            for pattern in patterns:
                try:
                    regex = re.compile(pattern)
                    for line_num, line in enumerate(lines, start=1):
                        if regex.search(line):
                            sig = self.vuln_db.get_signature_by_algorithm(algorithm)
                            if sig:
                                # Extract key size if present on the same line
                                key_size = self._extract_key_size_from_line(line)
                                confidence = 'high' if key_size else 'low'
                                # Adjust severity based on key size
                                severity = self.vuln_db.get_severity_for_algorithm_and_size(algorithm, key_size)
                                finding = Finding(
                                    file_path=file_path,
                                    line_number=line_num,
                                    algorithm=f"{algorithm} (OpenSSL)",
                                    severity=severity,
                                    matched_pattern=pattern,
                                    line_content=line.strip(),
                                    description=sig.description,
                                    recommendation=f"{sig.recommendation} Consider using liboqs (Open Quantum Safe) library.",
                                    key_size=key_size,
                                    confidence=confidence
                                )
                                findings.append(finding)
                except re.error:
                    continue
        
        return findings
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings, prefer entries with key_size/high confidence"""
        best = {}
        for f in findings:
            key = (f.file_path, f.line_number, f.algorithm)
            prev = best.get(key)
            if not prev:
                best[key] = f
            else:
                prev_score = (1 if getattr(prev, 'key_size', None) else 0, 1 if getattr(prev, 'confidence', '') == 'high' else 0)
                curr_score = (1 if getattr(f, 'key_size', None) else 0, 1 if getattr(f, 'confidence', '') == 'high' else 0)
                if curr_score > prev_score:
                    best[key] = f
        return list(best.values())

    def _extract_key_size_from_line(self, line: str):
        from .base_detector import BaseDetector
        return BaseDetector._extract_key_size_from_line(self, line)

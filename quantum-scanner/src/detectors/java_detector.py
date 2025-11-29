"""
Java Detector
Detects quantum-vulnerable cryptography in Java code
"""

from typing import List
from .base_detector import BaseDetector
from ..vulnerability_db import VulnerabilityDatabase
from ..scanner import Finding


class JavaDetector(BaseDetector):
    """Detector for Java code"""
    
    def __init__(self, vuln_db: VulnerabilityDatabase):
        super().__init__(vuln_db, "java")
    
    def detect(self, file_path: str, content: str) -> List[Finding]:
        """
        Detect vulnerabilities in Java code using regex patterns
        """
        # Use base regex search
        findings = self._regex_search(file_path, content)
        
        # Additional Java-specific detection
        findings.extend(self._detect_jce_usage(file_path, content))
        
        return self._deduplicate_findings(findings)
    
    def _detect_jce_usage(self, file_path: str, content: str) -> List[Finding]:
        """Detect Java Cryptography Extension usage patterns"""
        findings = []
        lines = content.split('\n')
        
        # Common JCE vulnerable patterns
        jce_patterns = {
            'RSA': [
                r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']\s*\)',
                r'Cipher\.getInstance\s*\(\s*["\']RSA',
                r'KeyFactory\.getInstance\s*\(\s*["\']RSA["\']\s*\)',
            ],
            'ECDSA': [
                r'KeyPairGenerator\.getInstance\s*\(\s*["\']EC["\']\s*\)',
                r'Signature\.getInstance\s*\(\s*["\'][^"\']*ECDSA[^"\']*["\']\s*\)',
                r'ECGenParameterSpec',
            ],
            'DSA': [
                r'KeyPairGenerator\.getInstance\s*\(\s*["\']DSA["\']\s*\)',
                r'Signature\.getInstance\s*\(\s*["\'][^"\']*DSA[^"\']*["\']\s*\)',
            ],
            'DH': [
                r'KeyAgreement\.getInstance\s*\(\s*["\']DH["\']\s*\)',
                r'KeyPairGenerator\.getInstance\s*\(\s*["\']DiffieHellman["\']\s*\)',
                r'DHParameterSpec',
            ]
        }
        
        import re
        from ..vulnerability_db import Severity
        
        for algorithm, patterns in jce_patterns.items():
            for pattern in patterns:
                try:
                    regex = re.compile(pattern)
                    for line_num, line in enumerate(lines, start=1):
                        if regex.search(line):
                            # Get signature for this algorithm
                            sig = self.vuln_db.get_signature_by_algorithm(algorithm)
                            if sig:
                                # Try extract key size from this or nearby lines
                                key_size = self._extract_key_size_from_line(line)
                                if key_size is None:
                                    # Look ahead a few lines for initialize(XXXX)
                                    lookahead_text = "\n".join(lines[line_num-1: min(line_num+4, len(lines))])
                                    key_size = self._extract_key_size_from_line(lookahead_text)
                                confidence = 'high' if key_size else 'low'
                                # Adjust severity based on key size
                                severity = self.vuln_db.get_severity_for_algorithm_and_size(algorithm, key_size)
                                finding = Finding(
                                    file_path=file_path,
                                    line_number=line_num,
                                    algorithm=algorithm,
                                    severity=severity,
                                    matched_pattern=pattern,
                                    line_content=line.strip(),
                                    description=sig.description,
                                    recommendation=sig.recommendation,
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
        # Use BaseDetector helper without inheritance here
        return BaseDetector._extract_key_size_from_line(self, line)

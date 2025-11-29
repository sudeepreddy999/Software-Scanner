"""
Python Detector
Detects quantum-vulnerable cryptography in Python code using AST parsing and regex
"""

import ast
import re
from typing import List, Set
from .base_detector import BaseDetector
from ..vulnerability_db import VulnerabilityDatabase, Severity
from ..scanner import Finding


class PythonDetector(BaseDetector):
    """Detector for Python code"""
    
    def __init__(self, vuln_db: VulnerabilityDatabase):
        super().__init__(vuln_db, "python")
    
    def detect(self, file_path: str, content: str) -> List[Finding]:
        """
        Detect vulnerabilities in Python code
        
        Combines AST-based import detection with regex pattern matching
        """
        findings = []
        
        # Regex-based detection (covers most cases)
        findings.extend(self._regex_search(file_path, content))
        
        # AST-based detection (more accurate for imports and function calls)
        try:
            findings.extend(self._ast_detect(file_path, content))
        except SyntaxError:
            # If AST parsing fails, rely on regex results
            pass
        
        # Remove duplicates based on line number and algorithm
        unique_findings = self._deduplicate_findings(findings)
        
        return unique_findings
    
    def _ast_detect(self, file_path: str, content: str) -> List[Finding]:
        """Use AST parsing to detect vulnerable imports and function calls"""
        findings = []
        
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings
        
        # Track imported crypto modules
        crypto_imports = self._extract_crypto_imports(tree)
        
        # Detect vulnerable patterns in imports
        lines = content.split('\n')
        
        for node in ast.walk(tree):
            # Check imports
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                
                # Check for vulnerable crypto library imports
                if self._is_vulnerable_import(module, node.names):
                    line_num = node.lineno
                    if line_num <= len(lines):
                        line_content = lines[line_num - 1]
                        
                        # Determine which algorithm
                        algorithm, description, recommendation = self._classify_python_import(
                            module, node.names
                        )
                        
                        if algorithm:
                            # Attempt to extract key size from the same line text
                            key_size = self._extract_key_size_from_line(line_content)
                            confidence = 'high' if key_size else 'low'
                            # Adjust severity based on key size
                            severity = self.vuln_db.get_severity_for_algorithm_and_size(algorithm, key_size)
                            finding = Finding(
                                file_path=file_path,
                                line_number=line_num,
                                algorithm=algorithm,
                                severity=severity,
                                matched_pattern=f"import from {module}",
                                line_content=line_content,
                                description=description,
                                recommendation=recommendation,
                                key_size=key_size,
                                confidence=confidence
                            )
                            findings.append(finding)
            
            # Check function calls
            elif isinstance(node, ast.Call):
                if self._is_vulnerable_call(node, crypto_imports):
                    line_num = node.lineno
                    if line_num <= len(lines):
                        line_content = lines[line_num - 1]
                        
                        algorithm, description, recommendation = self._classify_python_call(node)
                        
                        if algorithm:
                            # Try to extract key size from AST first, fallback to line text
                            key_size = self._extract_key_size_from_call(node)
                            if key_size is None:
                                key_size = self._extract_key_size_from_line(line_content)
                            confidence = 'high' if key_size else 'low'
                            # Adjust severity based on key size
                            severity = self.vuln_db.get_severity_for_algorithm_and_size(algorithm, key_size)
                            finding = Finding(
                                file_path=file_path,
                                line_number=line_num,
                                algorithm=algorithm,
                                severity=severity,
                                matched_pattern="function call",
                                line_content=line_content,
                                description=description,
                                recommendation=recommendation,
                                key_size=key_size,
                                confidence=confidence
                            )
                            findings.append(finding)
        
        return findings
    
    def _extract_crypto_imports(self, tree: ast.AST) -> Set[str]:
        """Extract all cryptography-related imports"""
        crypto_imports = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(crypto_lib in alias.name.lower() 
                           for crypto_lib in ['crypto', 'rsa', 'ecdsa', 'dsa']):
                        crypto_imports.add(alias.asname if alias.asname else alias.name)
            
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if any(crypto_lib in module.lower() 
                       for crypto_lib in ['crypto', 'rsa', 'ecdsa', 'dsa', 'cryptography']):
                    for alias in node.names:
                        crypto_imports.add(alias.asname if alias.asname else alias.name)
        
        return crypto_imports
    
    def _is_vulnerable_import(self, module: str, names: List[ast.alias]) -> bool:
        """Check if import is from a cryptography library with vulnerable algorithms"""
        vulnerable_modules = [
            'Crypto.PublicKey',
            'Crypto.Cipher',
            'Crypto.Signature',
            'cryptography.hazmat.primitives.asymmetric',
            'ecdsa',
        ]
        
        for vuln_module in vulnerable_modules:
            if module.startswith(vuln_module):
                # Check if importing vulnerable algorithms
                for name in names:
                    imported_name = name.name
                    if imported_name in ['RSA', 'DSA', 'ElGamal', 'rsa', 'ec', 'dsa', 'PKCS1_OAEP', 'pkcs1_15']:
                        return True
        
        return False
    
    def _is_vulnerable_call(self, node: ast.Call, crypto_imports: Set[str]) -> bool:
        """Check if function call uses vulnerable cryptography"""
        # Check for patterns like RSA.generate(), ec.generate_private_key()
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                name = node.func.value.id
                attr = node.func.attr
                
                # Check if calling generate methods on crypto objects
                if name in crypto_imports:
                    if 'generate' in attr.lower():
                        return True
                
                # Check specific patterns
                if (name in ['RSA', 'DSA', 'ec', 'rsa', 'dsa'] and 
                    'generate' in attr.lower()):
                    return True
        
        return False
    
    def _classify_python_import(self, module: str, names: List[ast.alias]) -> tuple:
        """Classify the vulnerability type from import statement"""
        for name in names:
            imported = name.name
            
            if imported == 'RSA' or 'RSA' in module:
                return (
                    "RSA",
                    "RSA encryption/signatures are vulnerable to Shor's algorithm on quantum computers.",
                    "Replace with CRYSTALS-Kyber for key encapsulation or CRYSTALS-Dilithium for signatures."
                )
            
            elif imported == 'DSA' or 'DSA' in module:
                return (
                    "DSA",
                    "DSA signatures are vulnerable to quantum attacks.",
                    "Replace with CRYSTALS-Dilithium or SPHINCS+ for post-quantum signatures."
                )
            
            elif imported in ['ec', 'ECDSA'] or 'ecdsa' in module.lower():
                return (
                    "ECDSA/ECC",
                    "Elliptic curve cryptography is vulnerable to quantum computers.",
                    "Replace with CRYSTALS-Dilithium or SPHINCS+ for signatures."
                )
            
            elif imported == 'ElGamal':
                return (
                    "ElGamal",
                    "ElGamal encryption is vulnerable to quantum attacks.",
                    "Replace with CRYSTALS-Kyber or other lattice-based encryption."
                )
        
        return (None, None, None)
    
    def _classify_python_call(self, node: ast.Call) -> tuple:
        """Classify vulnerability from function call"""
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            
            if 'rsa' in attr.lower():
                return (
                    "RSA",
                    "RSA key generation or usage detected.",
                    "Migrate to CRYSTALS-Kyber or CRYSTALS-Dilithium."
                )
            
            elif 'ecdsa' in attr.lower() or 'ec' in attr.lower():
                return (
                    "ECDSA",
                    "Elliptic curve cryptography detected.",
                    "Use CRYSTALS-Dilithium for quantum-safe signatures."
                )
            
            elif 'dsa' in attr.lower():
                return (
                    "DSA",
                    "DSA signature algorithm detected.",
                    "Replace with CRYSTALS-Dilithium or SPHINCS+."
                )
        
        return (None, None, None)
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings preferring those with key_size/confidence"""
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
        # Delegate to BaseDetector implementation via method resolution order
        return super()._extract_key_size_from_line(line)

    def _extract_key_size_from_call(self, node: ast.Call):
        """Extract key size from Python AST Call nodes for common APIs.
        Handles cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(key_size=2048)
        and RSA.generate(2048) patterns.
        """
        # Check keywords first
        for kw in getattr(node, 'keywords', []) or []:
            if kw.arg and kw.arg.lower() in ['key_size', 'modulus_length', 'moduluslength']:
                try:
                    if isinstance(kw.value, ast.Num):
                        return int(kw.value.n)
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                        return int(kw.value.value)
                except Exception:
                    pass
        # Then positional args where numeric literal is present
        for arg in getattr(node, 'args', []) or []:
            if isinstance(arg, ast.Num):
                n = int(arg.n)
                if 128 <= n <= 16384:  # plausible key size range
                    return n
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                n = int(arg.value)
                if 128 <= n <= 16384:
                    return n
        return None

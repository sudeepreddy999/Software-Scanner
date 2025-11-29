"""
Main Scanner Engine
Orchestrates file discovery, content reading, and vulnerability detection
"""

import os
import fnmatch
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

from .vulnerability_db import VulnerabilityDatabase, Severity


class Finding:
    """Represents a detected vulnerability"""
    
    def __init__(
        self,
        file_path: str,
        line_number: int,
        algorithm: str,
        severity: Severity,
        matched_pattern: str,
        line_content: str,
        description: str,
        recommendation: str,
        key_size: Optional[int] = None,
        confidence: str = "low"
    ):
        self.file_path = file_path
        self.line_number = line_number
        self.algorithm = algorithm
        self.severity = severity
        self.matched_pattern = matched_pattern
        self.line_content = line_content.strip()
        self.description = description
        self.recommendation = recommendation
        self.key_size = key_size
        # allowed: 'high', 'low' (could be extended later)
        self.confidence = confidence
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "algorithm": self.algorithm,
            "severity": self.severity.value,
            "matched_pattern": self.matched_pattern,
            "line_content": self.line_content,
            "description": self.description,
            "recommendation": self.recommendation,
            "key_size": self.key_size,
            "confidence": self.confidence
        }


class ScanResult:
    """Container for scan results"""
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.files_scanned: int = 0
        self.errors: List[Dict[str, str]] = []
    
    def add_finding(self, finding: Finding):
        """Add a vulnerability finding"""
        self.findings.append(finding)
    
    def add_error(self, file_path: str, error: str):
        """Add an error encountered during scanning"""
        self.errors.append({"file": file_path, "error": error})
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "SAFE": 0
        }
        
        for finding in self.findings:
            severity = finding.severity.value
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "files_scanned": self.files_scanned,
            "vulnerabilities_found": len([f for f in self.findings if f.severity.value != 'SAFE']),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "safe": severity_counts["SAFE"],
            "errors": len(self.errors)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary"""
        return {
            "scan_summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors
        }


class QuantumScanner:
    """Main scanner class for detecting quantum-vulnerable cryptography"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.vuln_db = VulnerabilityDatabase()
        self.config = self._load_config(config_path)
        self.detectors = {}
        self._initialize_detectors()
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load scanner configuration"""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        
        # Default configuration
        default_config_path = os.path.join(
            os.path.dirname(__file__),
            '..',
            'config',
            'scanner_config.yaml'
        )
        
        if os.path.exists(default_config_path):
            with open(default_config_path, 'r') as f:
                return yaml.safe_load(f)
        
        # Fallback to minimal config
        return {
            "exclude_patterns": [
                "*/node_modules/*",
                "*/venv/*",
                "*/__pycache__/*",
                "*/.git/*"
            ],
            "max_file_size_mb": 10,
            "parallel_scanning": True,
            "max_workers": 4
        }
    
    def _initialize_detectors(self):
        """Initialize language-specific detectors"""
        # Import detectors dynamically
        try:
            from .detectors.python_detector import PythonDetector
            self.detectors['python'] = PythonDetector(self.vuln_db)
        except ImportError:
            pass
        
        try:
            from .detectors.java_detector import JavaDetector
            self.detectors['java'] = JavaDetector(self.vuln_db)
        except ImportError:
            pass
        
        try:
            from .detectors.c_cpp_detector import CCppDetector
            self.detectors['c_cpp'] = CCppDetector(self.vuln_db)
        except ImportError:
            pass
    
    def _should_exclude(self, path: str) -> bool:
        """Check if path should be excluded from scanning"""
        exclude_patterns = self.config.get("exclude_patterns", [])
        
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        
        return False
    
    def _get_language_from_extension(self, file_path: str) -> Optional[str]:
        """Determine language from file extension"""
        ext = os.path.splitext(file_path)[1].lower()
        
        extension_map = {
            '.py': 'python',
            '.java': 'java',
            '.c': 'c_cpp',
            '.cpp': 'c_cpp',
            '.cc': 'c_cpp',
            '.cxx': 'c_cpp',
            '.h': 'c_cpp',
            '.hpp': 'c_cpp',
            '.rs': 'rust',
            '.cs': 'csharp'
        }
        
        return extension_map.get(ext)
    
    def _discover_files(self, target_path: str) -> List[str]:
        """Discover all files to scan in target directory"""
        files_to_scan = []
        
        if os.path.isfile(target_path):
            if not self._should_exclude(target_path):
                files_to_scan.append(target_path)
            return files_to_scan
        
        for root, dirs, files in os.walk(target_path):
            # Modify dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if not self._should_exclude(os.path.join(root, d))]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                if self._should_exclude(file_path):
                    continue
                
                # Check if we have a detector for this file type
                language = self._get_language_from_extension(file_path)
                if language and language in self.detectors:
                    # Check file size
                    try:
                        size_mb = os.path.getsize(file_path) / (1024 * 1024)
                        max_size = self.config.get("max_file_size_mb", 10)
                        if size_mb <= max_size:
                            files_to_scan.append(file_path)
                    except OSError:
                        continue
        
        return files_to_scan
    
    def _scan_file(self, file_path: str) -> List[Finding]:
        """Scan a single file for vulnerabilities"""
        language = self._get_language_from_extension(file_path)
        
        if not language or language not in self.detectors:
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            detector = self.detectors[language]
            return detector.detect(file_path, content)
        
        except Exception as e:
            # Return empty list on error, will be logged separately
            return []
    
    def scan(self, target_path: str, verbose: bool = False) -> ScanResult:
        """
        Scan target path for quantum-vulnerable cryptography
        
        Args:
            target_path: Path to file or directory to scan
            verbose: Enable verbose output
            
        Returns:
            ScanResult object containing findings and statistics
        """
        result = ScanResult()
        
        if not os.path.exists(target_path):
            result.add_error(target_path, "Path does not exist")
            return result
        
        # Discover files
        if verbose:
            print(f"Discovering files in {target_path}...")
        
        files_to_scan = self._discover_files(target_path)
        result.files_scanned = len(files_to_scan)
        
        if verbose:
            print(f"Found {len(files_to_scan)} files to scan")
        
        # Scan files
        if self.config.get("parallel_scanning", True) and len(files_to_scan) > 1:
            # Parallel scanning
            max_workers = self.config.get("max_workers", 4)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_file = {
                    executor.submit(self._scan_file, file_path): file_path
                    for file_path in files_to_scan
                }
                
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        findings = future.result()
                        for finding in findings:
                            result.add_finding(finding)
                        
                        if verbose and findings:
                            print(f"  {file_path}: {len(findings)} vulnerabilities")
                    
                    except Exception as e:
                        result.add_error(file_path, str(e))
        else:
            # Sequential scanning
            for file_path in files_to_scan:
                try:
                    findings = self._scan_file(file_path)
                    for finding in findings:
                        result.add_finding(finding)
                    
                    if verbose and findings:
                        print(f"  {file_path}: {len(findings)} vulnerabilities")
                
                except Exception as e:
                    result.add_error(file_path, str(e))
        
        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.SAFE: 4  # Quantum-safe algorithms last
        }
        result.findings.sort(key=lambda f: (severity_order[f.severity], f.file_path, f.line_number))
        
        return result

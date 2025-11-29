"""
CLI Reporter
Generates command-line interface output for scan results
"""

from typing import List, Dict, Any
from ..scanner import ScanResult, Finding
from ..vulnerability_db import Severity


class CLIReporter:
    """Reporter for CLI table output"""
    
    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors
        self._init_colors()
    
    def _init_colors(self):
        """Initialize color codes for terminal output"""
        if self.use_colors:
            try:
                from colorama import init, Fore, Style
                init(autoreset=True)
                self.colors = {
                    'CRITICAL': Fore.RED + Style.BRIGHT,
                    'HIGH': Fore.RED,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.CYAN,
                    'SAFE': Fore.GREEN + Style.BRIGHT,
                    'RESET': Style.RESET_ALL,
                    'BOLD': Style.BRIGHT,
                    'GREEN': Fore.GREEN,
                    'BLUE': Fore.BLUE,
                }
            except ImportError:
                self.use_colors = False
                self.colors = {k: '' for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE', 'RESET', 'BOLD', 'GREEN', 'BLUE']}
        else:
            self.colors = {k: '' for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE', 'RESET', 'BOLD', 'GREEN', 'BLUE']}
    
    def generate(self, result: ScanResult) -> str:
        """Generate CLI report"""
        output = []
        
        # Header
        output.append(self._generate_header())
        output.append("")
        
        # Summary
        output.append(self._generate_summary(result))
        output.append("")
        
        # Findings
        if result.findings:
            output.append(self._generate_findings(result.findings))
        else:
            output.append(f"{self.colors['GREEN']}✓ No quantum-vulnerable algorithms detected!{self.colors['RESET']}")
        
        # Errors
        if result.errors:
            output.append("")
            output.append(self._generate_errors(result.errors))
        
        return "\n".join(output)
    
    def _generate_header(self) -> str:
        """Generate report header"""
        width = 80
        title = "Quantum Vulnerability Security Scan Report"
        
        lines = []
        lines.append("═" * width)
        lines.append(f"{self.colors['BOLD']}{title.center(width)}{self.colors['RESET']}")
        lines.append("═" * width)
        
        return "\n".join(lines)
    
    def _generate_summary(self, result: ScanResult) -> str:
        """Generate summary section"""
        summary = result.get_summary()
        
        lines = []
        lines.append(f"{self.colors['BOLD']}SCAN SUMMARY{self.colors['RESET']}")
        lines.append("─" * 80)
        lines.append(f"Files Scanned: {self.colors['BLUE']}{summary['files_scanned']}{self.colors['RESET']}")
        lines.append(f"Vulnerabilities Found: {self._colorize_count(summary['vulnerabilities_found'])}")
        
        # Show quantum-safe algorithms count if any
        safe_count = summary.get('safe', 0)
        if safe_count > 0:
            lines.append(f"Quantum-Safe Algorithms: {self.colors['SAFE']}{safe_count} ✓{self.colors['RESET']}")
        
        if summary['vulnerabilities_found'] > 0:
            lines.append("")
            lines.append(f"  {self.colors['CRITICAL']}● CRITICAL:{self.colors['RESET']} {summary['critical']}")
            lines.append(f"  {self.colors['HIGH']}● HIGH:{self.colors['RESET']}     {summary['high']}")
            lines.append(f"  {self.colors['MEDIUM']}● MEDIUM:{self.colors['RESET']}   {summary['medium']}")
            lines.append(f"  {self.colors['LOW']}● LOW:{self.colors['RESET']}      {summary['low']}")
        
        return "\n".join(lines)
    
    def _generate_findings(self, findings: List[Finding]) -> str:
        """Generate findings section"""
        # Separate vulnerable and safe findings
        vulnerable = [f for f in findings if f.severity.value != 'SAFE']
        safe = [f for f in findings if f.severity.value == 'SAFE']
        
        lines = []
        
        # Show vulnerabilities first
        if vulnerable:
            lines.append(f"{self.colors['BOLD']}DETECTED VULNERABILITIES{self.colors['RESET']}")
            lines.append("─" * 80)
            lines.append("")
            
            for i, finding in enumerate(vulnerable, 1):
                lines.append(self._format_finding(i, finding))
                lines.append("")
        
        # Then show quantum-safe algorithms
        if safe:
            lines.append(f"{self.colors['BOLD']}{self.colors['GREEN']}QUANTUM-SAFE ALGORITHMS DETECTED ✓{self.colors['RESET']}")
            lines.append("─" * 80)
            lines.append("")
            
            for i, finding in enumerate(safe, 1):
                lines.append(self._format_safe_finding(i, finding))
                lines.append("")
        
        return "\n".join(lines)
    
    def _format_finding(self, index: int, finding: Finding) -> str:
        """Format a single finding"""
        severity_color = self.colors.get(finding.severity.value, '')
        
        lines = []
        lines.append(f"{severity_color}[{finding.severity.value}]{self.colors['RESET']} {self.colors['BOLD']}{finding.algorithm}{self.colors['RESET']}")
        lines.append(f"  File: {finding.file_path}:{finding.line_number}")
        lines.append(f"  Code: {finding.line_content[:100]}")
        if getattr(finding, 'key_size', None):
            lines.append(f"  Key size: {finding.key_size} bits")
        if getattr(finding, 'confidence', None):
            lines.append(f"  Confidence: {finding.confidence}")
        lines.append(f"  Issue: {finding.description}")
        lines.append(f"  {self.colors['GREEN']}→ Recommendation:{self.colors['RESET']} {finding.recommendation}")
        
        return "\n".join(lines)
    
    def _format_safe_finding(self, index: int, finding: Finding) -> str:
        """Format a quantum-safe algorithm finding"""
        lines = []
        lines.append(f"{self.colors['SAFE']}✓ [{finding.severity.value}]{self.colors['RESET']} {self.colors['BOLD']}{self.colors['GREEN']}{finding.algorithm}{self.colors['RESET']}")
        lines.append(f"  File: {finding.file_path}:{finding.line_number}")
        lines.append(f"  Code: {finding.line_content[:100]}")
        if getattr(finding, 'key_size', None):
            lines.append(f"  Key size: {finding.key_size} bits")
        if getattr(finding, 'confidence', None):
            lines.append(f"  Confidence: {finding.confidence}")
        lines.append(f"  {self.colors['GREEN']}✓ {finding.description}{self.colors['RESET']}")
        lines.append(f"  {self.colors['GREEN']}→ {finding.recommendation}{self.colors['RESET']}")
        
        return "\n".join(lines)
    
    def _generate_errors(self, errors: List[Dict[str, str]]) -> str:
        """Generate errors section"""
        lines = []
        lines.append(f"{self.colors['BOLD']}SCAN ERRORS{self.colors['RESET']}")
        lines.append("─" * 80)
        
        for error in errors:
            lines.append(f"  {error['file']}: {error['error']}")
        
        return "\n".join(lines)
    
    def _colorize_count(self, count: int) -> str:
        """Colorize count based on value"""
        if count == 0:
            return f"{self.colors['GREEN']}{count}{self.colors['RESET']}"
        elif count < 5:
            return f"{self.colors['MEDIUM']}{count}{self.colors['RESET']}"
        else:
            return f"{self.colors['CRITICAL']}{count}{self.colors['RESET']}"
    
    def print_summary(self, result: ScanResult):
        """Print a brief summary to console"""
        summary = result.get_summary()
        
        print(f"\n{self.colors['BOLD']}Scan Complete!{self.colors['RESET']}")
        print(f"Files scanned: {summary['files_scanned']}")
        print(f"Vulnerabilities: {self._colorize_count(summary['vulnerabilities_found'])}")
        
        if summary['vulnerabilities_found'] > 0:
            print(f"  Critical: {self.colors['CRITICAL']}{summary['critical']}{self.colors['RESET']}")
            print(f"  High: {self.colors['HIGH']}{summary['high']}{self.colors['RESET']}")
            print(f"  Medium: {self.colors['MEDIUM']}{summary['medium']}{self.colors['RESET']}")
            print(f"  Low: {self.colors['LOW']}{summary['low']}{self.colors['RESET']}")
        
        safe_count = summary.get('safe', 0)
        if safe_count > 0:
            print(f"Quantum-Safe Algorithms: {self.colors['SAFE']}{safe_count} ✓{self.colors['RESET']}")

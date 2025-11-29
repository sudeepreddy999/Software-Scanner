"""
HTML Reporter
Generates HTML report for scan results
"""

from typing import Dict, Any
from ..scanner import ScanResult, Finding
from ..vulnerability_db import Severity


class HTMLReporter:
    """Reporter for HTML output"""
    
    def generate(self, result: ScanResult) -> str:
        """Generate HTML report"""
        summary = result.get_summary()
        
        html = self._generate_html_template()
        html = html.replace("{{TITLE}}", "Quantum Vulnerability Scan Report")
        html = html.replace("{{FILES_SCANNED}}", str(summary['files_scanned']))
        html = html.replace("{{TOTAL_VULNERABILITIES}}", str(summary['vulnerabilities_found']))
        html = html.replace("{{CRITICAL_COUNT}}", str(summary['critical']))
        html = html.replace("{{HIGH_COUNT}}", str(summary['high']))
        html = html.replace("{{MEDIUM_COUNT}}", str(summary['medium']))
        html = html.replace("{{LOW_COUNT}}", str(summary['low']))
        html = html.replace("{{SAFE_COUNT}}", str(summary.get('safe', 0)))
        
        # Separate vulnerable and safe findings
        vulnerable = [f for f in result.findings if f.severity.value != 'SAFE']
        safe = [f for f in result.findings if f.severity.value == 'SAFE']
        
        # Generate findings HTML
        vulnerable_html = self._generate_findings_html(vulnerable, is_safe=False)
        safe_html = self._generate_findings_html(safe, is_safe=True)
        
        html = html.replace("{{VULNERABLE_FINDINGS}}", vulnerable_html)
        html = html.replace("{{SAFE_FINDINGS}}", safe_html)
        
        return html
    
    def _generate_findings_html(self, findings: list[Finding], is_safe: bool = False) -> str:
        """Generate HTML for findings"""
        if not findings:
            if is_safe:
                return ''
            return '<div class="no-findings">✓ No quantum-vulnerable algorithms detected!</div>'
        
        html_parts = []
        
        for finding in findings:
            severity_class = finding.severity.value.lower()
            
            if is_safe:
                # Special styling for safe findings
                html_parts.append(f'''
            <div class="finding safe">
                <div class="finding-header safe-header">
                    <span class="severity-badge safe">✓ {finding.severity.value}</span>
                    <span class="algorithm">{finding.algorithm}</span>
                </div>
                <div class="finding-body">
                    <div class="finding-field">
                        <strong>File:</strong> {finding.file_path}:{finding.line_number}
                    </div>
                    <div class="finding-field">
                        <strong>Code:</strong> <code>{self._escape_html(finding.line_content)}</code>
                    </div>
                    {f'<div class="finding-field"><strong>Key size:</strong> {finding.key_size} bits</div>' if getattr(finding, 'key_size', None) else ''}
                    {f'<div class="finding-field"><strong>Confidence:</strong> {finding.confidence}</div>' if getattr(finding, 'confidence', None) else ''}
                    <div class="finding-field">
                        <strong>Description:</strong> {finding.description}
                    </div>
                    <div class="finding-field safe-recommendation">
                        <strong>✓ Recommendation:</strong> {finding.recommendation}
                    </div>
                </div>
            </div>
            ''')
            else:
                # Original styling for vulnerable findings
                html_parts.append(f'''
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="severity-badge {severity_class}">{finding.severity.value}</span>
                    <span class="algorithm">{finding.algorithm}</span>
                </div>
                <div class="finding-body">
                    <div class="finding-field">
                        <strong>File:</strong> {finding.file_path}:{finding.line_number}
                    </div>
                    <div class="finding-field">
                        <strong>Code:</strong> <code>{self._escape_html(finding.line_content)}</code>
                    </div>
                    {f'<div class="finding-field"><strong>Key size:</strong> {finding.key_size} bits</div>' if getattr(finding, 'key_size', None) else ''}
                    {f'<div class="finding-field"><strong>Confidence:</strong> {finding.confidence}</div>' if getattr(finding, 'confidence', None) else ''}
                    <div class="finding-field">
                        <strong>Description:</strong> {finding.description}
                    </div>
                    <div class="finding-field recommendation">
                        <strong>Recommendation:</strong> {finding.recommendation}
                    </div>
                </div>
            </div>
            ''')
        
        return '\n'.join(html_parts)
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#39;'))
    
    def _generate_html_template(self) -> str:
        """Generate HTML template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TITLE}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        header h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .summary {
            padding: 30px;
            background: #f9f9f9;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .summary h2 {
            margin-bottom: 20px;
            color: #667eea;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .stat-card h3 {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        
        .severity-stats {
            display: flex;
            gap: 15px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .severity-stat {
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: bold;
        }
        
        .severity-stat.critical {
            background: #fee;
            color: #c00;
        }
        
        .severity-stat.high {
            background: #ffd7d7;
            color: #d00;
        }
        
        .severity-stat.medium {
            background: #fff4e0;
            color: #f90;
        }
        
        .severity-stat.low {
            background: #e0f7ff;
            color: #06c;
        }
        
        .severity-stat.safe {
            background: #e8f5e9;
            color: #2e7d32;
        }
        
        .findings {
            padding: 30px;
        }
        
        .findings h2 {
            margin-bottom: 20px;
            color: #667eea;
        }
        
        .finding {
            margin-bottom: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .finding.critical {
            border-left: 4px solid #c00;
        }
        
        .finding.high {
            border-left: 4px solid #d00;
        }
        
        .finding.medium {
            border-left: 4px solid #f90;
        }
        
        .finding.low {
            border-left: 4px solid #06c;
        }
        
        .finding.safe {
            border-left: 4px solid #4caf50;
            background: #f9fff9;
        }
        
        .finding-header {
            background: #f9f9f9;
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .finding-header.safe-header {
            background: #e8f5e9;
        }
        
        .severity-badge {
            padding: 5px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }
        
        .severity-badge.critical {
            background: #c00;
        }
        
        .severity-badge.high {
            background: #d00;
        }
        
        .severity-badge.medium {
            background: #f90;
        }
        
        .severity-badge.low {
            background: #06c;
        }
        
        .severity-badge.safe {
            background: #4caf50;
        }
        
        .algorithm {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .finding-body {
            padding: 20px;
        }
        
        .finding-field {
            margin-bottom: 15px;
        }
        
        .finding-field:last-child {
            margin-bottom: 0;
        }
        
        .finding-field strong {
            display: inline-block;
            min-width: 120px;
            color: #667eea;
        }
        
        .finding-field code {
            background: #f5f5f5;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .recommendation {
            background: #e8f5e9;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #4caf50;
        }
        
        .safe-recommendation {
            background: #e8f5e9;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #2e7d32;
        }
        
        .no-findings {
            text-align: center;
            padding: 40px;
            font-size: 1.2em;
            color: #4caf50;
        }
        
        .safe-section {
            padding: 30px;
            background: #f9fff9;
            border-top: 2px solid #4caf50;
        }
        
        .safe-section h2 {
            color: #2e7d32;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .safe-section h2::before {
            content: "✓";
            font-size: 1.2em;
        }
        
        footer {
            padding: 20px;
            text-align: center;
            background: #f9f9f9;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #e0e0e0;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{TITLE}}</h1>
            <p>Detecting Quantum-Vulnerable Algorithms & Recognizing Post-Quantum Cryptography</p>
        </header>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <h3>Files Scanned</h3>
                    <div class="value">{{FILES_SCANNED}}</div>
                </div>
                <div class="stat-card">
                    <h3>Total Vulnerabilities</h3>
                    <div class="value">{{TOTAL_VULNERABILITIES}}</div>
                </div>
                <div class="stat-card" style="border-left-color: #4caf50;">
                    <h3>Quantum-Safe Algorithms</h3>
                    <div class="value" style="color: #4caf50;">{{SAFE_COUNT}}</div>
                </div>
            </div>
            <div class="severity-stats">
                <div class="severity-stat critical">
                    CRITICAL: {{CRITICAL_COUNT}}
                </div>
                <div class="severity-stat high">
                    HIGH: {{HIGH_COUNT}}
                </div>
                <div class="severity-stat medium">
                    MEDIUM: {{MEDIUM_COUNT}}
                </div>
                <div class="severity-stat low">
                    LOW: {{LOW_COUNT}}
                </div>
                <div class="severity-stat safe">
                    ✓ SAFE: {{SAFE_COUNT}}
                </div>
            </div>
        </div>
        
        <div class="findings">
            <h2>Detected Vulnerabilities</h2>
            {{VULNERABLE_FINDINGS}}
        </div>
        
        <div class="safe-section">
            <h2>Quantum-Safe Algorithms Detected</h2>
            {{SAFE_FINDINGS}}
        </div>
        
        <footer>
            <p>Generated by Quantum Vulnerability Scanner | For more information about post-quantum cryptography, visit <a href="https://csrc.nist.gov/projects/post-quantum-cryptography" target="_blank">NIST PQC</a></p>
        </footer>
    </div>
</body>
</html>'''
    
    def save_to_file(self, result: ScanResult, output_path: str):
        """Save HTML report to file"""
        html_content = self.generate(result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

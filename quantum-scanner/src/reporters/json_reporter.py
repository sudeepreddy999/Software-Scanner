"""
JSON Reporter
Generates JSON output for scan results
"""

import json
from typing import Dict, Any
from ..scanner import ScanResult


class JSONReporter:
    """Reporter for JSON output"""
    
    def __init__(self, pretty: bool = True):
        self.pretty = pretty
    
    def generate(self, result: ScanResult) -> str:
        """Generate JSON report"""
        report_data = result.to_dict()
        
        if self.pretty:
            return json.dumps(report_data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(report_data, ensure_ascii=False)
    
    def save_to_file(self, result: ScanResult, output_path: str):
        """Save JSON report to file"""
        json_content = self.generate(result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(json_content)

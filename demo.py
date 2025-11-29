#!/usr/bin/env python3
"""
Demo script to test the Quantum Vulnerability Scanner
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum-scanner'))

from src.scanner import QuantumScanner
from src.reporters.cli_reporter import CLIReporter

def main():
    print("=" * 80)
    print("Quantum Vulnerability Scanner - Demo")
    print("=" * 80)
    print()
    
    # Scan the test samples directory
    test_dir = os.path.join('quantum-scanner', 'tests', 'test_samples')
    
    if not os.path.exists(test_dir):
        print(f"Error: Test directory '{test_dir}' not found")
        return 1
    
    print(f"Scanning test samples in: {test_dir}")
    print()
    
    # Initialize scanner
    scanner = QuantumScanner()
    
    # Perform scan
    result = scanner.scan(test_dir, verbose=True)
    
    print()
    print("=" * 80)
    print("Scan Results")
    print("=" * 80)
    print()
    
    # Generate CLI report
    reporter = CLIReporter(use_colors=True)
    report = reporter.generate(result)
    print(report)
    
    # Summary
    summary = result.get_summary()
    print()
    print(f"Total vulnerabilities found: {summary['vulnerabilities_found']}")
    print(f"  CRITICAL: {summary['critical']}")
    print(f"  HIGH: {summary['high']}")
    print(f"  MEDIUM: {summary['medium']}")
    print(f"  LOW: {summary['low']}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

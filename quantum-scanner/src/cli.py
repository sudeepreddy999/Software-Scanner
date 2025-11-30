

import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

from .scanner import QuantumScanner
from .reporters.cli_reporter import CLIReporter
from .reporters.json_reporter import JSONReporter
from .reporters.html_reporter import HTMLReporter
from .openssl_analyzer import OpenSSLAnalyzer
from .reporters.excel_reporter import ExcelCipherReporter
from .reporters.text_summary_reporter import TextSummaryReporter
from .windows_system_scanner import WindowsSystemScanner


def main():
 
    parser = argparse.ArgumentParser(
        description="Quantum Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
  
    scan_parser = subparsers.add_parser(
        'scan',
        help='Scan source code for quantum-vulnerable algorithms',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a directory with CLI output
  python -m src.cli scan /path/to/project

  # Generate JSON report
  python -m src.cli scan /path/to/project --format json --output report.json

  # Generate HTML report
  python -m src.cli scan /path/to/project --format html --output report.html

Supported Languages:
  - Python (.py)
  - Java (.java)
  - JavaScript/TypeScript (.js, .jsx, .ts, .tsx)
  - C/C++ (.c, .cpp, .cc, .h, .hpp)
  - Go (.go)
        """
    )
    
    scan_parser.add_argument(
        'target',
        help='Target file or directory to scan'
    )
    
    scan_parser.add_argument(
        '-f', '--format',
        choices=['cli', 'json', 'html'],
        default='cli',
        help='Output format (default: cli)'
    )
    
    scan_parser.add_argument(
        '-o', '--output',
        help='Output file path (for json/html formats)'
    )
    
    scan_parser.add_argument(
        '-c', '--config',
        help='Path to custom configuration file'
    )
    
    scan_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    scan_parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    # Subcommand: scan-openssl (new functionality)
    openssl_parser = subparsers.add_parser(
        'scan-openssl',
        help='Analyze OpenSSL cipher suites and quantum resistance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze OpenSSL and generate Excel report
  python -m src.cli scan-openssl -o openssl_analysis.xlsx

  # Verbose output
  python -m src.cli scan-openssl -o report.xlsx --verbose

This command will:
  - Query all available cipher suites from your installed OpenSSL
  - Extract algorithm details (key exchange, authentication, encryption)
  - Identify key sizes and hash algorithms
  - Assess quantum resistance strength
  - Generate comprehensive Excel report with recommendations
        """
    )
    
    openssl_parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output Excel file path (e.g., openssl_analysis.xlsx)'
    )
    
    openssl_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    # Subcommand: scan-system (Windows agent-style system scan)
    sys_parser = subparsers.add_parser(
        'scan-system',
        help='Scan Windows system files (certs/keys/configs) for quantum-vulnerable algorithms',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run a Windows system scan with CLI output
  python -m src.cli scan-system

  # Specify custom root paths and get JSON output
  python -m src.cli scan-system --paths C:\\ProgramData C:\\Users --format json --output system_report.json
        """
    )
    sys_parser.add_argument(
        '--paths', nargs='*', default=None,
        help='Root paths to scan (Windows only). Defaults to common system directories.'
    )
    sys_parser.add_argument(
        '-f', '--format',
        choices=['cli', 'json', 'html'],
        default='cli',
        help='Output format (default: cli)'
    )
    sys_parser.add_argument(
        '-o', '--output',
        help='Output file path (for json/html formats)'
    )
    sys_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Version argument at main parser level
    parser.add_argument(
        '--version',
        action='version',
        version='Quantum Vulnerability Scanner v1.0.0'
    )
    
    args = parser.parse_args()
    
    # If no command specified, show help
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Route to appropriate handler
    if args.command == 'scan':
        return handle_scan_command(args)
    elif args.command == 'scan-openssl':
        return handle_openssl_command(args)
    elif args.command == 'scan-system':
        return handle_system_command(args)


def handle_scan_command(args):
    """Handle the 'scan' command for source code vulnerability scanning"""
    
    # Validate target path
    if not os.path.exists(args.target):
        print(f"Error: Target path '{args.target}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    # Validate output file for json/html
    if args.format in ['json', 'html'] and not args.output:
        print(f"Error: --output is required for {args.format} format", file=sys.stderr)
        sys.exit(1)
    
    # Print banner
    if args.format == 'cli' and not args.verbose:
        print_banner(not args.no_color)
    
    try:
        # Initialize scanner
        if args.verbose:
            print(f"Initializing scanner...")
            if args.config:
                print(f"Using configuration: {args.config}")
        
        scanner = QuantumScanner(config_path=args.config)
        
        # Perform scan
        if args.verbose:
            print(f"Scanning target: {args.target}")
            print()
        
        result = scanner.scan(args.target, verbose=args.verbose)
        
        # Generate report
        if args.format == 'cli':
            reporter = CLIReporter(use_colors=not args.no_color)
            report = reporter.generate(result)
            print(report)
            
            # Exit with appropriate code
            summary = result.get_summary()
            if summary['critical'] > 0:
                sys.exit(2)  # Critical vulnerabilities found
            elif summary['high'] > 0:
                sys.exit(1)  # High vulnerabilities found
            else:
                sys.exit(0)  # Success
        
        elif args.format == 'json':
            reporter = JSONReporter(pretty=True)
            reporter.save_to_file(result, args.output)
            print(f"JSON report saved to: {args.output}")
            
            summary = result.get_summary()
            if summary['vulnerabilities_found'] > 0:
                sys.exit(1)
            else:
                sys.exit(0)
        
        elif args.format == 'html':
            reporter = HTMLReporter()
            reporter.save_to_file(result, args.output)
            print(f"HTML report saved to: {args.output}")
            
            summary = result.get_summary()
            if summary['vulnerabilities_found'] > 0:
                sys.exit(1)
            else:
                sys.exit(0)
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        sys.exit(130)
    
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def handle_openssl_command(args):
    """Handle the 'scan-openssl' command for OpenSSL cipher suite analysis"""
    
    # Validate output file
    if not args.output.endswith('.xlsx'):
        print(f"Warning: Output file should have .xlsx extension. Adding it.")
        args.output = args.output + '.xlsx' if not args.output.endswith('.xls') else args.output
    
    try:
        print("Quantum OpenSSL Cipher Suite Analyzer")
        print("=" * 50)
        print()
        
        if args.verbose:
            print("Initializing OpenSSL analyzer...")
        
        # Initialize analyzer
        analyzer = OpenSSLAnalyzer()
        
        # Check if OpenSSL is available
        if args.verbose:
            print("Checking for OpenSSL installation...")
        
        if not analyzer.check_openssl_available():
            print("Error: OpenSSL not found on system", file=sys.stderr)
            print("Please install OpenSSL to use this feature.", file=sys.stderr)
            print("  macOS: brew install openssl", file=sys.stderr)
            print("  Ubuntu/Debian: sudo apt-get install openssl", file=sys.stderr)
            print("  Windows: Download from https://slproweb.com/products/Win32OpenSSL.html", file=sys.stderr)
            sys.exit(1)
        
        version = analyzer.get_openssl_version()
        print(f"OpenSSL Version: {version}")
        print()
        
        if args.verbose:
            print("Retrieving available cipher suites...")
        
        # Run analysis
        result = analyzer.analyze()
        
        if 'error' in result:
            print(f"Error: {result['error']}", file=sys.stderr)
            sys.exit(1)
        
        cipher_suites = result['cipher_suites']
        statistics = result['statistics']
        
        print(f"Found {len(cipher_suites)} cipher suites")
        print()
        
        # Display summary statistics
        if args.verbose:
            print("Quantum Strength Distribution:")
            strength_counts = statistics.get('by_strength', {})
            for strength, count in strength_counts.items():
                percentage = (count / len(cipher_suites) * 100) if cipher_suites else 0
                print(f"  {strength:15s}: {count:4d} ({percentage:5.1f}%)")
            print()
        
        # Generate Excel report
        if args.verbose:
            print(f"Generating Excel report...")
        
        try:
            excel_reporter = ExcelCipherReporter()
            excel_reporter.generate_report(
                cipher_suites=cipher_suites,
                statistics=statistics,
                openssl_version=version,
                output_file=args.output
            )
            
            print(f"✓ Excel report successfully generated: {args.output}")
            print()
            
            # Generate text summary report
            # Automatically create .txt file with same base name
            txt_output = args.output.replace('.xlsx', '_summary.txt').replace('.xls', '_summary.txt')
            if not txt_output.endswith('.txt'):
                txt_output = args.output + '_summary.txt'
            
            if args.verbose:
                print(f"Generating text summary report...")
            
            text_reporter = TextSummaryReporter()
            text_reporter.generate_report(
                cipher_suites=cipher_suites,
                statistics=statistics,
                openssl_version=version,
                output_file=txt_output
            )
            
            print(f"✓ Text summary successfully generated: {txt_output}")
            print()
            print("Report Summary:")
            print("  Excel Report:")
            print("    • All cipher suites with complete details (12 columns)")
            print("    • Color-coded quantum strength indicators")
            print("    • Sortable and filterable data")
            print("  Text Summary:")
            print("    • Frequency distribution of quantum strengths")
            print("    • Categorized lists of cipher suites by strength level")
            print("    • Statistical breakdowns and recommendations")
            print()
            
            # Warning if critical ciphers found
            critical_count = statistics.get('by_strength', {}).get('CRITICAL', 0)
            if critical_count > 0:
                print(f"⚠️  WARNING: {critical_count} CRITICAL cipher suites found!")
                print("   These are vulnerable to quantum attacks and should be disabled.")
                sys.exit(2)
            else:
                print("✓ No critical vulnerabilities found.")
                sys.exit(0)
                
        except ImportError as e:
            print(f"Error: Required library not installed", file=sys.stderr)
            print(f"Please install openpyxl: pip install openpyxl", file=sys.stderr)
            if args.verbose:
                print(f"Details: {str(e)}", file=sys.stderr)
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user", file=sys.stderr)
        sys.exit(130)
    
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def handle_system_command(args):
    """Handle the 'scan-system' command for Windows system file scanning"""
    import platform as _platform
    if _platform.system() != 'Windows':
        print("Error: scan-system is only supported on Windows hosts.", file=sys.stderr)
        sys.exit(1)

    if args.format in ['json', 'html'] and not args.output:
        print(f"Error: --output is required for {args.format} format", file=sys.stderr)
        sys.exit(1)

    try:
        if args.verbose:
            print("Initializing Windows system scanner...")
        scanner = WindowsSystemScanner(paths=args.paths)
        if args.verbose:
            print("Scanning system paths...\n")
        result = scanner.scan(verbose=args.verbose)

        if args.format == 'cli':
            reporter = CLIReporter(use_colors=True)
            report = reporter.generate(result)
            print(report)
            summary = result.get_summary()
            if summary['critical'] > 0:
                sys.exit(2)
            elif summary['vulnerabilities_found'] > 0:
                sys.exit(1)
            else:
                sys.exit(0)
        elif args.format == 'json':
            reporter = JSONReporter(pretty=True)
            reporter.save_to_file(result, args.output)
            print(f"JSON report saved to: {args.output}")
            sys.exit(0)
        elif args.format == 'html':
            reporter = HTMLReporter()
            reporter.save_to_file(result, args.output)
            print(f"HTML report saved to: {args.output}")
            sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        sys.exit(1)


def print_banner(use_colors: bool = True):
    """Print application banner"""
    if use_colors:
        try:
            from colorama import init, Fore, Style
            init(autoreset=True)
            color_start = Fore.CYAN + Style.BRIGHT
            color_end = Style.RESET_ALL
        except ImportError:
            color_start = ""
            color_end = ""
    else:
        color_start = ""
        color_end = ""
    
    banner = f"""
{color_start}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        Quantum Vulnerability Scanner v1.0.0                   ║
║        Detecting Quantum-Vulnerable Cryptography             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{color_end}
    """
    print(banner)


if __name__ == '__main__':
    main()

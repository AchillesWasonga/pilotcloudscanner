import argparse
from modules.aws_scanner import AWSScanner
from modules.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="Cloud Security Misconfiguration Scanner")
    parser.add_argument("--platform", choices=["aws", "azure"], required=True, help="Cloud platform to scan")
    args = parser.parse_args()

    if args.platform == "aws":
        scanner = AWSScanner()
    else:
        print("Azure scanning not yet implemented!")
        return

    print(f"Starting scan on {args.platform}...")
    findings = scanner.scan()
    print("Scan complete. Generating report...")

    report_file = ReportGenerator.generate(findings, args.platform)
    print(f"Report generated: {report_file}")

if __name__ == "__main__":
    main()

import argparse
import logging
from modules.aws_scanner import AWSScanner
from modules.azure_scanner import AzureScanner
from modules.report_generator import ReportGenerator

# Set up logging
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def main():
    parser = argparse.ArgumentParser(description="Cloud Security Misconfiguration Scanner")
    parser.add_argument("--platform", choices=["aws", "azure"], required=True, help="Cloud platform to scan")
    parser.add_argument("--output", choices=["json", "html", "csv"], default="json", help="Output report format")
    args = parser.parse_args()

    # Initialize scanner based on selected platform
    if args.platform == "aws":
        scanner = AWSScanner()
    elif args.platform == "azure":
        scanner = AzureScanner("<YOUR_AZURE_SUBSCRIPTION_ID>")  # Subscription ID after I get an account
    else:
        print("Invalid platform selection!")
        return

    print(f"Starting scan on {args.platform}...")
    findings = scanner.scan()

    if not findings:
        print("No misconfigurations detected!")
        logging.info(f"No issues found on {args.platform}.")
    else:
        print(f"Scan complete. Found {len(findings)} issues. Generating report...")

        # Generate report in user-specified format
        report_file = ReportGenerator.generate(findings, args.platform, args.output)
        print(f"Report generated: {report_file}")
        logging.info(f"Report saved as {report_file}")

if __name__ == "__main__":
    main()

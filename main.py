import argparse
import logging
from modules.aws_scanner import AWSScanner
from modules.azure_scanner import AzureScanner
from modules.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def main():
    parser = argparse.ArgumentParser(description="Cloud Security Misconfiguration Scanner")
    parser.add_argument("--platform", choices=["aws", "azure"], required=True, help="Cloud platform to scan")
    parser.add_argument("--output", choices=["json", "html", "csv"], default="json", help="Output report format")
    args = parser.parse_args()

    # Initialize appropriate scanner
    if args.platform == "aws":
        scanner = AWSScanner()

    elif args.platform == "azure":
        try:
            subscription_id = input("🔑 Enter your Azure Subscription ID: ").strip()
            if not subscription_id:
                raise ValueError("Subscription ID cannot be empty.")
            scanner = AzureScanner(subscription_id)
        except Exception as e:
            print(f"❌ Failed to initialize Azure scanner: {e}")
            logging.error(f"Azure scanner initialization error: {e}")
            return

    else:
        print("❌ Invalid platform selection!")
        return

    print(f"🚀 Starting scan on {args.platform}...")
    findings = scanner.scan()

    if not findings:
        print("✅ No misconfigurations detected!")
        logging.info(f"No issues found on {args.platform}.")
    else:
        print(f"⚠️ Scan complete. Found {len(findings)} issues. Generating report...")

        report_file = ReportGenerator.generate(findings, args.platform, args.output)
        print(f"📄 Report generated: {report_file}")
        logging.info(f"Report saved as {report_file}")

if __name__ == "__main__":
    main()

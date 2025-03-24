import argparse
import logging
from modules.aws_scanner import AWSScanner
from modules.azure_scanner import AzureScanner
from modules.report_generator import ReportGenerator

# New import for automatic subscription detection
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient

# Set up logging
logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_azure_subscription_id():
    """
    Automatically fetch the Azure subscription ID of the logged-in user.
    """
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscription_id = next(subscription_client.subscriptions.list()).subscription_id
        print(f"📡 Detected Azure Subscription ID: {subscription_id}")
        return subscription_id
    except Exception as e:
        logging.error(f"Error fetching Azure Subscription ID: {e}")
        print("❌ Could not auto-fetch Azure Subscription ID. Please check your credentials.")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Cloud Security Misconfiguration Scanner")
    parser.add_argument("--platform", choices=["aws", "azure"], required=True, help="Cloud platform to scan")
    parser.add_argument("--output", choices=["json", "html", "csv"], default="json", help="Output report format")
    args = parser.parse_args()

    # Initialize scanner based on selected platform
    if args.platform == "aws":
        scanner = AWSScanner()
    elif args.platform == "azure":
        subscription_id = get_azure_subscription_id()
        scanner = AzureScanner(subscription_id)
    else:
        print("Invalid platform selection!")
        return

    print(f"🚀 Starting scan on {args.platform}...")
    findings = scanner.scan()

    if not findings:
        print("✅ No misconfigurations detected!")
        logging.info(f"No issues found on {args.platform}.")
    else:
        print(f"⚠️ Scan complete. Found {len(findings)} issues. Generating report...")

        # Generate report in user-specified format
        report_file = ReportGenerator.generate(findings, args.platform, args.output)
        print(f"📄 Report generated: {report_file}")
        logging.info(f"Report saved as {report_file}")

if __name__ == "__main__":
    main()

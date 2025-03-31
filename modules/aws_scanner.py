import boto3
import logging


class AWSScanner:
    def __init__(self):
        self.ec2 = boto3.client("ec2")
        self.iam = boto3.client("iam")
        self.s3 = boto3.client("s3")
        logging.basicConfig(filename="aws_scanner.log", level=logging.INFO)

    def scan_security_groups(self):
        findings = []
        print("Scanning AWS Security Groups for open ports...")

        try:
            response = self.ec2.describe_security_groups()
            for sg in response.get("SecurityGroups", []):
                for perm in sg.get("IpPermissions", []):
                    ip_ranges = perm.get("IpRanges", [])
                    for ip_range in ip_ranges:
                        cidr = ip_range.get("CidrIp", "")
                        if cidr == "0.0.0.0/0":
                            port = perm.get("FromPort", "All")
                            protocol = perm.get("IpProtocol", "All")

                            findings.append({
                                "Type": "Security Group",
                                "Resource": sg["GroupId"],
                                "Port": port,
                                "Protocol": protocol,
                                "Issue": f"Open to the public on port {port}/{protocol}"
                            })

                            print(f"Security Group {sg['GroupId']} is open to 0.0.0.0/0 on port {port}/{protocol}")

        except Exception as e:
            logging.error(f"Error scanning security groups: {e}")

        print(f"Security Group Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan_iam_roles(self):
        findings = []
        print("Scanning IAM users for over-permissive policies...")

        try:
            users = self.iam.list_users().get("Users", [])
            for user in users:
                policies = self.iam.list_attached_user_policies(UserName=user["UserName"]).get("AttachedPolicies", [])
                for policy in policies:
                    findings.append({
                        "Type": "IAM Policy",
                        "Resource": user["UserName"],
                        "Issue": f"Attached policy {policy['PolicyName']} might be overly permissive"
                    })
                    print(f"IAM user {user['UserName']} has attached policy {policy['PolicyName']}")

        except Exception as e:
            logging.error(f"Error scanning IAM users: {e}")

        print(f"IAM User Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan_s3_buckets(self):
        findings = []
        print("Scanning S3 buckets for public access...")

        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    acl = self.s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        if grant["Grantee"].get("URI", "").endswith("AllUsers"):
                            findings.append({
                                "Type": "S3 Bucket",
                                "Resource": name,
                                "Issue": "Bucket has public read access"
                            })
                            print(f"S3 bucket {name} is publicly readable")
                except Exception:
                    continue  # skip buckets that we can't access or analyze

        except Exception as e:
            logging.error(f"Error scanning S3 buckets: {e}")

        print(f"S3 Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan(self):
        print("Starting AWS Security Scan...")
        sg_findings = self.scan_security_groups()
        iam_findings = self.scan_iam_roles()
        s3_findings = self.scan_s3_buckets()

        all_findings = sg_findings + iam_findings + s3_findings
        print(f"Total Findings: {len(all_findings)}")
        return all_findings

import boto3
import logging

class AWSScanner:
    def __init__(self):
        self.ec2 = boto3.client("ec2")
        self.s3 = boto3.client("s3")
        self.iam = boto3.client("iam")
        logging.basicConfig(filename="aws_scanner.log", level=logging.INFO)

    def scan_security_groups(self):
        """
        Scans AWS Security Groups for open ports accessible to the public.
        """
        findings = []
        print("Scanning AWS Security Groups for misconfigurations...")

        try:
            response = self.ec2.describe_security_groups()
            for sg in response["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range["CidrIp"] == "0.0.0.0/0":  # Open to public
                            if perm["FromPort"] in [22, 3389]:  # Only flag SSH & RDP by default
                                findings.append({
                                    "Type": "Security Group",
                                    "SecurityGroupId": sg["GroupId"],
                                    "Port": perm["FromPort"],
                                    "Protocol": perm["IpProtocol"],
                                    "Issue": "Open port accessible to the public",
                                })
                                print(f"⚠️ Open port {perm['FromPort']} in {sg['GroupName']} (ID: {sg['GroupId']})")

            print(f"Security Group Scan Completed. Found {len(findings)} issues.")
        except Exception as e:
            logging.error(f"Error during Security Group scan: {str(e)}")

        return findings

    def scan_s3_buckets(self):
        """
        Scans AWS S3 Buckets for public access.
        """
        findings = []
        print("🔍 Scanning S3 Buckets for public access...")

        try:
            response = self.s3.list_buckets()
            for bucket in response["Buckets"]:
                acl = self.s3.get_bucket_acl(Bucket=bucket["Name"])
                for grant in acl["Grants"]:
                    if grant["Grantee"].get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                        findings.append({
                            "Type": "S3 Bucket",
                            "BucketName": bucket["Name"],
                            "Issue": "Publicly accessible bucket"
                        })
                        print(f"⚠️ Public S3 Bucket: {bucket['Name']}")

            print(f"S3 Bucket Scan Completed. Found {len(findings)} issues.")
        except Exception as e:
            logging.error(f"Error during S3 scan: {str(e)}")

        return findings

    def scan_iam_users(self):
        """
        Scans AWS IAM users for overly permissive roles.
        """
        findings = []
        print("Scanning IAM users for over-permissioned roles...")

        try:
            response = self.iam.list_users()
            for user in response["Users"]:
                attached_policies = self.iam.list_attached_user_policies(UserName=user["UserName"])
                for policy in attached_policies["AttachedPolicies"]:
                    if policy["PolicyName"] in ["AdministratorAccess"]:  # Flag full admin access
                        findings.append({
                            "Type": "IAM User",
                            "UserName": user["UserName"],
                            "Policy": policy["PolicyName"],
                            "Issue": "User has AdministratorAccess policy"
                        })
                        print(f"⚠️ User {user['UserName']} has full AdministratorAccess!")

            print(f"IAM User Scan Completed. Found {len(findings)} issues.")
        except Exception as e:
            logging.error(f"Error during IAM scan: {str(e)}")

        return findings

    def scan(self):
        """
        Runs all AWS security scans.
        """
        print("Starting AWS Security Scan...")
        security_findings = self.scan_security_groups()
        s3_findings = self.scan_s3_buckets()
        iam_findings = self.scan_iam_users()

        all_findings = security_findings + s3_findings + iam_findings
        print(f"Total Findings: {len(all_findings)}")
        
        return all_findings

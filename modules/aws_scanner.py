import boto3

class AWSScanner:
    def __init__(self):
        self.ec2 = boto3.client("ec2")

    def scan(self):
        findings = []
        print("Scanning AWS Security Groups for misconfigurations...")

        try:
            response = self.ec2.describe_security_groups()
            for sg in response["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    if perm.get("IpRanges", []) and perm["IpRanges"][0]["CidrIp"] == "0.0.0.0/0":
                        findings.append({
                            "SecurityGroupId": sg["GroupId"],
                            "Port": perm["FromPort"],
                            "Protocol": perm["IpProtocol"],
                            "Issue": "Open port accessible to the public"
                        })
            print(f"Scan completed. Found {len(findings)} issues.")
        except Exception as e:
            print(f"Error during AWS scan: {str(e)}")

        return findings

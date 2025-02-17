import boto3

class AWSScanner:
    def __init__(self):
        self.ec2 = boto3.client("ec2")

    def scan(self):
        findings = []
        print("Starting AWS Security Group Scan...")

        try:
            response = self.ec2.describe_security_groups()
            for sg in response.get("SecurityGroups", []):
                sg_id = sg.get("GroupId", "Unknown")
                sg_name = sg.get("GroupName", "Unnamed")

                print(f"Scanning Security Group: {sg_name} (ID: {sg_id})")

                # Check Inbound (Ingress) Rules
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            print(f"Found OPEN INBOUND port {perm.get('FromPort', 'ALL')} in {sg_name}")
                            findings.append({
                                "SecurityGroupId": sg_id,
                                "GroupName": sg_name,
                                "Direction": "Inbound",
                                "Port": perm.get("FromPort", "ALL"),
                                "Protocol": perm.get("IpProtocol", "ALL"),
                                "Issue": "Open port accessible to the public"
                            })

                # Check Outbound (Egress) Rules
                for perm in sg.get("IpPermissionsEgress", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            print(f"Found OPEN OUTBOUND port {perm.get('FromPort', 'ALL')} in {sg_name}")
                            findings.append({
                                "SecurityGroupId": sg_id,
                                "GroupName": sg_name,
                                "Direction": "Outbound",
                                "Port": perm.get("FromPort", "ALL"),
                                "Protocol": perm.get("IpProtocol", "ALL"),
                                "Issue": "Unrestricted outbound traffic"
                            })

            print(f"Scan Completed. {len(findings)} issues found.")
        except Exception as e:
            print(f"Error during AWS scan: {str(e)}")

        return findings

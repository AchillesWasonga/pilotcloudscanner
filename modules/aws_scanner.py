import boto3

class AWSScanner:
    def __init__(self):
        self.ec2 = boto3.client("ec2")

    def scan(self):
        findings = []
        print("🚀 Starting AWS Security Scan...")
        
        try:
            # Fetch all security groups
            response = self.ec2.describe_security_groups()
            print(f"🔍 Found {len(response['SecurityGroups'])} security groups.")

            for sg in response["SecurityGroups"]:
                print(f"⚡ Checking Security Group: {sg['GroupName']} (ID: {sg['GroupId']})")

                # Iterate over inbound rules
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):  # Iterate over ALL IP rules
                        if ip_range["CidrIp"] == "0.0.0.0/0":  # Open to the public
                            print(f"🚨 ALERT: Open security group detected: {sg['GroupName']} (Port: {perm.get('FromPort', 'All')})")

                            findings.append({
                                "SecurityGroupId": sg["GroupId"],
                                "GroupName": sg["GroupName"],
                                "Port": perm.get("FromPort", "All"),
                                "Protocol": perm.get("IpProtocol", "All"),
                                "Issue": "Security group allows unrestricted public access"
                            })
                            
            if findings:
                print(f"✅ Scan completed. Found {len(findings)} misconfigurations.")
            else:
                print("🎉 No security group misconfigurations detected!")

        except Exception as e:
            print(f"❌ Error during AWS scan: {str(e)}")

        return findings

from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient

class AzureScanner:
    def __init__(self):
        credential = DefaultAzureCredential()
        self.network_client = NetworkManagementClient(credential, "<YOUR_SUBSCRIPTION_ID>")

    def scan(self):
        findings = []
        # Scan NSGs for open ports
        for nsg in self.network_client.network_security_groups.list_all():
            for rule in nsg.security_rules:
                if rule.access == "Allow" and "Any" in rule.destination_address_prefix:
                    findings.append({
                        "NSG": nsg.name,
                        "Port": rule.destination_port_range,
                        "Protocol": rule.protocol,
                        "Issue": "Open port accessible to the public"
                    })
        return findings

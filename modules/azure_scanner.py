from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
import logging

class AzureScanner:
    def __init__(self, subscription_id):
        self.credential = DefaultAzureCredential()
        self.subscription_id = subscription_id
        self.network_client = NetworkManagementClient(self.credential, subscription_id)
        self.compute_client = ComputeManagementClient(self.credential, subscription_id)
        self.storage_client = StorageManagementClient(self.credential, subscription_id)
        
        logging.basicConfig(filename="azure_scanner.log", level=logging.INFO)

    def scan_network_security_groups(self):
        """
        Scans Azure NSGs for open ports.
        """
        findings = []
        print("🔍 Scanning Azure NSGs for open ports...")

        try:
            for nsg in self.network_client.network_security_groups.list_all():
                for rule in nsg.security_rules:
                    if rule.access == "Allow" and rule.destination_address_prefix == "*":
                        if int(rule.destination_port_range) in [22, 3389, 80, 443]:  # Flag only critical ports
                            findings.append({
                                "Type": "NSG Rule",
                                "NSG": nsg.name,
                                "Port": rule.destination_port_range,
                                "Protocol": rule.protocol,
                                "Issue": "Open port accessible to the public"
                            })
                            print(f"⚠️ Open {rule.protocol} port {rule.destination_port_range} in NSG {nsg.name}")

            print(f"NSG Scan Completed. Found {len(findings)} issues.")
        except Exception as e:
            logging.error(f"Error scanning NSGs: {str(e)}")

        return findings

    def scan_public_vms(self):
        """
        Scans Azure Virtual Machines for public IP exposure.
        """
        findings = []
        print("Scanning Azure Virtual Machines for public exposure...")

        try:
            for vm in self.compute_client.virtual_machines.list_all():
                network_interfaces = self.network_client.network_interfaces.list_virtual_machine_scale_set_network_interfaces(
                    vm.name, vm.resource_group
                )
                for nic in network_interfaces:
                    for ip_config in nic.ip_configurations:
                        if ip_config.public_ip_address:
                            findings.append({
                                "Type": "Virtual Machine",
                                "VM Name": vm.name,
                                "Public IP": ip_config.public_ip_address,
                                "Issue": "VM has a public IP"
                            })
                            print(f"⚠️ VM {vm.name} has public IP: {ip_config.public_ip_address}")

            print(f"VM Scan Completed. Found {len(findings)} issues.")
        except Exception as e:
            logging.error(f"Error scanning VMs: {str(e)}")

        return findings

    def scan_storage_accounts(self):
        """
        Scans Azure Storage Accounts for public access.
        """
        findings = []
        print("🔍 Scanning Azure Storage Accounts for public access...")

        try:
            for account in self.storage_client.storage_accounts.list():
                if account.allow_blob_public_access:
                    findings.append({
                        "Type": "Storage Account",
                        "Account Name": account.name,
                        "Issue": "Public blob access enabled"
                    })
                    print(f"⚠️ Storage Account {account.name} allows public blob access!")

            print(f"Storage Scan Completed. Found {len(findings)} issues.")
        except Exception as e:
            logging.error(f"Error scanning storage accounts: {str(e)}")

        return findings

    def scan(self):
        """
        Runs all Azure security scans.
        """
        print("Starting Azure Security Scan...")
        nsg_findings = self.scan_network_security_groups()
        vm_findings = self.scan_public_vms()
        storage_findings = self.scan_storage_accounts()

        all_findings = nsg_findings + vm_findings + storage_findings
        print(f"🔹 Total Findings: {len(all_findings)}")
        
        return all_findings

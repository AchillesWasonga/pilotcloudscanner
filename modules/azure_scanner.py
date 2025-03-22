from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network.models import SecurityRule
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
        Scans Azure NSGs for open ports accessible from the Internet.
        """
        findings = []
        print("🔍 Scanning Azure NSGs for open ports...")

        try:
            for nsg in self.network_client.network_security_groups.list_all():
                for rule in nsg.security_rules:
                    if rule.access == "Allow" and rule.direction == "Inbound":
                        source = rule.source_address_prefix
                        if source in ["*", "0.0.0.0/0", "Internet"]:
                            if rule.destination_port_range and rule.destination_port_range.isdigit():
                                port = int(rule.destination_port_range)
                                if port in [22, 80, 443, 3389]:
                                    findings.append({
                                        "Type": "NSG Rule",
                                        "NSG": nsg.name,
                                        "Port": port,
                                        "Protocol": rule.protocol,
                                        "Issue": "Open port accessible to the public"
                                    })
                                    print(f"⚠️ NSG {nsg.name} has open {rule.protocol} port {port} to the public.")
        except Exception as e:
            logging.error(f"Error scanning NSGs: {str(e)}")

        print(f"✅ NSG Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan_public_vms(self):
        """
        Scans Azure Virtual Machines for public IP exposure.
        """
        findings = []
        print("🔍 Scanning Azure Virtual Machines for public IP exposure...")

        try:
            for vm in self.compute_client.virtual_machines.list_all():
                resource_group = vm.id.split("/")[4]
                nic_refs = vm.network_profile.network_interfaces

                for nic_ref in nic_refs:
                    nic_name = nic_ref.id.split("/")[-1]
                    nic = self.network_client.network_interfaces.get(resource_group, nic_name)

                    for ip_config in nic.ip_configurations:
                        if ip_config.public_ip_address:
                            public_ip = ip_config.public_ip_address.id.split("/")[-1]
                            findings.append({
                                "Type": "Virtual Machine",
                                "VM Name": vm.name,
                                "Public IP": public_ip,
                                "Issue": "VM is publicly exposed"
                            })
                            print(f"⚠️ VM {vm.name} has a public IP assigned: {public_ip}")
        except Exception as e:
            logging.error(f"Error scanning public VMs: {str(e)}")

        print(f"✅ VM Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan_storage_accounts(self):
        """
        Scans Azure Storage Accounts for public blob access.
        """
        findings = []
        print("🔍 Scanning Azure Storage Accounts for public blob access...")

        try:
            for account in self.storage_client.storage_accounts.list():
                if account.allow_blob_public_access is False:
                    continue
                findings.append({
                    "Type": "Storage Account",
                    "Account Name": account.name,
                    "Issue": "Public blob access enabled"
                })
                print(f"⚠️ Storage Account {account.name} allows public blob access!")
        except Exception as e:
            logging.error(f"Error scanning storage accounts: {str(e)}")

        print(f"✅ Storage Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan(self):
        """
        Orchestrates all Azure security scans and returns combined findings.
        """
        print("🚀 Starting Azure Security Scan...")
        nsg_findings = self.scan_network_security_groups()
        vm_findings = self.scan_public_vms()
        storage_findings = self.scan_storage_accounts()

        all_findings = nsg_findings + vm_findings + storage_findings
        print(f"🔹 Total Findings: {len(all_findings)}")
        return all_findings

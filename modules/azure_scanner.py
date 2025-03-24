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
        Scans Azure NSGs for inbound rules that allow traffic from the public internet.
        """
        findings = []
        print("🔍 Scanning Azure NSGs for open ports...")

        try:
            for nsg in self.network_client.network_security_groups.list_all():
                for rule in nsg.security_rules:
                    if rule.access.lower() == "allow" and rule.direction.lower() == "inbound":
                        source = (rule.source_address_prefix or "").strip().lower()
                        if source in ["*", "0.0.0.0/0", "any", "internet"]:
                            port = rule.destination_port_range or "Any"
                            protocol = rule.protocol or "Any"

                            findings.append({
                                "Type": "NSG Rule",
                                "Resource": nsg.name,
                                "Port": port,
                                "Protocol": protocol,
                                "Issue": "Inbound port open to the internet"
                            })

                            print(f"⚠️ NSG '{nsg.name}' has {protocol} port {port} open to the public.")

        except Exception as e:
            logging.error(f"Error scanning NSGs: {str(e)}")

        print(f"✅ NSG Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan_public_vms(self):
        """
        Scans Azure VMs for public IPs.
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
                            public_ip_id = ip_config.public_ip_address.id
                            public_ip_name = public_ip_id.split("/")[-1]

                            findings.append({
                                "Type": "Virtual Machine",
                                "Resource": vm.name,
                                "Public IP": public_ip_name,
                                "Issue": "VM has a public IP address"
                            })

                            print(f"⚠️ VM '{vm.name}' has a public IP: {public_ip_name}")

        except Exception as e:
            logging.error(f"Error scanning VMs: {str(e)}")

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
                if account.allow_blob_public_access:
                    findings.append({
                        "Type": "Storage Account",
                        "Resource": account.name,
                        "Issue": "Public blob access is enabled"
                    })
                    print(f"⚠️ Storage Account '{account.name}' allows public blob access!")

        except Exception as e:
            logging.error(f"Error scanning storage accounts: {str(e)}")

        print(f"✅ Storage Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan(self):
        """
        Runs all Azure security scans and returns combined findings.
        """
        print("🚀 Starting Azure Security Scan...")
        nsg_findings = self.scan_network_security_groups()
        vm_findings = self.scan_public_vms()
        storage_findings = self.scan_storage_accounts()

        all_findings = nsg_findings + vm_findings + storage_findings
        print(f"🔹 Total Findings: {len(all_findings)}")
        return all_findings

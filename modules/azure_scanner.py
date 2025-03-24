from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
import logging

class AzureScanner:
    def __init__(self, subscription_id):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.network_client = NetworkManagementClient(self.credential, subscription_id)
        self.compute_client = ComputeManagementClient(self.credential, subscription_id)
        self.storage_client = StorageManagementClient(self.credential, subscription_id)

        logging.basicConfig(filename="azure_scanner.log", level=logging.INFO)

    def scan_network_security_groups(self):
        """
        Scans NSGs attached to NICs and subnets for publicly accessible critical ports.
        """
        findings = []
        print("🔍 Scanning Azure NSGs for open ports...")

        try:
            # Fetch all NICs
            for nic in self.network_client.network_interfaces.list_all():
                nsg = nic.network_security_group
                if not nsg:
                    continue

                nsg_name = nsg.id.split("/")[-1]
                resource_group = nic.id.split("/")[4]

                # Get full NSG object
                nsg_obj = self.network_client.network_security_groups.get(resource_group, nsg_name)

                for rule in nsg_obj.security_rules:
                    if rule.access != "Allow" or rule.direction != "Inbound":
                        continue

                    source = rule.source_address_prefix or "*"
                    ports_to_flag = []

                    if rule.destination_port_range:
                        if rule.destination_port_range == "*" or rule.destination_port_range == "":
                            ports_to_flag = [22, 80, 443, 3389]
                        elif "-" in rule.destination_port_range:
                            start, end = map(int, rule.destination_port_range.split("-"))
                            ports_to_flag = list(range(start, end + 1))
                        elif rule.destination_port_range.isdigit():
                            ports_to_flag = [int(rule.destination_port_range)]

                    if source in ["*", "0.0.0.0/0", "Internet"]:
                        for port in ports_to_flag:
                            findings.append({
                                "Type": "NSG Rule",
                                "NSG": nsg_name,
                                "Port": port,
                                "Protocol": rule.protocol,
                                "Issue": f"Open inbound port {port} accessible from {source}"
                            })
                            print(f"⚠️ NSG {nsg_name} allows inbound {rule.protocol} on port {port} from {source}")

        except Exception as e:
            logging.error(f"Error scanning NSGs: {str(e)}")

        print(f"✅ NSG Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan_public_vms(self):
        """
        Checks Azure VMs for public IP exposure.
        """
        findings = []
        print("🔍 Scanning Azure Virtual Machines for public IP exposure...")

        try:
            for vm in self.compute_client.virtual_machines.list_all():
                resource_group = vm.id.split("/")[4]
                vm_name = vm.name

                for nic_ref in vm.network_profile.network_interfaces:
                    nic_name = nic_ref.id.split("/")[-1]
                    nic = self.network_client.network_interfaces.get(resource_group, nic_name)

                    for ip_config in nic.ip_configurations:
                        if ip_config.public_ip_address:
                            public_ip = ip_config.public_ip_address.id.split("/")[-1]
                            findings.append({
                                "Type": "Virtual Machine",
                                "VM Name": vm_name,
                                "Public IP": public_ip,
                                "Issue": "VM is publicly exposed"
                            })
                            print(f"⚠️ VM {vm_name} has a public IP: {public_ip}")

        except Exception as e:
            logging.error(f"Error scanning VMs: {str(e)}")

        print(f"✅ VM Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan_storage_accounts(self):
        """
        Flags Azure Storage Accounts that allow blob public access.
        """
        findings = []
        print("🔍 Scanning Azure Storage Accounts for public blob access...")

        try:
            for account in self.storage_client.storage_accounts.list():
                if account.allow_blob_public_access:
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
        Orchestrates all Azure security scans.
        """
        print("🚀 Starting Azure Security Scan...")
        nsg_findings = self.scan_network_security_groups()
        vm_findings = self.scan_public_vms()
        storage_findings = self.scan_storage_accounts()

        all_findings = nsg_findings + vm_findings + storage_findings
        print(f"🔹 Total Findings: {len(all_findings)}")
        return all_findings

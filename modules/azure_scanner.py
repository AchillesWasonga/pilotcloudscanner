import logging
import re

from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.storage.blob import BlobServiceClient

class AzureScanner:
    def __init__(self):
        self.credential = DefaultAzureCredential()
        self.subscription_id = self.get_subscription_id()
        self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
        self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)
        self.storage_client = StorageManagementClient(self.credential, self.subscription_id)

        logging.basicConfig(filename="azure_scanner.log", level=logging.INFO)

    def get_subscription_id(self):
        try:
            sub_client = SubscriptionClient(self.credential)
            sub = next(sub_client.subscriptions.list())
            print(f"Detected Azure Subscription ID: {sub.subscription_id}")
            return sub.subscription_id
        except Exception as e:
            print("Could not auto-fetch Azure Subscription ID. Please check your credentials.")
            logging.error(f"Subscription ID fetch error: {e}")
            exit(1)

    def scan_network_security_groups(self):
        findings = []
        print("Scanning Azure NSGs for open ports...")

        try:
            for nsg in self.network_client.network_security_groups.list_all():
                for rule in nsg.security_rules:
                    if rule.access == "Allow" and rule.direction == "Inbound":
                        sources = []

                        if rule.source_address_prefix:
                            sources.append(rule.source_address_prefix)
                        if rule.source_address_prefixes:
                            sources.extend(rule.source_address_prefixes)

                        for source in sources:
                            if (source or "").lower().strip() in ["*", "0.0.0.0/0", "any", "internet"]:
                                port = rule.destination_port_range or "Any"
                                protocol = rule.protocol or "Any"

                                findings.append({
                                    "Type": "NSG Rule",
                                    "Resource": nsg.name,
                                    "Port": port,
                                    "Protocol": protocol,
                                    "Issue": f"Publicly accessible port {port}/{protocol}"
                                })

                                print(f"NSG {nsg.name} allows public {protocol} access on port {port}")
                                break  # Avoid duplicate entries for same rule
        except Exception as e:
            logging.error(f"Error scanning NSGs: {e}")

        print(f"NSG Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan_public_vms(self):
        findings = []
        print("Scanning Azure Virtual Machines for public IP exposure...")

        try:
            for vm in self.compute_client.virtual_machines.list_all():
                match = re.search(r"/resourceGroups/([^/]+)/", vm.id, re.IGNORECASE)
                rg_name = match.group(1) if match else None
                if not rg_name:
                    continue

                for nic_ref in vm.network_profile.network_interfaces:
                    nic_name = nic_ref.id.split("/")[-1]
                    nic = self.network_client.network_interfaces.get(rg_name, nic_name)

                    for ip_config in nic.ip_configurations:
                        if ip_config.public_ip_address:
                            try:
                                public_ip_id = ip_config.public_ip_address.id
                                public_ip_name = public_ip_id.split("/")[-1]
                                public_ip = self.network_client.public_ip_addresses.get(rg_name, public_ip_name)

                                if public_ip.ip_address:
                                    findings.append({
                                        "Type": "Virtual Machine",
                                        "Resource": vm.name,
                                        "Public IP": public_ip.ip_address,
                                        "Issue": "VM is publicly exposed"
                                    })

                                    print(f"VM {vm.name} has public IP: {public_ip.ip_address}")
                            except Exception as e:
                                logging.warning(f"Failed to fetch public IP for {vm.name}: {e}")
        except Exception as e:
            logging.error(f"Error scanning public VMs: {e}")

        print(f"VM Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan_storage_accounts(self):
        findings = []
        print("Scanning Azure Storage Accounts for public blob access...")

        try:
            for account in self.storage_client.storage_accounts.list():
                try:
                    blob_service = BlobServiceClient(
                        account_url=f"https://{account.name}.blob.core.windows.net",
                        credential=self.credential
                    )
                    for container in blob_service.list_containers():
                        props = blob_service.get_container_client(container.name).get_container_properties()
                        if props.public_access:
                            findings.append({
                                "Type": "Storage Container",
                                "Resource": f"{account.name}/{container.name}",
                                "Issue": "Container is publicly accessible"
                            })
                            print(f"Storage container {container.name} in account {account.name} is public")

                except Exception as e:
                    logging.warning(f"Skipping storage account {account.name}: {e}")
        except Exception as e:
            logging.error(f"Error scanning storage accounts: {e}")

        print(f"Storage Scan Completed. Found {len(findings)} issues.")
        return findings

    def scan(self):
        print("Starting Azure Security Scan...")
        nsg_findings = self.scan_network_security_groups()
        vm_findings = self.scan_public_vms()
        storage_findings = self.scan_storage_accounts()

        all_findings = nsg_findings + vm_findings + storage_findings
        print(f"Total Findings: {len(all_findings)}")
        return all_findings

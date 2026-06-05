import os
import re
import logging
from core.logger import setup_logger
from core.cve_checker import CVEChecker
from core.compliance_mapper import ComplianceMapper  # <-- NEW IMPORT

logger = setup_logger()

class CloudAuditor:
    def __init__(self):
        self.findings = []
        self.cve_checker = CVEChecker()
        self.compliance_mapper = ComplianceMapper()  # <-- INITIALIZE

    def scan_aws_security(self):
        try:
            import boto3
            ec2 = boto3.resource('ec2')
            
            for sg in ec2.security_groups.all():
                for perm in sg.ip_permissions:
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            issue_text = "Security group allows public access from all IPs"
                            compliance = self.compliance_mapper.get_compliance_info(issue_text)  # <-- ADD

                            self.findings.append({
                                "issue": issue_text,
                                "risk": "High",
                                "resource": sg.id,
                                "cves": self.cve_checker.check_vulnerabilities("AWS EC2"),
                                "compliance": compliance,  # <-- SAVE
                                "fix": "Restrict access to only necessary IP addresses"
                            })
            logger.info("AWS scan completed")
        except Exception as e:
            logger.debug(f"AWS scan skipped: {e}")

    def scan_azure_security(self):
        try:
            from azure.mgmt.compute import ComputeManagementClient
            from azure.identity import DefaultAzureCredential
            issue_text = "Azure configuration review"
            compliance = self.compliance_mapper.get_compliance_info("cloud security configuration")  # <-- ADD

            self.findings.append({
                "issue": issue_text,
                "risk": "Info",
                "resource": "Azure Subscription",
                "cves": self.cve_checker.check_vulnerabilities("Azure"),
                "compliance": compliance,  # <-- SAVE
                "fix": "Ensure disk encryption, RBAC, and logging are properly enabled"
            })
            logger.info("Azure scan completed")
        except:
            pass

    def scan_docker_containers(self):
        try:
            import docker
            client = docker.from_env()
            docker_cves = self.cve_checker.check_vulnerabilities("Docker")
            for container in client.containers.list():
                if '0.0.0.0' in str(container.ports):
                    issue_text = "Container ports exposed publicly to the internet"
                    compliance = self.compliance_mapper.get_compliance_info(issue_text)  # <-- ADD

                    self.findings.append({
                        "issue": issue_text,
                        "risk": "Medium",
                        "resource": container.name,
                        "cves": docker_cves,
                        "compliance": compliance,  # <-- SAVE
                        "fix": "Bind ports only to localhost or specific internal interfaces"
                    })
        except:
            pass

    def scan_secrets_in_files(self, path="."):
        patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Generic Secret": r"['\"]?(api_key|secret|password|token)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+]{16,}['\"]?"
        }
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(('.py', '.env', '.json', '.yaml', '.yml')):
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                            content = f.read()
                            for name, pattern in patterns.items():
                                if re.search(pattern, content):
                                    issue_text = f"Possible {name} found in source code"
                                    compliance = self.compliance_mapper.get_compliance_info(issue_text)  # <-- ADD

                                    self.findings.append({
                                        "issue": issue_text,
                                        "risk": "Critical",
                                        "resource": os.path.join(root, file),
                                        "cves": [],
                                        "compliance": compliance,  # <-- SAVE
                                        "fix": "Remove hardcoded secrets, use environment variables or a secure vault"
                                    })
                    except:
                        pass

    # ... (rest of the code remains the same)
    

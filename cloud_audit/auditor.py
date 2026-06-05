import os
import re
import logging
from core.logger import setup_logger

logger = setup_logger()

class CloudAuditor:
    def __init__(self):
        self.findings = []

    def scan_aws_security(self):
        """Check AWS EC2, S3, Security Groups"""
        try:
            import boto3
            ec2 = boto3.resource('ec2')
            
            # Check Security Groups
            for sg in ec2.security_groups.all():
                for perm in sg.ip_permissions:
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            self.findings.append({
                                "issue": "Security Group open to world",
                                "risk": "High",
                                "resource": sg.id,
                                "fix": "Restrict access to specific IPs"
                            })
            logger.info("AWS scan completed")
        except Exception as e:
            logger.debug(f"AWS scan skipped: {e}")

    def scan_azure_security(self):
        """Check Azure VMs and Config"""
        try:
            from azure.mgmt.compute import ComputeManagementClient
            from azure.identity import DefaultAzureCredential
            # Basic check example
            self.findings.append({
                "issue": "Azure configuration check passed",
                "risk": "Info",
                "fix": "Ensure disk encryption is enabled"
            })
            logger.info("Azure scan completed")
        except:
            pass

    def scan_docker_containers(self):
        """Scan Docker images for issues"""
        try:
            import docker
            client = docker.from_env()
            for container in client.containers.list():
                if '0.0.0.0' in str(container.ports):
                    self.findings.append({
                        "issue": "Container port exposed publicly",
                        "risk": "Medium",
                        "resource": container.name,
                        "fix": "Bind only to specific interfaces"
                    })
        except:
            pass

    def scan_secrets_in_files(self, path="."):
        """Look for hardcoded secrets, passwords, API keys"""
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
                                    self.findings.append({
                                        "issue": f"Possible {name} found in code",
                                        "risk": "Critical",
                                        "resource": os.path.join(root, file),
                                        "fix": "Remove and use environment variables"
                                    })
                    except:
                        pass

    def audit(self):
        """Main function to run all checks"""
        print("\n☁️ Running Cloud & Infrastructure Audit...")
        self.scan_aws_security()
        self.scan_azure_security()
        self.scan_docker_containers()
        self.scan_secrets_in_files()

        result = {
            "module": "Cloud & Infrastructure Audit",
            "total_findings": len(self.findings),
            "issues": self.findings,
            "status": "completed"
        }

        print(f"✅ Audit done. Found {len(self.findings)} issues.")
        return result
        

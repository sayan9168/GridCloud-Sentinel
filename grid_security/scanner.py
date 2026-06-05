import socket
import logging
from scapy.all import ARP, Ether, srp
from gurux_dlms import GXDLMSClient, GXDLMSConnection
from core.logger import setup_logger
from core.cve_checker import CVEChecker
from core.compliance_mapper import ComplianceMapper  # <-- NEW IMPORT

logger = setup_logger()

class GridSecurityScanner:
    def __init__(self, subnet="192.168.1.0/24", dlms_port=4059):
        self.subnet = subnet
        self.dlms_port = dlms_port
        self.devices = []
        self.security_issues = []
        self.cve_checker = CVEChecker()
        self.compliance_mapper = ComplianceMapper()  # <-- INITIALIZE

    # ... (keep all existing methods: discover_devices, check_dlms_port, etc.)

    def analyze_dlms_security(self, ip):
        try:
            client = GXDLMSClient(True)
            client.useLogicalNameReferencing = True
            client.serverAddress = 1

            conn = GXDLMSConnection()
            conn.clientAddress = 16
            conn.serverAddress = 1
            conn.password = "123456"

            if self.check_dlms_port(ip):
                self.devices.append({"ip": ip, "protocol": "DLMS/COSEM"})
                
                # Check DLMS vulnerabilities
                dlms_cves = self.cve_checker.check_vulnerabilities("DLMS", "COSEM")
                issue_text = "Known vulnerabilities found in DLMS/COSEM firmware"
                compliance = self.compliance_mapper.get_compliance_info(issue_text)  # <-- ADD

                self.security_issues.append({
                    "ip": ip,
                    "issue": issue_text,
                    "risk": "High",
                    "cves": dlms_cves,
                    "compliance": compliance,  # <-- SAVE COMPLIANCE DATA
                    "fix": "Update device firmware to latest secure version, enable IEC 62351 security"
                })

                if conn.password in ["123456", "0000", "admin"]:
                    issue_text = "Default/weak credentials in use"
                    compliance = self.compliance_mapper.get_compliance_info(issue_text)  # <-- ADD

                    self.security_issues.append({
                        "ip": ip,
                        "issue": issue_text,
                        "risk": "High",
                        "cves": [],
                        "compliance": compliance,  # <-- SAVE
                        "fix": "Change default password immediately, use strong authentication"
                    })

                if client.authentication == 0:
                    issue_text = "No encryption or authentication enabled"
                    compliance = self.compliance_mapper.get_compliance_info(issue_text)  # <-- ADD

                    self.security_issues.append({
                        "ip": ip,
                        "issue": issue_text,
                        "risk": "Critical",
                        "cves": [],
                        "compliance": compliance,  # <-- SAVE
                        "fix": "Enable High Level Security (HLS) and encryption per IEC 62351 standard"
                    })

        except Exception as e:
            logger.debug(f"DLMS check failed for {ip}: {str(e)}")

    def scan_mqtt_bacnet(self, ip):
        ports = {"MQTT": 1883, "BACnet": 47808, "IEC 60870": 2404}
        for proto, port in ports.items():
            try:
                socket.create_connection((ip, port), timeout=1)
                cves = self.cve_checker.check_vulnerabilities(proto)
                issue_text = f"{proto} port open and accessible on the network"
                compliance = self.compliance_mapper.get_compliance_info(issue_text)  # <-- ADD

                self.devices.append({"ip": ip, "protocol": proto})
                self.security_issues.append({
                    "ip": ip,
                    "issue": issue_text,
                    "risk": "Medium",
                    "cves": cves,
                    "compliance": compliance,  # <-- SAVE
                    "fix": "Restrict access to trusted IPs only, enable TLS encryption"
                })
            except:
                pass

    # ... (keep the rest of the code unchanged)
    

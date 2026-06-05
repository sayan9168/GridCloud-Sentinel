import socket
import logging
from scapy.all import ARP, Ether, srp
from gurux_dlms import GXDLMSClient, GXDLMSConnection
from core.logger import setup_logger
from core.cve_checker import CVEChecker  # <-- NEW IMPORT

logger = setup_logger()

class GridSecurityScanner:
    def __init__(self, subnet="192.168.1.0/24", dlms_port=4059):
        self.subnet = subnet
        self.dlms_port = dlms_port
        self.devices = []
        self.security_issues = []
        self.cve_checker = CVEChecker()  # <-- INITIALIZE CVE CHECKER

    def discover_devices(self):
        logger.info(f"Discovering devices in {self.subnet}...")
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
        answered, _ = srp(arp_req, timeout=2, verbose=0)

        for _, rcv in answered:
            ip = rcv.psrc
            mac = rcv.hwsrc
            self.devices.append({"ip": ip, "mac": mac, "protocols": []})
        logger.info(f"Found {len(self.devices)} devices")
        return self.devices

    def check_dlms_port(self, ip):
        try:
            with socket.create_connection((ip, self.dlms_port), timeout=2):
                return True
        except:
            return False

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
                
                # Check DLMS related vulnerabilities
                dlms_cves = self.cve_checker.check_vulnerabilities("DLMS", "COSEM")
                if dlms_cves:
                    self.security_issues.append({
                        "ip": ip,
                        "issue": "Known vulnerabilities found in DLMS/COSEM",
                        "risk": "High",
                        "cves": dlms_cves,  # <-- ADDED CVE DETAILS
                        "fix": "Update firmware to latest version, enable IEC 62351 security"
                    })

                if conn.password in ["123456", "0000", "admin"]:
                    self.security_issues.append({
                        "ip": ip,
                        "issue": "Default/weak credentials",
                        "risk": "High",
                        "cves": [],
                        "fix": "Change default password immediately, use strong authentication"
                    })

                if client.authentication == 0:
                    self.security_issues.append({
                        "ip": ip,
                        "issue": "No encryption or authentication enabled",
                        "risk": "Critical",
                        "cves": [],
                        "fix": "Enable High Level Security (HLS) per IEC 62351 standard"
                    })

        except Exception as e:
            logger.debug(f"DLMS check failed for {ip}: {str(e)}")

    def scan_mqtt_bacnet(self, ip):
        ports = {"MQTT": 1883, "BACnet": 47808, "IEC 60870": 2404}
        for proto, port in ports.items():
            try:
                socket.create_connection((ip, port), timeout=1)
                cves = self.cve_checker.check_vulnerabilities(proto)
                self.devices.append({"ip": ip, "protocol": proto})
                self.security_issues.append({
                    "ip": ip,
                    "issue": f"{proto} port open to network",
                    "risk": "Medium",
                    "cves": cves,  # <-- ADDED CVE DETAILS
                    "fix": "Restrict access, enable TLS encryption"
                })
            except:
                pass

    def scan(self):
        print("\n🔍 Running AMI/Smart Grid Security Scan...")
        self.discover_devices()

        for dev in self.devices:
            ip = dev["ip"]
            self.analyze_dlms_security(ip)
            self.scan_mqtt_bacnet(ip)

        result = {
            "module": "AMI & Smart Grid",
            "devices_found": len(self.devices),
            "security_issues": self.security_issues,
            "status": "completed"
        }

        print(f"✅ Scan done. Found {len(self.security_issues)} issues.")
        return result
        

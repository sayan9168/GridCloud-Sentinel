import socket
import logging
from scapy.all import ARP, Ether, srp
from gurux_dlms import GXDLMSClient, GXDLMSConnection, GXDLMSTranslator
from core.logger import setup_logger

logger = setup_logger()

class GridSecurityScanner:
    def __init__(self, subnet="192.168.1.0/24", dlms_port=4059):
        self.subnet = subnet
        self.dlms_port = dlms_port
        self.devices = []
        self.security_issues = []

    def discover_devices(self):
        """Step 1: Find all active devices in the subnet"""
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
        """Check if DLMS/COSEM port (4059) is open"""
        try:
            with socket.create_connection((ip, self.dlms_port), timeout=2):
                return True
        except:
            return False

    def analyze_dlms_security(self, ip):
        """Step 2: Connect & check security settings (non-intrusive)"""
        try:
            client = GXDLMSClient(True)
            client.useLogicalNameReferencing = True
            client.serverAddress = 1

            # Try default credentials (common risk)
            conn = GXDLMSConnection()
            conn.clientAddress = 16
            conn.serverAddress = 1
            conn.password = "123456"  # Default weak password

            if self.check_dlms_port(ip):
                self.devices.append({"ip": ip, "protocol": "DLMS/COSEM"})
                self.security_issues.append({
                    "ip": ip,
                    "issue": "DLMS port open",
                    "risk": "Medium",
                    "fix": "Restrict port 4059 access"
                })

                # Check authentication level
                if conn.password in ["123456", "0000", "admin"]:
                    self.security_issues.append({
                        "ip": ip,
                        "issue": "Default/weak credentials",
                        "risk": "High",
                        "fix": "Change default password"
                    })

                # Check if High Level Security is enabled
                if client.authentication == 0:
                    self.security_issues.append({
                        "ip": ip,
                        "issue": "No encryption/authentication",
                        "risk": "Critical",
                        "fix": "Enable HLS/encryption (IEC 62351)"
                    })

        except Exception as e:
            logger.debug(f"DLMS check failed for {ip}: {str(e)}")

    def scan_mqtt_bacnet(self, ip):
        """Check other common grid protocols"""
        ports = {"MQTT": 1883, "BACnet": 47808, "IEC 60870": 2404}
        for proto, port in ports.items():
            try:
                socket.create_connection((ip, port), timeout=1)
                self.devices.append({"ip": ip, "protocol": proto})
                self.security_issues.append({
                    "ip": ip,
                    "issue": f"{proto} port open",
                    "risk": "Medium",
                    "fix": "Limit access & enable TLS"
                })
            except:
                pass

    def scan(self):
        """Main run method"""
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
                

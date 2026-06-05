from core.logger import setup_logger
from grid_security.scanner import GridSecurityScanner
from cloud_audit.auditor import CloudAuditor
from ai_threat_hunter.detector import ThreatHunter
from reporting.generator import ReportGenerator
from web_dashboard.main import start_dashboard

logger = setup_logger()

class GridCloudSentinel:
    def __init__(self):
        logger.info("Starting GridCloud Sentinel...")
        self.grid_scanner = GridSecurityScanner()
        self.cloud_auditor = CloudAuditor()
        self.threat_hunter = ThreatHunter()
        self.report_gen = ReportGenerator()

    def run_all_features(self):
        """Run all features via command line"""
        print("\n=== FEATURE 1: AMI & Smart Grid Security ===")
        grid_results = self.grid_scanner.scan()

        print("\n=== FEATURE 2: Cloud & Infrastructure Audit ===")
        cloud_results = self.cloud_auditor.audit()

        print("\n=== FEATURE 3: AI Threat Hunting ===")
        threats = self.threat_hunter.detect_anomalies(grid_results, cloud_results)

        print("\n=== GENERATING COMPLIANCE REPORT ===")
        self.report_gen.create_full_report(grid_results, cloud_results, threats)
        logger.info("Scan completed successfully.")

if __name__ == "__main__":
    print("Choose mode:")
    print("1. Command Line Interface")
    print("2. Advanced Web Dashboard")
    choice = input("Enter choice (1/2): ").strip()

    if choice == "2":
        start_dashboard()
    else:
        tool = GridCloudSentinel()
        tool.run_all_features()
        

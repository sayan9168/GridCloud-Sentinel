from core.logger import setup_logger
from grid_security.scanner import GridSecurityScanner
from cloud_audit.auditor import CloudAuditor
from ai_threat_hunter.detector import ThreatHunter

logger = setup_logger()

class GridCloudSentinel:
    def __init__(self):
        logger.info("Starting GridCloud Sentinel...")
        self.grid_scanner = GridSecurityScanner()
        self.cloud_auditor = CloudAuditor()
        self.threat_hunter = ThreatHunter()

    def run_all_features(self):
        """Run all 3 security modules in one go"""
        print("\n=== FEATURE 1: AMI & Smart Grid Security ===")
        grid_results = self.grid_scanner.scan()

        print("\n=== FEATURE 2: Cloud & Infrastructure Audit ===")
        cloud_results = self.cloud_auditor.audit()

        print("\n=== FEATURE 3: AI Threat Hunting ===")
        threats = self.threat_hunter.detect_anomalies(
            grid_data=grid_results,
            cloud_data=cloud_results
        )

        print("\n=== GENERATING COMPLIANCE REPORT ===")
        self.generate_report(grid_results, cloud_results, threats)

    def generate_report(self, grid_data, cloud_data, threats):
        """Combine all results into one report"""
        from reporting.generator import ReportGenerator
        ReportGenerator().create_full_report(grid_data, cloud_data, threats)
        logger.info("Report saved successfully.")

if __name__ == "__main__":
    tool = GridCloudSentinel()
    tool.run_all_features()
  

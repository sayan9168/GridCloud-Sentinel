from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from datetime import datetime

class ReportGenerator:
    def create_full_report(self, grid_data, cloud_data, ai_data):
        """Generate a complete PDF report with all findings"""
        filename = f"GridCloud_Sentinel_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        c = canvas.Canvas(filename, pagesize=A4)
        width, height = A4

        # Header
        c.setFont("Helvetica-Bold", 18)
        c.drawString(50, height - 50, "GRID CLOUD SENTINEL - SECURITY REPORT")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 75, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Grid Security Section
        y = height - 120
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "1. AMI & Smart Grid Security")
        y -= 25
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Devices Found: {grid_data.get('devices_found', 0)}")
        y -= 20
        c.drawString(50, y, f"Issues Found: {len(grid_data.get('security_issues', []))}")

        # Cloud Audit Section
        y -= 40
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "2. Cloud & Infrastructure Audit")
        y -= 25
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Total Findings: {cloud_data.get('total_findings', 0)}")

        # AI Threat Section
        y -= 40
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "3. AI Threat Hunting Results")
        y -= 25
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Potential Hidden Threats: {ai_data.get('unknown_threats_found', 0)}")

        c.save()
        print(f"📄 Full report saved as: {filename}")
        return filename
      

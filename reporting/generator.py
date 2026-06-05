from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from datetime import datetime

class ReportGenerator:
    def create_full_report(self, grid_data, cloud_data, ai_data):
        filename = f"GridCloud_Sentinel_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        c = canvas.Canvas(filename, pagesize=A4)
        width, height = A4

        # Header
        c.setFont("Helvetica-Bold", 18)
        c.drawString(50, height - 50, "GRID CLOUD SENTINEL - SECURITY REPORT")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 75, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, height - 95, "All findings include known vulnerability references")

        y = height - 130

        # --- Grid Security Section ---
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "1. AMI & Smart Grid Security")
        y -= 25
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Devices Found: {grid_data.get('devices_found', 0)}")
        y -= 20
        c.drawString(50, y, f"Security Issues: {len(grid_data.get('security_issues', []))}")
        y -= 20

        for issue in grid_data.get("security_issues", []):
            if y < 100:
                c.showPage()
                y = height - 50
            c.setFont("Helvetica-Bold", 11)
            c.drawString(60, y, f"• {issue.get('issue')} [{issue.get('risk')}]")
            y -= 18
            c.setFont("Helvetica", 10)
            c.drawString(70, y, f"IP: {issue.get('ip')}")
            y -= 15
            c.drawString(70, y, f"Fix: {issue.get('fix')}")
            y -= 15

            # Show CVEs if available
            if issue.get("cves"):
                c.setFont("Helvetica-Oblique", 9)
                c.drawString(70, y, "Related Known Vulnerabilities:")
                y -= 12
                for cve in issue["cves"]:
                    c.drawString(80, y, f"- {cve['cve_id']} | Score: {cve['cvss_score']} | {cve['severity']}")
                    y -= 12
                    if y < 80:
                        c.showPage()
                        y = height - 50

            y -= 10

        # --- Cloud Audit Section ---
        if y < 150:
            c.showPage()
            y = height - 50
        y -= 20
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "2. Cloud & Infrastructure Audit")
        y -= 25
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Total Findings: {cloud_data.get('total_findings', 0)}")
        y -= 20

        for issue in cloud_data.get("issues", []):
            if y < 100:
                c.showPage()
                y = height - 50
            c.setFont("Helvetica-Bold", 11)
            c.drawString(60, y, f"• {issue.get('issue')} [{issue.get('risk')}]")
            y -= 18
            c.setFont("Helvetica", 10)
            c.drawString(70, y, f"Resource: {issue.get('resource')}")
            y -= 15
            c.drawString(70, y, f"Fix: {issue.get('fix')}")
            y -= 15

            if issue.get("cves"):
                c.setFont("Helvetica-Oblique", 9)
                c.drawString(70, y, "Related Known Vulnerabilities:")
                y -= 12
                for cve in issue["cves"]:
                    c.drawString(80, y, f"- {cve['cve_id']} | Score: {cve['cvss_score']} | {cve['severity']}")
                    y -= 12
                    if y < 80:
                        c.showPage()
                        y = height - 50

            y -= 10

        # --- AI Threat Section ---
        if y < 150:
            c.showPage()
            y = height - 50
        y -= 20
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "3. AI Threat Hunting Results")
        y -= 25
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Status: {ai_data.get('status', 'Completed')}")
        y -= 20
        c.drawString(50, y, f"Potential Hidden Threats Found: {ai_data.get('unknown_threats_found', 0)}")

        if ai_data.get("details"):
            y -= 25
            for threat in ai_data["details"]:
                if y < 100:
                    c.showPage()
                    y = height - 50
                c.setFont("Helvetica-Bold", 11)
                c.drawString(60, y, f"• Suspicious Activity Detected")
                y -= 18
                c.setFont("Helvetica", 10)
                c.drawString(70, y, f"Confidence: {threat.get('confidence')}%")
                y -= 15
                c.drawString(70, y, f"Source: {threat.get('source')}")
                y -= 15
                c.drawString(70, y, f"Recommendation: {threat.get('recommendation')}")
                y -= 15

        c.save()
        print(f"📄 Full report saved as: {filename}")
        return filename
        

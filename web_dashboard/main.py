from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import json
from datetime import datetime
from core.logger import setup_logger
from grid_security.scanner import GridSecurityScanner
from cloud_audit.auditor import CloudAuditor
from ai_threat_hunter.detector import ThreatHunter
from reporting.generator import ReportGenerator

logger = setup_logger()
app = FastAPI(title="GridCloud Sentinel Dashboard")

# Setup templates and static files
templates = Jinja2Templates(directory="web_dashboard/templates")
app.mount("/static", StaticFiles(directory="web_dashboard/static"), name="static")

# Store latest scan results
latest_results = {
    "grid": None,
    "cloud": None,
    "ai": None,
    "report_path": None,
    "last_scan": None
}

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "results": latest_results}
    )

@app.post("/run-scan")
async def run_full_scan():
    """Run all 3 security modules"""
    global latest_results
    try:
        logger.info("Starting full scan from dashboard...")
        
        # Initialize tools
        grid_scanner = GridSecurityScanner()
        cloud_auditor = CloudAuditor()
        threat_hunter = ThreatHunter()
        report_gen = ReportGenerator()

        # Run scans
        grid_data = grid_scanner.scan()
        cloud_data = cloud_auditor.audit()
        ai_data = threat_hunter.detect_anomalies(grid_data, cloud_data)
        
        # Generate report
        report_path = report_gen.create_full_report(grid_data, cloud_data, ai_data)

        # Save results
        latest_results.update({
            "grid": grid_data,
            "cloud": cloud_data,
            "ai": ai_data,
            "report_path": report_path,
            "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        return {"status": "success", "message": "Scan completed successfully"}

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return {"status": "error", "message": str(e)}

@app.get("/get-results")
async def get_results():
    """Return latest scan data as JSON"""
    return latest_results

@app.get("/download-report")
async def download_report():
    """Download generated PDF report"""
    if latest_results["report_path"]:
        return FileResponse(
            path=latest_results["report_path"],
            filename=latest_results["report_path"].split("/")[-1],
            media_type="application/pdf"
        )
    return {"error": "No report available"}

def start_dashboard():
    """Start the web server"""
    print("\n🌐 Starting Advanced Web Dashboard...")
    print("📊 Access it at: http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

if __name__ == "__main__":
    start_dashboard()
      

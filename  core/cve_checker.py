import requests
import logging
from core.logger import setup_logger

logger = setup_logger()

class CVEChecker:
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def check_cves(self, product_name, version=None):
        """Check known vulnerabilities for a product/version"""
        params = {
            "keywordSearch": f"{product_name} {version}" if version else product_name,
            "resultsPerPage": 5
        }
        try:
            response = requests.get(self.nvd_api_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                cves = []
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln["cve"]["id"]
                    desc = vuln["cve"]["descriptions"][0]["value"]
                    score = vuln.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
                    cves.append({
                        "cve_id": cve_id,
                        "cvss_score": score,
                        "description": desc[:200] + "...",
                        "severity": "Critical" if float(score)>=9 else "High" if float(score)>=7 else "Medium" if float(score)>=4 else "Low"
                    })
                return cves
        except Exception as e:
            logger.debug(f"CVE check failed: {e}")
        return []
      

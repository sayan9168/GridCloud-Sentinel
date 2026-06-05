import requests
import logging
from core.logger import setup_logger

logger = setup_logger()

class CVEChecker:
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.timeout = 10

    def check_vulnerabilities(self, product_name, version=None):
        """
        Check NVD database for known vulnerabilities
        Returns list of CVEs with severity, score, and description
        """
        search_term = f"{product_name} {version}" if version else product_name
        params = {
            "keywordSearch": search_term,
            "resultsPerPage": 5,
            "noRejected": ""
        }

        try:
            response = requests.get(self.nvd_api_url, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            cve_list = []
            for item in data.get("vulnerabilities", []):
                cve_data = item["cve"]
                cve_id = cve_data["id"]
                description = cve_data["descriptions"][0]["value"]

                # Get CVSS score and severity
                metrics = cve_data.get("metrics", {}).get("cvssMetricV31", [])
                if metrics:
                    cvss_score = metrics[0]["cvssData"]["baseScore"]
                    severity = metrics[0]["cvssData"]["baseSeverity"]
                else:
                    cvss_score = "N/A"
                    severity = "Unknown"

                cve_list.append({
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": description[:250] + "..." if len(description) > 250 else description
                })

            return cve_list

        except Exception as e:
            logger.debug(f"CVE check failed for {search_term}: {str(e)}")
            return []
          

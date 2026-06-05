from core.logger import setup_logger

logger = setup_logger()

class ComplianceMapper:
    """
    Maps security findings to international standards and regulations:
    - NIS 2 Directive (EU)
    - IEC 62443 (Industrial Control Systems)
    - ISO 27001 / ISO 27002
    - NIST SP 800 Series
    - GDPR
    - IEC 62351 (Power Grid Security)
    """

    # Rule database: keywords mapped to standards and requirements
    COMPLIANCE_RULES = {
        "default password": {
            "standards": [
                "NIS 2 Directive - Article 16",
                "IEC 62443-3-3 - SR 2.5",
                "ISO 27001 A.9.2.1",
                "NIST SP 800-53 IA-5",
                "IEC 62351-8"
            ],
            "description": "Default or easily guessable credentials must be changed immediately to prevent unauthorized access."
        },
        "weak password": {
            "standards": [
                "NIS 2 Directive - Article 16",
                "ISO 27001 A.9.2.2",
                "NIST SP 800-63B",
                "IEC 62351-8"
            ],
            "description": "Passwords must be complex, unique, and regularly rotated to resist brute-force and dictionary attacks."
        },
        "no encryption": {
            "standards": [
                "NIS 2 Directive - Article 15",
                "GDPR - Article 32",
                "IEC 62443-3-3 - SR 4.1",
                "ISO 27001 A.10.1.1",
                "IEC 62351-4"
            ],
            "description": "Data in transit and at rest must be encrypted to ensure confidentiality and integrity."
        },
        "port open": {
            "standards": [
                "NIS 2 Directive - Article 14",
                "IEC 62443-3-3 - SR 3.1",
                "ISO 27001 A.13.1.1",
                "NIST SP 800-41 Rev.1"
            ],
            "description": "Unnecessary network ports and services must be closed or restricted to authorized IP addresses only."
        },
        "public access": {
            "standards": [
                "NIS 2 Directive - Article 14",
                "ISO 27001 A.13.1.2",
                "NIST SP 800-53 AC-3",
                "IEC 62443-2-1"
            ],
            "description": "Access to systems, data, and resources must be restricted to authorized users only."
        },
        "outdated firmware": {
            "standards": [
                "NIS 2 Directive - Article 17",
                "IEC 62443-3-3 - SR 7.3",
                "ISO 27001 A.12.1.2",
                "NIST SP 800-40 Rev.4"
            ],
            "description": "Software and firmware must be kept up-to-date with security patches to address known vulnerabilities."
        },
        "secret exposed": {
            "standards": [
                "GDPR - Article 32",
                "NIS 2 Directive - Article 16",
                "ISO 27001 A.8.2.3",
                "NIST SP 800-53 SC-28"
            ],
            "description": "Credentials, API keys, and secrets must never be hardcoded or stored in publicly accessible locations."
        },
        "no authentication": {
            "standards": [
                "NIS 2 Directive - Article 16",
                "IEC 62443-3-3 - SR 2.1",
                "ISO 27001 A.9.1.1",
                "IEC 62351-8"
            ],
            "description": "All access to systems and devices must require strong authentication."
        }
    }

    def get_compliance_info(self, issue_description):
        """
        Match an issue description to relevant compliance rules
        Returns list of applicable standards and requirements
        """
        issue_lower = issue_description.lower()
        matched_rules = []

        # Check for keyword matches
        for keyword, rule_data in self.COMPLIANCE_RULES.items():
            if keyword in issue_lower:
                matched_rules.append(rule_data)

        # If no match found, return general guidance
        if not matched_rules:
            matched_rules.append({
                "standards": ["Industry Best Practice"],
                "description": "Follow standard security guidelines and organizational policies."
            })

        return matched_rules
  

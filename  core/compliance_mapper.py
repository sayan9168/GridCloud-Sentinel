class ComplianceMapper:
    RULES = {
        "open_port": {
            "standards": ["NIS 2", "IEC 62443-3-3", "NIST SP 800-41"],
            "description": "Access to network services must be restricted and controlled."
        },
        "weak_password": {
            "standards": ["ISO 27001 A.9.2.1", "NIS 2 Art. 16", "IEC 62351-8"],
            "description": "Authentication credentials must be strong and regularly changed."
        },
        "missing_encryption": {
            "standards": ["GDPR Art. 32", "NIS 2 Art. 15", "IEC 62351-4"],
            "description": "Data in transit and at rest must be encrypted."
        }
    }

    def get_applicable_rules(self, issue_description):
        """Match issue to compliance rules"""
        matched = []
        for keyword, rule in self.RULES.items():
            if keyword in issue_description.lower():
                matched.append(rule)
        return matched if matched else [{"standards": ["General Best Practice"], "description": "Follow industry security guidelines."}]
      

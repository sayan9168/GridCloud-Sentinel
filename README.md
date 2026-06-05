
# 🛡️ GridCloud Sentinel
**All-in-One Advanced Cybersecurity Platform**

*Securing Critical Infrastructure, Cloud Environments, and Detecting Hidden Threats — Defensive, Legal, and Enterprise-Grade*

---

## 📋 Overview
**GridCloud Sentinel** is a unified cybersecurity tool designed to address the growing security challenges in **smart energy grids (AMI)**, **cloud infrastructure**, and **hybrid IT environments**. Unlike separate tools for each domain, it combines **6 powerful features into one platform**, making it efficient, cost-effective, and highly valuable for organizations of all sizes.

Built entirely on **defensive principles**, it contains no offensive or hacking capabilities — fully compliant with international laws and standards.

---

## ✨ Key Features
### 🔌 1. AMI & Smart Grid Security Analyzer
Specialized protection for energy utilities and critical infrastructure:
- Discovers and identifies smart meters, concentrators, and field devices
- Deep inspection of industrial protocols: **DLMS/COSEM, IEC 62351, MQTT, CoAP, BACnet, IEC 60870**
- Detects weak/default credentials, missing encryption, firmware vulnerabilities, and tampering indicators
- Validates compliance with **IEC 62443, IEC 62351, and NIS 2 Directive**

### ☁️ 2. Cloud & Infrastructure Misconfiguration Auditor
Comprehensive security for modern cloud and on-premise systems:
- Supports **AWS, Azure, Google Cloud, and hybrid environments**
- Scans Amazon Machine Images (AMIs), Docker containers, VM templates, and servers
- Detects exposed secrets, overly permissive access, open ports, outdated software, and insecure defaults
- Compares configurations against **CIS Benchmarks, ISO 27001, and industry best practices**

### 🧠 3. AI-Powered Threat Hunting & Behavior Analytics
The intelligent core that finds what standard scanners miss:
- Automatically builds a **normal behavior baseline** for your environment
- Detects **unknown threats, anomalies, and suspicious patterns** (not just known signatures)
- Reduces false positives through continuous learning
- Visualizes potential attack paths and prioritizes risks

### 🔎 4. CVE & Vulnerability Lookup Engine
Real-time vulnerability intelligence:
- Automatically cross-references findings with the official **NVD (National Vulnerability Database)**
- Provides **CVE IDs, CVSS risk scores (0–10), severity levels, and detailed descriptions**
- Helps quantify the real impact of each issue

### 📜 5. Compliance Standard Mapper
Simplifies regulatory reporting:
- Automatically maps every security finding to major global standards:
  - 🇪🇺 **NIS 2 Directive** (EU)
  - 🔒 **ISO 27001 / ISO 27002**
  - 🛡️ **IEC 62443 / IEC 62351** (Industrial & Energy)
  - 🇺🇸 **NIST SP 800 Series**
  - 📄 **GDPR**
- Provides clear descriptions of requirements and obligations

### 🌐 6. Advanced Web Dashboard
Modern, user-friendly interface for easy management:
- One-click full security scan
- Interactive charts and risk summaries
- Detailed view of all findings, CVEs, and compliance status
- One-click PDF report generation and download
- Responsive design — works on desktop, tablet, and mobile

---

## ⚖️ Legal & Ethical Statement
**GridCloud Sentinel is built exclusively for defensive and authorized security purposes.**
- ❌ **No offensive capabilities**: It never attempts unauthorized access, exploitation, or disruption
- ✅ **Authorized use only**: Must be used only on systems you own or have **explicit written permission** to test
- ✅ **Transparent**: Fully open-source code allows verification of functionality
- ✅ **Compliant**: Adheres to global cybercrime laws, including the NIS Directive, GDPR, CFAA, and local regulations

---

## 🚀 Installation & Setup
### Prerequisites
- Python 3.8+
- Internet connection (for CVE lookups)
- Required permissions for network/cloud scanning

### Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/gridcloud-sentinel.git
cd gridcloud-sentinel
 
 
Step 2: Install Dependencies
 
bash
  
pip install -r requirements.txt
 
 
Step 3: Run the Tool
 
Choose between Command Line Interface or Web Dashboard:
 
bash
  
python main.py
 
 
- Select  1  for CLI mode
- Select  2  to start the Web Dashboard at  http://localhost:8000 
 
 
 
📂 Project Structure
 
plaintext
  
gridcloud-sentinel/
├── core/                      # Core engine and utilities
│   ├── logger.py              # Logging system
│   ├── cve_checker.py         # CVE lookup engine
│   └── compliance_mapper.py   # Compliance standard mapper
├── grid_security/             # Smart Grid/AMI security module
│   └── scanner.py
├── cloud_audit/               # Cloud & infrastructure auditor
│   └── auditor.py
├── ai_threat_hunter/          # AI anomaly detection
│   └── detector.py
├── reporting/                 # PDF report generation
│   └── generator.py
├── web_dashboard/             # Advanced web interface
│   ├── main.py
│   ├── templates/
│   └── static/
├── requirements.txt           # Dependencies
├── .gitignore                 # Ignore sensitive files
└── main.py                    # Main entry point
 
 
 
 
📊 Example Output
 
Summary Report
 
plaintext
  
✅ Smart Grid Scan: 3 devices found, 2 high-risk issues
✅ Cloud Audit: 5 resources scanned, 3 misconfigurations found
✅ AI Analysis: 1 potential hidden threat detected
📄 Full report saved: GridCloud_Sentinel_Report_20260605_074500.pdf
 
 
 
 
🎯 Why This Tool Stands Out
 
Most security tools focus on only one area — either grids, cloud, or threat detection. GridCloud Sentinel combines all critical domains into one platform, offering:
 
- Lower cost: Replaces multiple expensive commercial tools
- Simplified workflow: Single interface for all security needs
- Regulatory readiness: Built-in compliance reporting
- Future-proof: Modular design allows easy addition of new standards and protocols
 
 
 
🤝 Contributing
 
Contributions are welcome! If you want to improve the tool:
 
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request
 
 
 
📜 License
 
This project is licensed under the MIT License — free to use, modify, and distribute, provided that legal and ethical usage is maintained.
 
 
 
📧 Contact
 
For inquiries, collaborations, or support:
 
- Developer: [sayan/Handle]
- GitHub: [https://github.com/sayan9168]
- Email: [sm6881164@gmail.com]
 
 
 
"Protecting critical infrastructure and digital environments with intelligence and integrity."
 
plaintext
  

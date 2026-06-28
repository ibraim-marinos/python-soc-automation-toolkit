# Python SOC Automation Toolkit

A professional Python toolkit designed to automate common Security Operations Center (SOC) workflows.

This project demonstrates practical Python scripting skills applied to real-world cybersecurity workflows, including threat intelligence enrichment, Windows event log analysis, and alert automation.

The objective of this project is to demonstrate practical cybersecurity automation skills applicable to modern Security Operations Center (SOC) environments.

---

# Project Overview

The toolkit is structured as a modular collection of Python utilities that automate repetitive security operations workflows.

Rather than creating isolated scripts, each module is designed to be reusable, documented, and easy to extend.
# Planned Features

## IP Reputation Checker

Checks IP addresses against multiple Threat Intelligence platforms.

Current integrations:

- AbuseIPDB
- VirusTotal

Capabilities:

- Reputation lookup
- Abuse confidence score
- Malicious detection ratio
- JSON output
- Console summary

---

## Windows Failed Login Parser

Parses Windows Security Event Logs to identify failed authentication attempts.

Features include:

- Event ID 4625 detection
- Username extraction
- Source IP extraction
- Failed login counting
- Brute force identification

---

## Alert Enrichment Module

Enriches security alerts using multiple intelligence sources.

Future capabilities include:

- IOC enrichment
- Threat context collection
- Risk summary generation
- Automated report creation

---

# Project Structure

```
python-soc-automation-toolkit/

├── docs/
├── output/
├── reports/
├── sample_data/
├── screenshots/
├── scripts/
│   ├── ip_reputation_checker.py
│   ├── windows_failed_login_parser.py
│   └── alert_enrichment.py
│
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example
├── PROJECT_PROGRESS.md
└── LICENSE
```

---

# Technologies Used

- Python 3
- Requests
- Pandas
- Rich
- Python-dotenv
- Git
- GitHub
- Visual Studio Code

---

# Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/python-soc-automation-toolkit.git
```

Navigate into the project:

```bash
cd python-soc-automation-toolkit
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it.

Windows:

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create your environment variables:

```
.env
```

Example:

```
VIRUSTOTAL_API_KEY=YOUR_API_KEY
ABUSEIPDB_API_KEY=YOUR_API_KEY
```

---

# Current Development Status

This project is currently under active development.

Completed:

- Project structure
- Python environment
- Dependency management
- Documentation foundation

Upcoming:

- Threat Intelligence integration
- Windows Event Log parser
- Alert enrichment
- CLI interface
- Report generation

---

# Learning Objectives

This project focuses on developing practical skills in:

- Python scripting
- API integration
- Threat Intelligence
- Windows Event Logs
- Security automation
- Detection engineering fundamentals

---

# Future Improvements

Planned future enhancements include:

- URL reputation lookup
- Domain reputation lookup
- File hash enrichment
- CSV export
- HTML reports
- Interactive CLI menu
- Unit testing
- Docker support

---

# Disclaimer

This project was created for educational and portfolio purposes to demonstrate cybersecurity automation skills.

It is not intended for production environments without additional security review and testing.
# VulnScanner - Web Vulnerability Scanner

Automated web vulnerability scanner that checks for common web application security issues including OWASP Top 10 vulnerabilities.

## Features

- Directory/file enumeration
- Sensitive file detection
- SQL injection detection (error-based)
- XSS reflection testing
- Open redirect detection
- CORS misconfiguration testing
- Security header analysis
- robots.txt and sitemap.xml analysis
- Technology fingerprinting
- Backup file detection
- JSON/HTML report generation

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/vuln-scanner.git
cd vuln-scanner
pip3 install -r requirements.txt
chmod +x vulnscanner.py
```

## Usage

### Quick Scan
```bash
python3 vulnscanner.py quick https://example.com
```

### Full Scan
```bash
python3 vulnscanner.py full https://example.com
```

### Specific Checks
```bash
# Directory enumeration
python3 vulnscanner.py dirs https://example.com

# Sensitive file check
python3 vulnscanner.py files https://example.com

# SQL injection check
python3 vulnscanner.py sqli https://example.com/page?id=1

# XSS check
python3 vulnscanner.py xss https://example.com/search?q=test

# Open redirect check
python3 vulnscanner.py redirect https://example.com/login?next=http://evil.com

# CORS check
python3 vulnscanner.py cors https://example.com/api

# Security headers
python3 vulnscanner.py headers https://example.com
```

### Generate Report
```bash
python3 vulnscanner.py full https://example.com --report json --output scan.json
python3 vulnscanner.py full https://example.com --report html --output scan.html
```

## Vulnerabilities Detected

| Category | Checks |
|----------|--------|
| Injection | SQL error-based, XSS reflection, command injection hints |
| Broken Auth | Default credentials, weak auth headers |
| Sensitive Data | Backup files, config files, .env, .git |
| XXE | XML endpoint detection |
| Access Control | Open redirects, CORS misconfig |
| Security Misconfig | Missing headers, server info, directory listing |
| Known Vulns | Outdated software detection |

## Legal Disclaimer

This tool is for authorized security testing only. Do not scan websites without written permission from the owner.

## License

MIT License

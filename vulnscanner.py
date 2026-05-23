#!/usr/bin/env python3
"""
VulnScanner - Web Vulnerability Scanner
For authorized security testing only.
"""

import argparse
import sys
import re
import json
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"

SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD",
    ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml", "crossdomain.xml",
    "wp-config.php.bak", "wp-config.php~", "config.php.bak", "config.inc.php",
    "web.config", "config.yml", "config.json", "settings.py", "database.yml",
    "backup.sql", "dump.sql", "db.sql", "database.sql", "admin/", "phpmyadmin/",
    "server-status", "server-info", ".DS_Store", "Thumbs.db", ".svn/entries",
    "composer.json", "package.json", "Gemfile", "requirements.txt",
    "debug", "trace", "test", "info.php", "phpinfo.php",
]

DIR_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "panel",
    "dashboard", "api", "v1", "v2", "graphql", "swagger", "docs", "backup",
    "bak", "test", "debug", "console", "shell", "cmd", "exec", "uploads",
    "upload", "files", "static", "assets", "images", "img", "css", "js",
    "scripts", "fonts", "media", "tmp", "temp", "cache", "log", "logs",
    "private", "secret", "hidden", "old", "new", "beta", "staging", "dev",
    "development", "production", "sandbox", "internal", "intranet", "portal",
    "cgi-bin", "bin", "scripts", "includes", "lib", "vendor", "node_modules",
    "install", "setup", "config", "conf", "settings", "manage", "manager",
    "system", "monitor", "health", "status", "metrics", "stats", "analytics",
    "search", "query", "db", "database", "sql", "mysql", "postgres", "redis",
    "phpmyadmin", "adminer", "pgadmin", "mongo-express",
]

SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "sqlite3", "postgresql", "ORA-", "SQL Server",
    "Microsoft OLE DB", "ODBC SQL Server", "unclosed quotation mark",
    "syntax error", "mysql_num_rows", "pg_query", "mysqli_", "PDOException",
    "SQLSTATE", "Warning: mysql", "MySqlException", "valid MySQL result",
    "supplied argument is not a valid MySQL", "Column count doesn't match",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<img src=x onerror=alert("XSS")>',
    'javascript:alert("XSS")',
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%00.{}".format("target.com"),
    "javascript:alert(1)",
]


class VulnScanner:
    def __init__(self, target, timeout=10, threads=10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnScanner/1.0 (Security Audit)",
        })
        self.findings = []

    def _get(self, url, **kwargs):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False, **kwargs)
        except:
            return None

    def _post(self, url, **kwargs):
        try:
            return self.session.post(url, timeout=self.timeout, allow_redirects=False, **kwargs)
        except:
            return None

    def add_finding(self, severity, category, title, detail="", url="", evidence=""):
        self.findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "url": url,
            "evidence": evidence[:200],
            "timestamp": datetime.now().isoformat(),
        })

    def check_headers(self):
        """Check security headers."""
        print(f"\n{Fore.CYAN}[*] Checking security headers...{Style.RESET_ALL}")
        resp = self._get(self.target)
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        required = {
            "strict-transport-security": ("HIGH", "Missing HSTS header"),
            "content-security-policy": ("HIGH", "Missing Content-Security-Policy"),
            "x-frame-options": ("MEDIUM", "Missing X-Frame-Options"),
            "x-content-type-options": ("MEDIUM", "Missing X-Content-Type-Options"),
        }

        for header, (severity, title) in required.items():
            if header not in headers:
                self.add_finding(severity, "Security Headers", title,
                               url=self.target)
                print(f"  {Fore.YELLOW}[!] {title}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}[+] {header}: {headers[header][:50]}{Style.RESET_ALL}")

        # Info leakage
        leak_headers = ["server", "x-powered-by", "x-aspnet-version"]
        for h in leak_headers:
            if h in headers:
                self.add_finding("LOW", "Information Leakage",
                               f"Server info header: {h}", detail=headers[h], url=self.target)
                print(f"  {Fore.YELLOW}[!] Info leak - {h}: {headers[h]}{Style.RESET_ALL}")

    def check_sensitive_files(self):
        """Check for sensitive files."""
        print(f"\n{Fore.CYAN}[*] Checking for sensitive files...{Style.RESET_ALL}")

        for path in SENSITIVE_FILES:
            url = f"{self.target}/{path}"
            resp = self._get(url)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                # Verify it's not a generic error page
                if "404" not in resp.text[:100].lower():
                    self.add_finding("HIGH", "Sensitive Files",
                                   f"Accessible: {path}", url=url)
                    print(f"  {Fore.RED}[!] Found: {path} ({resp.status_code}, {len(resp.text)} bytes){Style.RESET_ALL}")

    def enumerate_directories(self):
        """Enumerate directories."""
        print(f"\n{Fore.CYAN}[*] Enumerating directories...{Style.RESET_ALL}")

        found = []
        for path in DIR_WORDLIST:
            url = f"{self.target}/{path}/"
            resp = self._get(url)
            if resp and resp.status_code in (200, 301, 302, 403):
                status = resp.status_code
                color = Fore.GREEN if status == 200 else Fore.YELLOW if status in (301, 302) else Fore.CYAN
                label = {200: "OPEN", 301: "REDIRECT", 302: "REDIRECT", 403: "FORBIDDEN"}[status]
                found.append({"path": path, "status": status})
                print(f"  {color}[{label}] /{path}/{Style.RESET_ALL} ({status})")

                if status == 200 and "Index of" in resp.text:
                    self.add_finding("MEDIUM", "Directory Listing",
                                   f"Directory listing enabled: /{path}/", url=url)

        return found

    def check_sqli(self, url=None):
        """Check for SQL injection via error-based detection."""
        target = url or self.target
        print(f"\n{Fore.CYAN}[*] Checking for SQL injection...{Style.RESET_ALL}")

        # Add SQL payloads to URL parameters
        parsed = urlparse(target)
        params = parse_qs(parsed.query)

        if not params:
            # Try common parameter names
            test_params = ["id", "page", "user", "search", "q", "cat", "item"]
            for param in test_params:
                params[param] = ["1"]

        sqli_payloads = ["'", "1' OR '1'='1", "1 AND 1=1", "1 UNION SELECT NULL--", "'; WAITFOR DELAY '0:0:5'--"]

        for param_name in params:
            for payload in sqli_payloads:
                test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                resp = self._get(test_url)
                if resp:
                    for error in SQL_ERRORS:
                        if error.lower() in resp.text.lower():
                            self.add_finding("CRITICAL", "SQL Injection",
                                           f"Possible SQLi in parameter: {param_name}",
                                           detail=f"Payload: {payload}", url=test_url,
                                           evidence=error)
                            print(f"  {Fore.RED}[!] SQLi possible: {param_name} (payload: {payload[:20]}){Style.RESET_ALL}")
                            return True
        print(f"  {Fore.GREEN}[+] No SQL injection detected{Style.RESET_ALL}")
        return False

    def check_xss(self, url=None):
        """Check for reflected XSS."""
        target = url or self.target
        print(f"\n{Fore.CYAN}[*] Checking for XSS reflection...{Style.RESET_ALL}")

        parsed = urlparse(target)
        params = parse_qs(parsed.query)

        if not params:
            params = {"q": ["test"], "search": ["test"], "input": ["test"]}

        for param_name in params:
            for payload in XSS_PAYLOADS:
                test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                resp = self._get(test_url)
                if resp and payload in resp.text:
                    self.add_finding("HIGH", "XSS",
                                   f"Reflected XSS in parameter: {param_name}",
                                   detail=f"Payload reflected in response", url=test_url)
                    print(f"  {Fore.RED}[!] XSS reflected: {param_name}{Style.RESET_ALL}")
                    return True

        print(f"  {Fore.GREEN}[+] No XSS reflection detected{Style.RESET_ALL}")
        return False

    def check_open_redirect(self, url=None):
        """Check for open redirect vulnerabilities."""
        target = url or self.target
        print(f"\n{Fore.CYAN}[*] Checking for open redirects...{Style.RESET_ALL}")

        parsed = urlparse(target)
        params = parse_qs(parsed.query)

        redirect_params = ["next", "url", "redirect", "return", "goto", "continue",
                           "dest", "destination", "redir", "redirect_uri", "return_to"]

        if not params:
            params = {p: [""] for p in redirect_params[:3]}

        for param_name in params:
            if param_name.lower() not in redirect_params:
                continue

            for payload in REDIRECT_PAYLOADS:
                test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                resp = self._get(test_url)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location or payload in location:
                        self.add_finding("HIGH", "Open Redirect",
                                       f"Open redirect in parameter: {param_name}",
                                       detail=f"Redirects to: {location}", url=test_url)
                        print(f"  {Fore.RED}[!] Open redirect: {param_name} => {location}{Style.RESET_ALL}")
                        return True

        print(f"  {Fore.GREEN}[+] No open redirects detected{Style.RESET_ALL}")
        return False

    def check_cors(self):
        """Check CORS configuration."""
        print(f"\n{Fore.CYAN}[*] Checking CORS configuration...{Style.RESET_ALL}")

        origins = ["https://evil.com", "null"]
        for origin in origins:
            resp = self._get(self.target, headers={"Origin": origin})
            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*":
                    self.add_finding("HIGH", "CORS", "Wildcard CORS policy",
                                   url=self.target)
                    print(f"  {Fore.RED}[!] CORS allows all origins (*){Style.RESET_ALL}")
                    return True
                elif acao == origin:
                    self.add_finding("HIGH", "CORS", f"CORS reflects origin: {origin}",
                                   url=self.target)
                    print(f"  {Fore.RED}[!] CORS reflects origin: {origin}{Style.RESET_ALL}")
                    return True

        print(f"  {Fore.GREEN}[+] CORS configuration looks OK{Style.RESET_ALL}")
        return False

    def check_robots(self):
        """Analyze robots.txt."""
        print(f"\n{Fore.CYAN}[*] Analyzing robots.txt...{Style.RESET_ALL}")

        resp = self._get(f"{self.target}/robots.txt")
        if resp and resp.status_code == 200 and "disallow" in resp.text.lower():
            disallowed = re.findall(r'disallow:\s*(.+)', resp.text, re.IGNORECASE)
            print(f"  {Fore.WHITE}Disallowed paths:{Style.RESET_ALL}")
            for path in disallowed:
                path = path.strip()
                if path:
                    print(f"    {path}")
                    # Check if disallowed paths are actually accessible
                    check_url = f"{self.target}{path}"
                    check_resp = self._get(check_url)
                    if check_resp and check_resp.status_code == 200:
                        self.add_finding("MEDIUM", "Robots.txt",
                                       f"Disallowed path accessible: {path}", url=check_url)
                        print(f"    {Fore.YELLOW}[!] Accessible!{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[+] No robots.txt or empty{Style.RESET_ALL}")

    def fingerprint(self):
        """Fingerprint web technology."""
        print(f"\n{Fore.CYAN}[*] Technology fingerprinting...{Style.RESET_ALL}")

        resp = self._get(self.target)
        if not resp:
            return

        techs = []
        body = resp.text[:5000].lower()
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

        # Server header
        server = headers.get("server", "")
        if server:
            techs.append(f"Server: {server}")

        # X-Powered-By
        powered = headers.get("x-powered-by", "")
        if powered:
            techs.append(f"Powered by: {powered}")

        # CMS detection
        cms_patterns = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "sites/default"],
            "Joomla": ["joomla", "com_content"],
            "Laravel": ["laravel", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Express": ["express", "x-powered-by: express"],
            "Next.js": ["__next", "_next/static"],
            "React": ["react", "_reactroot"],
            "Angular": ["ng-version", "angular"],
            "Vue.js": ["vue", "data-v-"],
            "Bootstrap": ["bootstrap"],
            "jQuery": ["jquery"],
        }

        for tech, patterns in cms_patterns.items():
            if any(p in body for p in patterns):
                techs.append(tech)

        for t in techs:
            print(f"  {Fore.GREEN}[+] {t}{Style.RESET_ALL}")

        return techs

    def print_summary(self):
        """Print scan summary."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  VULNERABILITY SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"  Target: {self.target}")
        print(f"  Findings: {len(self.findings)}")

        severities = {}
        for f in self.findings:
            severities[f["severity"]] = severities.get(f["severity"], 0) + 1

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severities.get(sev, 0)
            if count:
                color = {"CRITICAL": Fore.RED, "HIGH": Fore.RED,
                         "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN, "INFO": Fore.WHITE}[sev]
                print(f"  {color}{sev}: {count}{Style.RESET_ALL}")

        if self.findings:
            print(f"\n{Fore.WHITE}  Detailed Findings:{Style.RESET_ALL}")
            for f in self.findings:
                color = {"CRITICAL": Fore.RED, "HIGH": Fore.RED,
                         "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN}[f["severity"]]
                print(f"\n  {color}[{f['severity']}] {f['title']}{Style.RESET_ALL}")
                print(f"    Category: {f['category']}")
                if f["url"]:
                    print(f"    URL: {f['url']}")
                if f["detail"]:
                    print(f"    Detail: {f['detail']}")

    def export_json(self, filename):
        report = {
            "tool": "VulnScanner",
            "version": VERSION,
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings,
        }
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")

    def export_html(self, filename):
        sev_colors = {"CRITICAL": "#ff0000", "HIGH": "#ff4444", "MEDIUM": "#ffaa00", "LOW": "#00aaff"}
        rows = ""
        for f in self.findings:
            color = sev_colors.get(f["severity"], "#fff")
            rows += (f'<tr><td style="color:{color}">{f["severity"]}</td>'
                    f'<td>{f["category"]}</td><td>{f["title"]}</td>'
                    f'<td>{f.get("url","")[:60]}</td></tr>\n')

        html = f"""<!DOCTYPE html>
<html><head><title>VulnScanner Report</title>
<style>
body {{ font-family: monospace; background: #1a1a1a; color: #e0e0e0; padding: 20px; }}
h1 {{ color: #ff4444; }} table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
th {{ background: #333; color: #00ffff; }}
</style></head><body>
<h1>VulnScanner Report</h1>
<p>Target: {self.target}</p>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Findings: {len(self.findings)}</p>
<table><tr><th>Severity</th><th>Category</th><th>Title</th><th>URL</th></tr>
{rows}</table></body></html>"""
        with open(filename, 'w') as f:
            f.write(html)
        print(f"\n{Fore.GREEN}[+] HTML report saved to {filename}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnScanner - Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s quick https://example.com
  %(prog)s full https://example.com
  %(prog)s sqli https://example.com/page?id=1
  %(prog)s xss https://example.com/search?q=test
  %(prog)s dirs https://example.com
  %(prog)s full https://example.com --report json --output scan.json
        """
    )

    sub = parser.add_subparsers(dest="command")

    for name, desc in [("quick", "Quick scan (headers, files, robots)"),
                        ("full", "Full vulnerability scan"),
                        ("dirs", "Directory enumeration"),
                        ("files", "Sensitive file check"),
                        ("sqli", "SQL injection check"),
                        ("xss", "XSS reflection check"),
                        ("redirect", "Open redirect check"),
                        ("cors", "CORS misconfiguration check"),
                        ("headers", "Security header check")]:
        p = sub.add_parser(name, help=desc)
        p.add_argument("url", help="Target URL")
        if name == "full":
            p.add_argument("--report", choices=["json", "html"], help="Report format")
            p.add_argument("--output", help="Output filename")

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════╗")
    print(f"║    VulnScanner v{VERSION}           ║")
    print(f"╚══════════════════════════════════╝{Style.RESET_ALL}")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if not HAS_REQUESTS:
        print(f"{Fore.RED}[!] requests library required. Install: pip3 install requests{Style.RESET_ALL}")
        sys.exit(1)

    scanner = VulnScanner(args.url)

    if args.command in ("quick", "full"):
        scanner.fingerprint()
        scanner.check_headers()
        scanner.check_robots()
        scanner.check_sensitive_files()

        if args.command == "full":
            scanner.enumerate_directories()
            scanner.check_sqli()
            scanner.check_xss()
            scanner.check_open_redirect()
            scanner.check_cors()

        scanner.print_summary()

        if args.command == "full" and hasattr(args, 'report') and args.report:
            if args.report == "json":
                scanner.export_json(args.output or "vuln_report.json")
            elif args.report == "html":
                scanner.export_html(args.output or "vuln_report.html")

    elif args.command == "dirs":
        scanner.enumerate_directories()
    elif args.command == "files":
        scanner.check_sensitive_files()
    elif args.command == "sqli":
        scanner.check_sqli()
    elif args.command == "xss":
        scanner.check_xss()
    elif args.command == "redirect":
        scanner.check_open_redirect()
    elif args.command == "cors":
        scanner.check_cors()
    elif args.command == "headers":
        scanner.check_headers()


if __name__ == "__main__":
    main()

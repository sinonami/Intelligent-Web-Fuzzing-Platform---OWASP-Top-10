# fuzzer/recon.py
import requests
from urllib.parse import urljoin

def run_recon(url):
    print(f"--- Passive Recon Started: {url} ---")
    results = []

    headers = {'User-Agent': 'Mozilla/5.0 Intelligent-NLP-Fuzzer'}
    base_url = url if url.endswith('/') else url + '/'

    # ── 1. Sensitive file exposure (A01/A05) ─────────────────────────────
    sensitive_files = [
        ".env", ".env.local", ".env.production",
        ".git/config", ".git/HEAD",
        "robots.txt", "sitemap.xml",
        "phpinfo.php", "info.php",
        "config.php", "config.php.bak", "config.yml", "config.yaml",
        ".htaccess", "web.config",
        "admin/", "admin/login", "admin/index.php",
        "backup.zip", "backup.tar.gz", "backup.sql",
        "setup.php", "install.php", "install/",
        "api/", "api/v1/", "api/v2/",
        "swagger.json", "openapi.json", "api-docs",
        "wp-login.php", "wp-config.php",
        "server-status", "server-info",
        "actuator", "actuator/env", "actuator/health",
        "debug", "console", "trace",
        "crossdomain.xml", "clientaccesspolicy.xml",
    ]

    for file in sensitive_files:
        target = urljoin(base_url, file)
        try:
            res = requests.get(target, timeout=8, allow_redirects=False, headers=headers)

            # 200 = exposed, 403 = exists but forbidden (still a finding), 301/302 = redirect worth noting
            if res.status_code == 200 and len(res.text) > 10:
                severity = "CRITICAL" if any(k in file for k in [".env", "config", "backup", "sql", "wp-config"]) else "HIGH"
                results.append({
                    "type": "CORS_MISCONFIGURATION",
                    "payload": file,
                    "method": "GET",
                    "status_code": 200,
                    "severity": severity,
                    "details": f"[A05:2021] Sensitive file publicly exposed at: {target}"
                })

            elif res.status_code == 403:
                results.append({
                    "type": "CORS_MISCONFIGURATION",
                    "payload": file,
                    "method": "GET",
                    "status_code": 403,
                    "severity": "MEDIUM",
                    "details": f"[A01:2021] Resource exists but access forbidden (path enumeration confirmed): {target}"
                })

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            continue

    # ── 2. HTTP security headers audit (A05/A09) ─────────────────────────
    try:
        res = requests.get(url, timeout=8, headers=headers, allow_redirects=True)

        security_headers = {
            "Strict-Transport-Security": "HSTS missing — allows protocol downgrade attacks",
            "Content-Security-Policy": "CSP missing — XSS mitigation not enforced",
            "X-Frame-Options": "Clickjacking protection missing",
            "X-Content-Type-Options": "MIME sniffing protection missing",
            "Referrer-Policy": "Referrer leakage possible",
            "Permissions-Policy": "Browser feature policy not set",
        }

        missing = []
        for header, reason in security_headers.items():
            if header not in res.headers:
                missing.append(f"{header} ({reason})")

        if missing:
            results.append({
                "type": "INSUFFICIENT_LOGGING",
                "payload": "Missing security headers: " + ", ".join(h.split(" ")[0] for h in missing),
                "method": "GET",
                "status_code": res.status_code,
                "severity": "MEDIUM",
                "details": f"[A05/A09:2021] Security headers absent: {'; '.join(missing)}"
            })

        # ── 3. Server banner / version disclosure (A06) ──────────────────
        server = res.headers.get("Server", "")
        x_powered = res.headers.get("X-Powered-By", "")

        if server and any(c.isdigit() for c in server):
            results.append({
                "type": "OUTDATED_COMPONENTS",
                "payload": f"Server: {server}",
                "method": "GET",
                "status_code": res.status_code,
                "severity": "MEDIUM",
                "details": f"[A06:2021] Server version fingerprinted via banner: {server}"
            })

        if x_powered:
            results.append({
                "type": "OUTDATED_COMPONENTS",
                "payload": f"X-Powered-By: {x_powered}",
                "method": "GET",
                "status_code": res.status_code,
                "severity": "MEDIUM",
                "details": f"[A06:2021] Technology stack disclosed via X-Powered-By header: {x_powered}"
            })

        # ── 4. Cookie security flags (A07/A08) ───────────────────────────
        for cookie in res.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if "httponly" not in str(cookie._rest).lower() and not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if cookie.domain and cookie.domain.startswith("."):
                issues.append("wildcard domain scope")

            if issues:
                results.append({
                    "type": "AUTH_INDICATORS_MISSING",
                    "payload": f"Cookie: {cookie.name}",
                    "method": "GET",
                    "status_code": res.status_code,
                    "severity": "MEDIUM",
                    "details": f"[A07:2021] Session cookie '{cookie.name}' has security issues: {', '.join(issues)}"
                })

        # ── 5. CORS misconfiguration (A05) ───────────────────────────────
        cors = res.headers.get("Access-Control-Allow-Origin", "")
        if cors == "*":
            results.append({
                "type": "CORS_MISCONFIGURATION",
                "payload": "Access-Control-Allow-Origin: *",
                "method": "GET",
                "status_code": res.status_code,
                "severity": "MEDIUM",
                "details": "[A05:2021] Wildcard CORS policy allows any origin to read responses — credential theft risk."
            })

    except Exception as e:
        print(f"[recon] Header audit error: {e}")

    # ── 6. Common admin/hidden paths (A01) ───────────────────────────────
    admin_paths = [
        "admin", "admin/login", "administrator", "admin.php",
        "login", "signin", "auth", "dashboard",
        "phpmyadmin", "pma", "db",
        "api/v1/users", "api/v1/admin", "api/users",
        "config", "backup", "uploads", "files",
        "shell", "cmd", "exec",
        "wp-admin", "wp-login.php",
        "manager/html",  # Tomcat
        "solr", "jenkins", "kibana",
    ]

    for path in admin_paths:
        target = urljoin(base_url, path)
        try:
            res = requests.get(target, timeout=6, allow_redirects=False, headers=headers)
            if res.status_code in [200, 401, 403]:
                severity = "HIGH" if res.status_code == 200 else "MEDIUM"
                results.append({
                    "type": "CORS_MISCONFIGURATION",
                    "payload": f"/{path}",
                    "method": "GET",
                    "status_code": res.status_code,
                    "severity": severity,
                    "details": f"[A01:2021] Hidden endpoint discovered (HTTP {res.status_code}): {target}"
                })
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            continue

    print(f"[recon] Found {len(results)} issues.")
    return results
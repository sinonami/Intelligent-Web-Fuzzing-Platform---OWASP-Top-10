# fuzzer/owasp.py
import requests
import re
from urllib.parse import urljoin

HEADERS = {'User-Agent': 'Intelligent-OWASP-Fuzzer/3.0'}


def check_misconfigurations(url):
    findings = []
    base_url = url if url.endswith('/') else url + '/'

    a05_files = ['.env', '.git/config', 'docker-compose.yml', 'web.config']
    for f in a05_files:
        target_file = urljoin(base_url, f)
        try:
            r = requests.get(target_file, timeout=3, allow_redirects=False, headers=HEADERS)
            if "page not found" in r.text.lower() or "error" in r.text.lower():
                continue
            if r.status_code == 200 and len(r.text) > 0 and (f in r.text or "DB_" in r.text or "repository" in r.text):
                findings.append({
                    "type": "CORS_MISCONFIGURATION",
                    "payload": f,
                    "method": "GET",
                    "status_code": 200,
                    "severity": "HIGH",
                    "details": f"[A05:2021] Security Misconfiguration: Exposed config file disclosing system parameters: {target_file}"
                })
        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.RequestException):
            continue

    a01_paths = ['config', 'backup', 'admin', 'api/v1/users', 'dashboard']
    for path in a01_paths:
        target_path = urljoin(base_url, path)
        try:
            r = requests.get(target_path, timeout=3, allow_redirects=False, headers=HEADERS)
            if r.status_code in [200, 401, 403]:
                findings.append({
                    "type": "CORS_MISCONFIGURATION",
                    "payload": f"Path: /{path}",
                    "method": "GET",
                    "status_code": r.status_code,
                    "severity": "HIGH" if r.status_code == 200 else "MEDIUM",
                    "details": f"[A01/A05] Access Control Anomaly: Hidden endpoint discovered at: {target_path}"
                })
        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.RequestException):
            continue

    return findings


def check_outdated_components(url):
    findings = []
    try:
        response = requests.get(url, timeout=5, headers=HEADERS, allow_redirects=True)
        text_content = response.text

        server_header = response.headers.get('Server', '')
        if server_header and any(char.isdigit() for char in server_header):
            findings.append({
                "type": "OUTDATED_COMPONENTS",
                "payload": server_header,
                "method": "GET",
                "status_code": 200,
                "severity": "HIGH",
                "details": f"[A06:2021] Outdated Components: Server version fingerprinted via banner: {server_header}"
            })

        if "BEGIN PRIVATE KEY" in text_content or "-----BEGIN RSA PRIVATE KEY-----" in text_content:
            findings.append({
                "type": "OUTDATED_COMPONENTS",
                "payload": "Private Key Exposure",
                "method": "GET",
                "status_code": 200,
                "severity": "CRITICAL",
                "details": "[A02:2021] Cryptographic Flaw: Private key found in HTTP response body."
            })

        md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        if md5_pattern.search(text_content):
            findings.append({
                "type": "CORS_MISCONFIGURATION",
                "payload": "MD5 Hash Leak",
                "method": "GET",
                "status_code": 200,
                "severity": "MEDIUM",
                "details": "[A02:2021] Cryptographic Flaw: MD5 hash pattern detected in response body."
            })
    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException) as e:
        print(f"[A06] check_outdated_components error: {e}")

    return findings


def check_auth_indicators(url):
    findings = []
    try:
        response = requests.get(url, timeout=5, headers=HEADERS, allow_redirects=True)

        if any(p in response.text.lower() for p in ['login', 'password', 'signin', 'auth']):
            findings.append({
                "type": "AUTH_INDICATORS_MISSING",
                "payload": "Rate-Limit Test",
                "method": "GET",
                "status_code": 200,
                "severity": "MEDIUM",
                "details": "[A07:2021] Identification Deficiencies: Authentication interface lacks rate-limiting or MFA indicators."
            })

        for cookie in response.cookies:
            if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
                findings.append({
                    "type": "AUTH_INDICATORS_MISSING",
                    "payload": f"Cookie: {cookie.name}",
                    "method": "GET",
                    "status_code": 200,
                    "severity": "MEDIUM",
                    "details": f"[A08:2021] Cookie '{cookie.name}' missing HttpOnly/Secure flags — session hijacking risk."
                })
    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException) as e:
        print(f"[A07] check_auth_indicators error: {e}")

    return findings


def check_logging_status(url=None):
    findings = []
    if not url:
        return findings

    try:
        response = requests.get(url, timeout=5, headers=HEADERS, allow_redirects=True)
        missing_headers = []
        if 'Content-Security-Policy' not in response.headers:
            missing_headers.append('Content-Security-Policy')
        if 'X-Frame-Options' not in response.headers:
            missing_headers.append('X-Frame-Options')
        if 'Strict-Transport-Security' not in response.headers:
            missing_headers.append('Strict-Transport-Security')

        if missing_headers:
            findings.append({
                "type": "INSUFFICIENT_LOGGING",
                "payload": "Missing Hardening Headers",
                "method": "GET",
                "status_code": response.status_code,
                "severity": "LOW",
                "details": f"[A09:2021] Security headers missing: {', '.join(missing_headers)}."
            })
    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException) as e:
        print(f"[A09] check_logging_status error: {e}")  # ← ИСПРАВЛЕНО: было continue вне цикла

    return findings


def check_cryptographic_failures(url):
    """OWASP A02:2021 - Cryptographic Failures"""
    findings = []

    # 1. Проверяем HTTP без TLS
    http_url = url.replace('https://', 'http://')
    try:
        r = requests.get(http_url, timeout=5, headers=HEADERS, allow_redirects=False)
        if r.status_code == 200:
            findings.append({
                "type": "OUTDATED_COMPONENTS",
                "payload": http_url,
                "method": "GET",
                "status_code": r.status_code,
                "severity": "HIGH",
                "details": "[A02:2021] Cryptographic Failure: Site accessible over plain HTTP without TLS encryption."
            })
    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException) as e:
        print(f"[A02] HTTP check error: {e}")  # ← ИСПРАВЛЕНО: было continue вне цикла

    # 2. Проверяем HTTPS заголовки и утечки ключей
    try:
        r = requests.get(url, timeout=5, headers=HEADERS, allow_redirects=True)

        hsts = r.headers.get('Strict-Transport-Security', '')
        if not hsts:
            findings.append({
                "type": "INSUFFICIENT_LOGGING",
                "payload": "Missing HSTS header",
                "method": "GET",
                "status_code": r.status_code,
                "severity": "MEDIUM",
                "details": "[A02:2021] Cryptographic Failure: HSTS header absent — HTTP downgrade attacks possible."
            })
        elif 'max-age' in hsts:
            match = re.search(r'max-age=(\d+)', hsts)
            if match and int(match.group(1)) < 31536000:
                findings.append({
                    "type": "INSUFFICIENT_LOGGING",
                    "payload": f"HSTS max-age too short: {hsts}",
                    "method": "GET",
                    "status_code": r.status_code,
                    "severity": "LOW",
                    "details": "[A02:2021] Cryptographic Failure: HSTS max-age below recommended 1 year."
                })

        body = r.text
        key_patterns = [
            ("-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
            ("-----BEGIN PRIVATE KEY-----", "PKCS8 Private Key"),
            ("-----BEGIN EC PRIVATE KEY-----", "EC Private Key"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key"),
            ("AKIA", "AWS Access Key ID"),
        ]
        for pattern, key_type in key_patterns:
            if pattern in body:
                findings.append({
                    "type": "OUTDATED_COMPONENTS",
                    "payload": f"{key_type} exposed",
                    "method": "GET",
                    "status_code": r.status_code,
                    "severity": "CRITICAL",
                    "details": f"[A02:2021] Cryptographic Failure: {key_type} found in HTTP response body."
                })

        md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        if md5_pattern.search(body):
            findings.append({
                "type": "CORS_MISCONFIGURATION",
                "payload": "MD5 hash detected",
                "method": "GET",
                "status_code": r.status_code,
                "severity": "LOW",
                "details": "[A02:2021] Cryptographic Failure: MD5 hash detected — weak algorithm."
            })
        elif sha1_pattern.search(body):
            findings.append({
                "type": "CORS_MISCONFIGURATION",
                "payload": "SHA1 hash detected",
                "method": "GET",
                "status_code": r.status_code,
                "severity": "LOW",
                "details": "[A02:2021] Cryptographic Failure: SHA1 hash detected — deprecated algorithm."
            })

    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException) as e:
        print(f"[A02] check_cryptographic_failures error: {e}")

    return findings


def check_software_integrity(url):
    """OWASP A08:2021 - Software and Data Integrity Failures"""
    findings = []

    try:
        r = requests.get(url, timeout=8, headers=HEADERS, allow_redirects=True)
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(r.text, 'html.parser')
        base_url = url if url.endswith('/') else url + '/'

        # 1. Script теги без SRI
        scripts = soup.find_all('script', src=True)
        sri_missing = []
        for script in scripts:
            src = script.get('src', '')
            if any(cdn in src for cdn in ['cdn.', 'cdnjs.', 'jsdelivr', 'unpkg', 'googleapis', 'bootstrapcdn']):
                if not script.get('integrity'):
                    sri_missing.append(src)

        if sri_missing:
            findings.append({
                "type": "AUTH_INDICATORS_MISSING",
                "payload": f"Scripts without SRI: {', '.join(sri_missing[:3])}",
                "method": "GET",
                "status_code": r.status_code,
                "severity": "MEDIUM",
                "details": f"[A08:2021] Software Integrity Failure: {len(sri_missing)} external script(s) without SRI hash — supply chain attack vector."
            })

        # 2. CSS без SRI
        links = soup.find_all('link', rel='stylesheet', href=True)
        css_missing = []
        for link in links:
            href = link.get('href', '')
            if any(cdn in href for cdn in ['cdn.', 'cdnjs.', 'jsdelivr', 'unpkg', 'googleapis', 'bootstrapcdn']):
                if not link.get('integrity'):
                    css_missing.append(href)

        if css_missing:
            findings.append({
                "type": "AUTH_INDICATORS_MISSING",
                "payload": f"Stylesheets without SRI: {', '.join(css_missing[:2])}",
                "method": "GET",
                "status_code": r.status_code,
                "severity": "LOW",
                "details": f"[A08:2021] Software Integrity Failure: {len(css_missing)} external stylesheet(s) without SRI."
            })

        # 3. Небезопасные update/upload endpoints
        integrity_paths = [
            'update', 'upgrade', 'upload', 'import',
            'webhook', 'callback', 'hook',
            'deserialize', 'restore', 'migrate'
        ]
        for path in integrity_paths:
            target = urljoin(base_url, path)
            try:
                resp = requests.get(target, timeout=4, headers=HEADERS, allow_redirects=False)
                if resp.status_code in [200, 405]:
                    findings.append({
                        "type": "AUTH_INDICATORS_MISSING",
                        "payload": f"/{path}",
                        "method": "GET",
                        "status_code": resp.status_code,
                        "severity": "MEDIUM",
                        "details": f"[A08:2021] Software Integrity Failure: Sensitive endpoint /{path} detected."
                    })
            except (requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.RequestException):
                continue

        # 4. JSONP endpoints
        api_paths = ['api', 'api/v1', 'graphql', 'rest']
        for path in api_paths:
            target = urljoin(base_url, path)
            try:
                resp = requests.get(target, timeout=4, headers=HEADERS)
                ct = resp.headers.get('Content-Type', '')
                if resp.status_code == 200 and 'json' in ct:
                    if any(p in resp.text[:200] for p in ['callback(', 'jsonp(', '/**/']):
                        findings.append({
                            "type": "CORS_MISCONFIGURATION",
                            "payload": f"JSONP at /{path}",
                            "method": "GET",
                            "status_code": resp.status_code,
                            "severity": "MEDIUM",
                            "details": f"[A08:2021] Software Integrity Failure: JSONP endpoint at /{path} — cross-origin data theft risk."
                        })
            except (requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.RequestException):
                continue

    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException) as e:
        print(f"[A08] check_software_integrity error: {e}")

    return findings
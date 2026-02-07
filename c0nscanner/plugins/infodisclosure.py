"""information disclosure scanner plugin for c0nscanner.

detects version leaks, stack traces, error messages, and other info leakage.
"""

from __future__ import annotations

import re

from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding


# ── helpers ──────────────────────────────────────────────────────────

SCRIPT_TAG_RE = re.compile(r'<script\b[^>]*>[\s\S]*?</script>', re.IGNORECASE)
HTML_COMMENT_RE = re.compile(r'<!--([\s\S]*?)-->')
JS_BLOCK_COMMENT_RE = re.compile(r'/\*([\s\S]*?)\*/')


def _strip_scripts_and_comments(html: str) -> str:
    """remove <script> blocks and html comments to avoid false positives
    from js bundles, polyfills, and build tool attributions."""
    text = SCRIPT_TAG_RE.sub('', html)
    text = HTML_COMMENT_RE.sub('', text)
    return text


# ── version patterns: HEADER-only ───────────────────────────────────
# checked against response headers (Server, X-Powered-By, etc.)
# framework names WITHOUT version numbers are valid here because
# headers like "X-Powered-By: Express" are legitimate disclosures.

HEADER_VERSION_PATTERNS = [
    (r"Apache/(\d+\.\d+[\.\d]*)", "apache web server", "low"),
    (r"nginx/(\d+\.\d+[\.\d]*)", "nginx web server", "low"),
    (r"IIS/(\d+\.\d+)", "microsoft iis", "low"),
    (r"PHP/(\d+\.\d+[\.\d]*)", "php", "low"),
    (r"Python/(\d+\.\d+[\.\d]*)", "python", "low"),
    (r"Node\.js\s+v?(\d+\.\d+[\.\d]*)", "node.js", "low"),
    (r"\bExpress(?:/(\d+[\.\d]*))?", "express.js", "low"),
    (r"ASP\.NET Version:[\s]*(\d+[\.\d]*)", "asp.net", "low"),
    (r"X-AspNet-Version:\s*(\d+[\.\d]*)", "asp.net", "low"),
    (r"Tomcat/(\d+\.\d+[\.\d]*)", "apache tomcat", "low"),
    (r"JBoss(?:/(\d+[\.\d]*))?", "jboss", "low"),
    (r"OpenSSL/(\d+\.\d+[\.\da-z]*)", "openssl", "low"),
]

HEADER_VERSION_COMPILED = [
    (re.compile(p, re.IGNORECASE), desc, sev)
    for p, desc, sev in HEADER_VERSION_PATTERNS
]

# ── version patterns: BODY-only ─────────────────────────────────────
# checked against the html body — ALL patterns REQUIRE an actual version
# number to avoid matching framework names in regular page content.
# e.g. "Express" alone in JS code is meaningless; "Express/4.18.2" is real.

BODY_VERSION_PATTERNS = [
    (r"Apache/(\d+\.\d+[\.\d]+)", "apache web server version", "low"),
    (r"nginx/(\d+\.\d+[\.\d]+)", "nginx web server version", "low"),
    (r"PHP/(\d+\.\d+[\.\d]+)", "php version", "low"),
    (r"Python/(\d+\.\d+[\.\d]+)", "python version", "low"),
    (r"Ruby/(\d+\.\d+[\.\d]+)", "ruby version", "low"),
    (r"Node\.js\s+v?(\d+\.\d+[\.\d]+)", "node.js version", "low"),
    (r"\bExpress/(\d+\.\d+[\.\d]+)", "express.js version", "low"),
    (r"\bDjango/(\d+\.\d+[\.\d]*)", "django version", "low"),
    (r"\bLaravel/(\d+\.\d+[\.\d]*)", "laravel version", "low"),
    (r"\bWordPress[\s/]+(\d+\.\d+[\.\d]*)", "wordpress version", "medium"),
    (r"\bJoomla!?\s+(\d+\.\d+[\.\d]*)", "joomla version", "medium"),
    (r"\bDrupal\s+(\d+\.\d+[\.\d]*)", "drupal version", "medium"),
    (r"jQuery[\s/]+v?(\d+\.\d+\.\d+)", "jquery version", "info"),
]

BODY_VERSION_COMPILED = [
    (re.compile(p, re.IGNORECASE), desc, sev)
    for p, desc, sev in BODY_VERSION_PATTERNS
]


# ── stack trace / error / secret patterns ────────────────────────────

ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "python stack trace", "medium"),
    (r"at\s+\S+\.java:\d+", "java stack trace", "medium"),
    (r"at\s+\S+\s+\([\w/]+\.cs:\d+\)", "c# stack trace", "medium"),
    (r"Fatal error:.*in\s+/\S+\.php\s+on line\s+\d+", "php fatal error with path", "medium"),
    (r"Warning:.*in\s+/\S+\.php\s+on line\s+\d+", "php warning with path", "low"),
    (r"Notice:.*in\s+/\S+\.php\s+on line\s+\d+", "php notice with path", "low"),
    (r"Parse error:.*in\s+/\S+\.php", "php parse error with path", "medium"),
    (r"<b>Fatal error</b>:", "php fatal error (html)", "medium"),
    (r"Microsoft OLE DB Provider", "database connection error", "medium"),
    (r"ODBC\s+(?:SQL Server|Microsoft Access)\s+Driver", "database driver error", "medium"),
    (r"pg_connect\(\):", "postgresql connection error", "medium"),
    (r"mysql_connect\(\):", "mysql connection error", "medium"),
    (r"ORA-\d{5}", "oracle database error", "medium"),
    (r"DJANGO_SETTINGS_MODULE", "django settings exposed", "medium"),
    # require quoted values with minimum length to avoid matching env references
    (r"SECRET_KEY\s*[:=]\s*['\"][^'\"]{8,}['\"]", "secret key exposed", "critical"),
    (r"DB_PASSWORD\s*[:=]\s*['\"][^'\"]{4,}['\"]", "database password exposed", "critical"),
    (r"API_KEY\s*[:=]\s*['\"][^'\"]{8,}['\"]", "api key exposed", "critical"),
    (r"password\s*[:=]\s*['\"][^'\"]{4,}['\"]", "hardcoded password", "critical"),
]

ERROR_COMPILED = [
    (re.compile(p, re.IGNORECASE), desc, sev) for p, desc, sev in ERROR_PATTERNS
]

# debug mode detection — compiled separately (case-sensitive for Python's True)
DEBUG_PATTERN = re.compile(r'\bDEBUG\s*=\s*True\b')


# ── comment credential detection ────────────────────────────────────
# instead of matching generic words like "key" or "token", require
# an actual assignment pattern: credential_name = "value"

CREDENTIAL_IN_COMMENT = re.compile(
    r'(?:password|passwd|pwd|api_key|api_secret|apikey|secret_key|'
    r'private_key|access_key|auth_token|access_token|bearer_token|'
    r'client_secret|database_url|db_pass(?:word)?|db_user|'
    r'mysql_password|mysql_root_password|redis_password|'
    r'aws_secret_access_key|stripe_secret|jwt_secret)\s*[:=]\s*["\']?\S{4,}',
    re.IGNORECASE,
)

# real server paths in comments (not just /usr/, but specific sensitive paths)
SENSITIVE_PATH_IN_COMMENT = re.compile(
    r'(?:/etc/(?:passwd|shadow|hosts|nginx|apache2?|mysql|php|ssl)|'
    r'/var/(?:www|log/|run/|lib/mysql)|'
    r'/home/\w+/\.|'
    r'C:\\(?:Windows\\System32|inetpub|Users\\[^\\]+\\))',
    re.IGNORECASE,
)


# ── email / ip patterns ─────────────────────────────────────────────

EMAIL_PATTERN = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')

# domains to skip — placeholder / standard / spec emails
IGNORE_EMAIL_DOMAINS = {
    'example.com', 'example.org', 'example.net',
    'test.com', 'test.org', 'localhost',
    'w3.org', 'ietf.org', 'smpte.org',
    'yoursite.com', 'yourdomain.com',
    'domain.com', 'domain.org',
    'email.com', 'company.com',
}

# skip emails that are clearly library / spec attributions
IGNORE_EMAIL_PATTERNS = re.compile(
    r'(?:'
    r'@nicedoc\.io|'
    r'@chromium\.org|'
    r'@googl(?:e|ers)\.com|'
    r'noreply@|'
    r'no-reply@|'
    r'donotreply@'
    r')',
    re.IGNORECASE,
)

INTERNAL_IP_PATTERN = re.compile(
    r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3})\b'
)


class InfoDisclosurePlugin(BasePlugin):
    """information disclosure vulnerability scanner."""

    name = "infodisclosure"
    description = "information disclosure detection (versions, errors, secrets)"
    default_severity = "low"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        resp = await http.get(target.url, use_cache=True)
        if resp.error:
            return findings

        # skip non-200 or empty responses — not a real page
        if resp.status != 200 or resp.content_length == 0:
            return findings

        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        reported_versions: set[str] = set()

        # ── version disclosure in HEADERS ──
        for pattern, desc, severity in HEADER_VERSION_COMPILED:
            match = pattern.search(headers_str)
            if match and desc not in reported_versions:
                reported_versions.add(desc)
                version = match.group(1) if match.lastindex and match.group(1) else "detected"
                findings.append(self.make_finding(
                    title=f"version disclosure: {desc}",
                    url=target.url,
                    severity=severity,
                    evidence=f"{desc}: {version} (in response headers)",
                    remediation="remove version information from server headers. "
                                "configure the server to hide version details.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                    ],
                ))

        # ── version disclosure in BODY (requires real version numbers) ──
        body_sample = resp.body[:50000]
        for pattern, desc, severity in BODY_VERSION_COMPILED:
            match = pattern.search(body_sample)
            if match and desc not in reported_versions:
                reported_versions.add(desc)
                version = match.group(1) if match.lastindex else "detected"
                findings.append(self.make_finding(
                    title=f"version disclosure: {desc}",
                    url=target.url,
                    severity=severity,
                    evidence=f"{desc}: {version} (in page body)",
                    remediation="remove version information from response bodies. "
                                "configure the server to hide version details.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                    ],
                ))

        # ── error messages / stack traces ──
        for pattern, desc, severity in ERROR_COMPILED:
            match = pattern.search(resp.body)
            if match:
                evidence_text = match.group(0)[:200]
                findings.append(self.make_finding(
                    title=f"error disclosure: {desc}",
                    url=target.url,
                    severity=severity,
                    evidence=f"{desc}: {evidence_text}",
                    remediation="implement custom error pages. disable debug mode "
                                "in production. never expose stack traces or internal "
                                "paths to users.",
                    references=[
                        "https://owasp.org/www-community/Improper_Error_Handling",
                    ],
                ))

        # ── debug mode (case-sensitive: Python's True vs JS true) ──
        if DEBUG_PATTERN.search(resp.body):
            findings.append(self.make_finding(
                title="error disclosure: debug mode enabled",
                url=target.url,
                severity="high",
                evidence="DEBUG = True found in page source",
                remediation="disable debug mode in production. set DEBUG = False.",
                references=[
                    "https://owasp.org/www-community/Improper_Error_Handling",
                ],
            ))

        # ── credential leaks in HTML comments ──
        for m in HTML_COMMENT_RE.finditer(resp.body[:200000]):
            comment = m.group(1)
            if len(comment) > 1000:  # skip huge comments (minified code, licenses)
                continue
            cred = CREDENTIAL_IN_COMMENT.search(comment)
            if cred:
                findings.append(self.make_finding(
                    title="credentials in html comment",
                    url=target.url,
                    severity="high",
                    evidence=f"found in html comment: {cred.group(0)[:150]}",
                    remediation="remove credentials from html comments. use environment "
                                "variables or secret management for sensitive values.",
                ))
            path_match = SENSITIVE_PATH_IN_COMMENT.search(comment)
            if path_match:
                findings.append(self.make_finding(
                    title="server path in html comment",
                    url=target.url,
                    severity="low",
                    evidence=f"found in html comment: {path_match.group(0)[:150]}",
                    remediation="remove server paths from production code.",
                ))

        # ── credential leaks in JS/CSS block comments ──
        for m in JS_BLOCK_COMMENT_RE.finditer(resp.body[:200000]):
            comment = m.group(1)
            if len(comment) > 1000:
                continue
            cred = CREDENTIAL_IN_COMMENT.search(comment)
            if cred:
                findings.append(self.make_finding(
                    title="credentials in js/css comment",
                    url=target.url,
                    severity="high",
                    evidence=f"found in comment: {cred.group(0)[:150]}",
                    remediation="remove credentials from source code comments. "
                                "use environment variables or secret management.",
                ))

        # ── internal ip addresses ──
        # strip scripts and comments to avoid false positives from JS
        # bundles, CDN configs, and polyfill attributions
        clean_body = _strip_scripts_and_comments(resp.body)

        # check headers (always reliable)
        header_ips = INTERNAL_IP_PATTERN.findall(headers_str)
        body_ips = INTERNAL_IP_PATTERN.findall(clean_body[:100000])
        all_ips = list(set(header_ips + body_ips))

        if all_ips:
            source = "response headers" if header_ips else "page body"
            findings.append(self.make_finding(
                title="internal ip address disclosure",
                url=target.url,
                severity="low",
                evidence=f"internal ip addresses found in {source}: {', '.join(all_ips[:5])}",
                remediation="remove internal ip addresses from response bodies and headers.",
                references=[
                    "https://cwe.mitre.org/data/definitions/200.html",
                ],
            ))

        # ── email addresses ──
        # use the same cleaned body (no scripts, no html comments)
        emails = EMAIL_PATTERN.findall(clean_body[:100000])
        if emails:
            filtered = [
                e for e in set(emails)
                if not any(e.lower().endswith(f"@{d}") for d in IGNORE_EMAIL_DOMAINS)
                and not IGNORE_EMAIL_PATTERNS.search(e)
            ]
            if filtered:
                findings.append(self.make_finding(
                    title="email address disclosure",
                    url=target.url,
                    severity="info",
                    evidence=f"email addresses found: {', '.join(sorted(filtered)[:5])}",
                    remediation="consider obfuscating email addresses to prevent harvesting.",
                ))

        # also trigger errors to find error-based disclosures
        error_findings = await self._trigger_errors(target, http)
        findings.extend(error_findings)

        return findings

    async def _trigger_errors(
        self, target: Target, http: HTTPEngine
    ) -> list[Finding]:
        """try to trigger error responses for information leakage."""
        findings: list[Finding] = []
        base = target.base_url.rstrip("/")
        error_triggers = [
            ("GET", f"{base}/c0n%00scanner", "null byte in url"),
            ("GET", f"{base}/'\"", "special characters in url"),
            ("GET", f"{base}/" + "A" * 5000, "long url"),
        ]

        for method, url, desc in error_triggers:
            resp = await http.request(method, url)
            if resp.error:
                continue

            if resp.status >= 400:
                for pattern, error_desc, severity in ERROR_COMPILED:
                    match = pattern.search(resp.body)
                    if match:
                        findings.append(self.make_finding(
                            title=f"error information disclosure ({desc})",
                            url=url,
                            severity=severity,
                            evidence=f"triggered via {desc}: {error_desc} - {match.group(0)[:150]}",
                            remediation="implement custom error handlers for all "
                                        "http error codes. never expose technical "
                                        "details in error responses.",
                        ))
                        break

        return findings

"""security headers analyzer plugin for c0nscanner.

checks for missing or misconfigured security headers.
"""

from __future__ import annotations

from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding


# security headers to check with their descriptions
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "hsts - forces https connections",
        "severity": "medium",
        "remediation": "add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
        "cvss": 5.0,
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "Content-Security-Policy": {
        "description": "csp - prevents xss and data injection",
        "severity": "medium",
        "remediation": "implement a content-security-policy header. start with a report-only policy and gradually tighten it.",
        "cvss": 5.0,
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "X-Content-Type-Options": {
        "description": "prevents mime-type sniffing",
        "severity": "low",
        "remediation": "add 'X-Content-Type-Options: nosniff' header.",
        "cvss": 3.0,
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "X-Frame-Options": {
        "description": "prevents clickjacking via framing",
        "severity": "medium",
        "remediation": "add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header. "
                       "alternatively use CSP frame-ancestors directive.",
        "cvss": 4.3,
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "X-XSS-Protection": {
        "description": "browser xss filter (legacy but still useful)",
        "severity": "low",
        "remediation": "add 'X-XSS-Protection: 1; mode=block' header.",
        "cvss": 2.0,
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    },
    "Referrer-Policy": {
        "description": "controls referrer information leakage",
        "severity": "low",
        "remediation": "add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "cvss": 3.0,
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "description": "controls browser feature access (camera, mic, etc)",
        "severity": "low",
        "remediation": "add a Permissions-Policy header to restrict unnecessary browser features.",
        "cvss": 2.0,
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "controls flash/pdf cross-domain access",
        "severity": "low",
        "remediation": "add 'X-Permitted-Cross-Domain-Policies: none' header.",
        "cvss": 2.0,
        "ref": "https://owasp.org/www-project-secure-headers/",
    },
}

# dangerous header values
DANGEROUS_CSP_VALUES = [
    "unsafe-inline",
    "unsafe-eval",
    "data:",
    "*",
]


class HeadersPlugin(BasePlugin):
    """security headers analysis plugin."""

    name = "headers"
    description = "security headers analysis (csp, hsts, x-frame-options, etc)"
    default_severity = "low"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        resp = await http.get(target.url, use_cache=True)
        if resp.error:
            return findings

        # skip non-200 or empty responses — not a real page
        if resp.status != 200 or resp.content_length == 0:
            return findings

        response_headers = {k.lower(): v for k, v in resp.headers.items()}

        # check for missing headers
        for header_name, info in SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            if header_lower not in response_headers:
                findings.append(self.make_finding(
                    title=f"missing security header: {header_name.lower()}",
                    url=target.url,
                    severity=info["severity"],
                    evidence=f"{info['description']} - header not present in response",
                    remediation=info["remediation"],
                    cvss=info["cvss"],
                    references=[info["ref"]],
                ))

        # check csp quality if present
        csp = response_headers.get("content-security-policy", "")
        if csp:
            csp_findings = self._analyze_csp(target.url, csp)
            findings.extend(csp_findings)

        # check hsts quality if present
        hsts = response_headers.get("strict-transport-security", "")
        if hsts:
            hsts_findings = self._analyze_hsts(target.url, hsts)
            findings.extend(hsts_findings)

        # check for information leaking headers
        leak_findings = self._check_info_leak_headers(target.url, response_headers)
        findings.extend(leak_findings)

        return findings

    def _analyze_csp(self, url: str, csp: str) -> list[Finding]:
        """analyze content-security-policy for weaknesses."""
        findings: list[Finding] = []

        for dangerous in DANGEROUS_CSP_VALUES:
            if dangerous in csp:
                findings.append(self.make_finding(
                    title=f"weak csp: '{dangerous}' directive found",
                    url=url,
                    severity="medium",
                    evidence=f"content-security-policy contains '{dangerous}' which weakens protection",
                    remediation=f"remove '{dangerous}' from the csp directive and use "
                                "nonces or hashes for inline scripts.",
                    cvss=4.0,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                ))

        # check for missing default-src
        if "default-src" not in csp:
            findings.append(self.make_finding(
                title="csp missing default-src directive",
                url=url,
                severity="low",
                evidence="content-security-policy does not include a default-src fallback",
                remediation="add 'default-src' directive as a fallback for unlisted resource types.",
                cvss=3.0,
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
            ))

        return findings

    def _analyze_hsts(self, url: str, hsts: str) -> list[Finding]:
        """analyze hsts header for weaknesses."""
        findings: list[Finding] = []

        # check max-age
        if "max-age=" in hsts:
            try:
                max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:  # less than 1 year
                    findings.append(self.make_finding(
                        title="hsts max-age too short",
                        url=url,
                        severity="low",
                        evidence=f"hsts max-age is {max_age}s (recommended: 31536000+)",
                        remediation="set hsts max-age to at least 31536000 (1 year).",
                        cvss=2.0,
                    ))
            except (ValueError, IndexError):
                pass

        if "includesubdomains" not in hsts.lower():
            findings.append(self.make_finding(
                title="hsts missing includesubdomains",
                url=url,
                severity="low",
                evidence="hsts header does not include the includeSubDomains directive",
                remediation="add 'includeSubDomains' to the hsts header.",
                cvss=2.0,
            ))

        return findings

    def _check_info_leak_headers(
        self, url: str, headers: dict[str, str]
    ) -> list[Finding]:
        """check for headers that leak server information."""
        findings: list[Finding] = []

        info_headers = {
            "server": "server software version",
            "x-powered-by": "backend technology",
            "x-aspnet-version": "asp.net version",
            "x-aspnetmvc-version": "asp.net mvc version",
        }

        for header, desc in info_headers.items():
            if header in headers:
                findings.append(self.make_finding(
                    title=f"information disclosure via '{header}' header",
                    url=url,
                    severity="info",
                    evidence=f"{header}: {headers[header]} ({desc} disclosed)",
                    remediation=f"remove or obfuscate the '{header}' response header.",
                    cvss=0.0,
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                    ],
                ))

        return findings

"""server-side request forgery (ssrf) scanner plugin for c0nscanner.

detects ssrf by testing for internal ip access and dns rebinding patterns.
"""

from __future__ import annotations

import re

from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding


# patterns indicating internal resource access
INTERNAL_PATTERNS = [
    # cloud metadata endpoints
    (r"ami-id", "aws ec2 metadata detected"),
    (r"instance-id", "cloud instance metadata detected"),
    (r"\"accountId\"", "aws metadata account id detected"),
    (r"computeMetadata", "gcp metadata detected"),
    (r"azEnvironment", "azure metadata detected"),
    # internal services
    (r"<title>.*dashboard.*</title>", "internal dashboard detected"),
    (r"phpinfo\(\)", "phpinfo page detected"),
    (r"server-status", "apache server-status detected"),
    (r"fpm-status", "php-fpm status detected"),
]

INTERNAL_REGEX = [(re.compile(p, re.IGNORECASE), d) for p, d in INTERNAL_PATTERNS]

# ssrf payloads targeting internal resources
SSRF_PAYLOADS = [
    # localhost variants
    ("http://127.0.0.1/", "localhost via 127.0.0.1"),
    ("http://localhost/", "localhost direct"),
    ("http://[::1]/", "localhost via ipv6"),
    ("http://0.0.0.0/", "localhost via 0.0.0.0"),
    ("http://0x7f000001/", "localhost via hex encoding"),
    ("http://2130706433/", "localhost via decimal encoding"),
    ("http://017700000001/", "localhost via octal encoding"),
    ("http://127.1/", "localhost via short form"),
    # cloud metadata endpoints
    ("http://169.254.169.254/latest/meta-data/", "aws metadata endpoint"),
    ("http://169.254.169.254/computeMetadata/v1/", "gcp metadata endpoint"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure metadata endpoint"),
    # internal network ranges
    ("http://10.0.0.1/", "internal network 10.x"),
    ("http://192.168.0.1/", "internal network 192.168.x"),
    ("http://172.16.0.1/", "internal network 172.16.x"),
    # dns rebinding / redirect
    ("http://spoofed.burpcollaborator.net/", "external callback test"),
]


class SSRFPlugin(BasePlugin):
    """server-side request forgery vulnerability scanner."""

    name = "ssrf"
    description = "ssrf detection with internal ip and metadata checks"
    default_severity = "high"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        if not target.is_parameterized:
            return findings

        for param in target.param_names:
            # test url-type parameters (common ssrf vectors)
            result = await self._test_ssrf(target, param, http)
            if result:
                findings.append(result)

        return findings

    async def _test_ssrf(
        self, target: Target, param: str, http: HTTPEngine
    ) -> Finding | None:
        """test for ssrf by injecting internal urls."""
        # get baseline response for comparison
        baseline = await http.get(target.url)
        if baseline.error:
            return None

        for payload, desc in SSRF_PAYLOADS:
            url = target.with_payload(param, payload)
            resp = await http.get(url)

            if resp.error:
                continue

            # check for signs of internal resource access
            # 1. response differs significantly from baseline
            if resp.content_length > 0 and abs(resp.content_length - baseline.content_length) > 100:
                # 2. check for internal content patterns
                for pattern, evidence_desc in INTERNAL_REGEX:
                    if pattern.search(resp.body):
                        return self.make_finding(
                            title=f"ssrf in '{param}' ({desc})",
                            url=target.url,
                            severity="critical" if "metadata" in desc else "high",
                            parameter=param,
                            payload=payload,
                            evidence=evidence_desc,
                            remediation="validate and whitelist allowed urls/domains. "
                                        "block requests to internal ip ranges and cloud "
                                        "metadata endpoints. use a url parser to validate schemes.",
                            cvss=9.1 if "metadata" in desc else 7.5,
                            references=[
                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                                "https://cwe.mitre.org/data/definitions/918.html",
                            ],
                        )

            # 3. check if the server fetched our url (response differs)
            if (
                resp.status == 200
                and resp.body_hash != baseline.body_hash
                and ("127.0.0.1" in payload or "169.254" in payload or "localhost" in payload)
            ):
                # additional content check
                if resp.content_length > 50 and resp.content_length != baseline.content_length:
                    return self.make_finding(
                        title=f"potential ssrf in '{param}' ({desc})",
                        url=target.url,
                        severity="medium",
                        parameter=param,
                        payload=payload,
                        evidence=f"response changed when internal url was injected "
                                 f"(baseline: {baseline.content_length}b, "
                                 f"injected: {resp.content_length}b)",
                        remediation="validate and whitelist allowed urls/domains. "
                                    "block requests to internal ip ranges.",
                        cvss=6.5,
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                        ],
                    )

        return None

"""cors misconfiguration scanner plugin for c0nscanner.

detects permissive or exploitable cors configurations.
"""

from __future__ import annotations

from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding


class CORSPlugin(BasePlugin):
    """cors misconfiguration scanner."""

    name = "cors"
    description = "cors misconfiguration detection"
    default_severity = "medium"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        # quick sanity check — make sure target is alive
        probe = await http.get(target.url, use_cache=True)
        if probe.error or probe.status != 200 or probe.content_length == 0:
            return findings

        # test 1: reflected origin
        result = await self._test_origin_reflection(target, http)
        if result:
            findings.append(result)

        # test 2: null origin
        result = await self._test_null_origin(target, http)
        if result:
            findings.append(result)

        # test 3: wildcard with credentials
        result = await self._test_wildcard_credentials(target, http)
        if result:
            findings.append(result)

        # test 4: subdomain trust
        result = await self._test_subdomain_trust(target, http)
        if result:
            findings.append(result)

        return findings

    async def _test_origin_reflection(
        self, target: Target, http: HTTPEngine
    ) -> Finding | None:
        """test if the server reflects arbitrary origins."""
        evil_origin = "https://evil-c0nscanner.com"
        resp = await http.get(
            target.url,
            headers={"Origin": evil_origin},
        )

        if resp.error:
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == evil_origin:
            severity = "high" if acac == "true" else "medium"
            return self.make_finding(
                title="cors: arbitrary origin reflected",
                url=target.url,
                severity=severity,
                evidence=f"origin '{evil_origin}' was reflected in access-control-allow-origin. "
                         f"credentials allowed: {acac}",
                remediation="do not reflect arbitrary origins. use a strict whitelist of "
                            "allowed origins. avoid using access-control-allow-credentials "
                            "with reflected origins.",
                cvss=7.5 if acac == "true" else 5.0,
                references=[
                    "https://portswigger.net/web-security/cors",
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                ],
            )

        return None

    async def _test_null_origin(
        self, target: Target, http: HTTPEngine
    ) -> Finding | None:
        """test if null origin is accepted."""
        resp = await http.get(
            target.url,
            headers={"Origin": "null"},
        )

        if resp.error:
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "null":
            return self.make_finding(
                title="cors: null origin accepted",
                url=target.url,
                severity="medium",
                evidence=f"null origin is reflected in access-control-allow-origin. "
                         f"credentials allowed: {acac}",
                remediation="do not allow 'null' as a valid origin. the null origin "
                            "is sent from sandboxed iframes and local files, making "
                            "it exploitable.",
                cvss=5.3,
                references=[
                    "https://portswigger.net/web-security/cors",
                ],
            )

        return None

    async def _test_wildcard_credentials(
        self, target: Target, http: HTTPEngine
    ) -> Finding | None:
        """test for wildcard origin with credentials."""
        resp = await http.get(
            target.url,
            headers={"Origin": "https://test.com"},
        )

        if resp.error:
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*" and acac == "true":
            return self.make_finding(
                title="cors: wildcard origin with credentials",
                url=target.url,
                severity="high",
                evidence="access-control-allow-origin is '*' with "
                         "access-control-allow-credentials: true",
                remediation="never combine wildcard (*) origin with credentials. "
                            "browsers block this, but it indicates a misconfiguration.",
                cvss=7.5,
                references=[
                    "https://portswigger.net/web-security/cors",
                ],
            )

        if acao == "*":
            return self.make_finding(
                title="cors: wildcard origin allowed",
                url=target.url,
                severity="low",
                evidence="access-control-allow-origin is set to '*'",
                remediation="restrict cors to specific trusted origins instead of using wildcard.",
                cvss=3.0,
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ],
            )

        return None

    async def _test_subdomain_trust(
        self, target: Target, http: HTTPEngine
    ) -> Finding | None:
        """test if arbitrary subdomains of the target domain are trusted."""
        evil_subdomain = f"https://evil.{target.domain}"
        resp = await http.get(
            target.url,
            headers={"Origin": evil_subdomain},
        )

        if resp.error:
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")

        if acao == evil_subdomain:
            return self.make_finding(
                title="cors: arbitrary subdomain trusted",
                url=target.url,
                severity="medium",
                evidence=f"arbitrary subdomain '{evil_subdomain}' is trusted. "
                         "an xss on any subdomain could be leveraged.",
                remediation="do not trust all subdomains. whitelist specific trusted subdomains only.",
                cvss=5.0,
                references=[
                    "https://portswigger.net/web-security/cors",
                ],
            )

        return None

"""open redirect scanner plugin for c0nscanner.

detects open redirect vulnerabilities in url parameters.
"""

from __future__ import annotations

from urllib.parse import urlparse

from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding


# common parameter names that often contain redirect urls
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnto", "return_to", "next", "next_url", "goto", "go", "to",
    "target", "dest", "destination", "redir", "redirect_to", "out",
    "view", "login_url", "logout", "checkout_url", "continue", "ref",
    "referrer", "callback", "callback_url", "fallback", "forward",
}

# open redirect payloads
REDIRECT_PAYLOADS = [
    # direct url
    ("https://evil.com", "direct external url"),
    ("//evil.com", "protocol-relative url"),
    # url encoding tricks
    ("https:%2F%2Fevil.com", "url-encoded slashes"),
    ("%2F%2Fevil.com", "double-encoded protocol-relative"),
    # backslash tricks
    ("https:\\\\evil.com", "backslash url"),
    ("/\\evil.com", "slash-backslash"),
    # scheme tricks
    ("javascript:alert(1)", "javascript scheme"),
    ("data:text/html,<script>alert(1)</script>", "data scheme"),
    # domain confusion
    ("https://evil.com@legitimate.com", "url with @ sign"),
    ("https://legitimate.com.evil.com", "subdomain confusion"),
    # tab/newline injection
    ("https://evil.com%09", "tab character append"),
    ("https://evil.com%0a", "newline append"),
    # dot bypass
    ("https://evil.com/.", "trailing dot"),
    ("/\\.evil.com", "dot after backslash"),
]


class OpenRedirectPlugin(BasePlugin):
    """open redirect vulnerability scanner."""

    name = "openredirect"
    description = "open redirect detection"
    default_severity = "medium"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        if not target.is_parameterized:
            return findings

        for param in target.param_names:
            # prioritize known redirect parameter names
            is_likely_redirect = param.lower() in REDIRECT_PARAMS

            result = await self._test_redirect(target, param, http, is_likely_redirect)
            if result:
                findings.append(result)

        return findings

    async def _test_redirect(
        self, target: Target, param: str, http: HTTPEngine,
        is_likely_redirect: bool
    ) -> Finding | None:
        """test for open redirect in a specific parameter."""
        payloads = REDIRECT_PAYLOADS
        if not is_likely_redirect:
            # only test a subset for non-redirect-like params
            payloads = payloads[:4]

        for payload, desc in payloads:
            url = target.with_payload(param, payload)
            resp = await http.request("GET", url, allow_redirects=False)

            if resp.error:
                continue

            # check for redirect status codes
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")

                if self._is_external_redirect(location, target.domain):
                    return self.make_finding(
                        title=f"open redirect in '{param}'",
                        url=target.url,
                        severity="medium",
                        parameter=param,
                        payload=payload,
                        evidence=f"redirect to external location: {location} "
                                 f"(technique: {desc})",
                        remediation="validate redirect targets against a whitelist "
                                    "of allowed domains. use relative urls for redirects. "
                                    "never use user input directly in redirect locations.",
                        cvss=4.7,
                        references=[
                            "https://cwe.mitre.org/data/definitions/601.html",
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
                        ],
                    )

            # check for meta refresh or javascript redirect in body
            if resp.status == 200:
                body_lower = resp.body.lower()
                if ("evil.com" in body_lower and
                    ("meta http-equiv" in body_lower or
                     "window.location" in body_lower or
                     "document.location" in body_lower)):
                    return self.make_finding(
                        title=f"open redirect via html/js in '{param}'",
                        url=target.url,
                        severity="medium",
                        parameter=param,
                        payload=payload,
                        evidence=f"redirect to external url found in response body (technique: {desc})",
                        remediation="validate redirect targets. sanitize user input "
                                    "before using in meta refresh or javascript redirects.",
                        cvss=4.7,
                        references=[
                            "https://cwe.mitre.org/data/definitions/601.html",
                        ],
                    )

        return None

    def _is_external_redirect(self, location: str, target_domain: str) -> bool:
        """check if a redirect location points to an external domain."""
        if not location:
            return False

        # normalize
        location = location.strip()

        # protocol-relative
        if location.startswith("//"):
            location = "https:" + location

        try:
            parsed = urlparse(location)
            if parsed.hostname:
                return parsed.hostname.lower() != target_domain.lower()
        except Exception:
            pass

        # check for dangerous schemes
        if location.lower().startswith(("javascript:", "data:", "vbscript:")):
            return True

        return False

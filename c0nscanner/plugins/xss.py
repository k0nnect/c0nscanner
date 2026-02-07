"""cross-site scripting (xss) scanner plugin for c0nscanner.

detects reflected xss and basic dom-based xss patterns.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from c0nscanner.config import Config
from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding
from c0nscanner.utils.helpers import random_boundary


# dom sinks that can lead to xss
DOM_SINKS = [
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"\.insertAdjacentHTML\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
    r"new\s+Function\s*\(",
    r"\.src\s*=",
    r"\.href\s*=",
    r"\.action\s*=",
    r"location\s*=",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
    r"window\.open\s*\(",
]

DOM_SINK_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DOM_SINKS]

# dom sources - user controllable input
DOM_SOURCES = [
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"location\.search",
    r"location\.hash",
    r"location\.href",
    r"window\.name",
    r"document\.cookie",
]

DOM_SOURCE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DOM_SOURCES]


class XSSPlugin(BasePlugin):
    """cross-site scripting vulnerability scanner."""

    name = "xss"
    description = "xss detection (reflected, dom-based)"
    default_severity = "high"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        config = self._module_config
        types = config.get("types", ["reflected", "dom"])

        # reflected xss needs parameters
        if "reflected" in types and target.is_parameterized:
            for param in target.param_names:
                result = await self._test_reflected(target, param, http)
                if result:
                    findings.append(result)

        # dom-based xss can be found on any page
        if "dom" in types:
            result = await self._test_dom_based(target, http)
            if result:
                findings.append(result)

        return findings

    async def _test_reflected(
        self, target: Target, param: str, http: HTTPEngine
    ) -> Finding | None:
        """test for reflected xss by injecting and checking reflection."""
        # first, test with a unique boundary to confirm reflection
        boundary = random_boundary()
        url = target.with_payload(param, boundary)
        resp = await http.get(url)

        if resp.error or boundary not in resp.body:
            return None  # input not reflected

        # determine reflection context
        context = self._detect_context(resp.body, boundary)

        # test context-specific payloads
        test_payloads = self._get_context_payloads(context, boundary)

        for payload, check_pattern in test_payloads:
            url = target.with_payload(param, payload)
            resp = await http.get(url)

            if resp.error:
                continue

            if re.search(check_pattern, resp.body, re.IGNORECASE):
                return self.make_finding(
                    title=f"reflected xss in '{param}' ({context} context)",
                    url=target.url,
                    severity="high",
                    parameter=param,
                    payload=payload,
                    evidence=f"payload reflected in {context} context without proper encoding",
                    remediation="encode all user input before rendering in html. "
                                "use context-aware output encoding (html entity, "
                                "js escape, url encode). implement content-security-policy.",
                    cvss=6.1,
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cwe.mitre.org/data/definitions/79.html",
                    ],
                )

        return None

    def _detect_context(self, body: str, boundary: str) -> str:
        """detect the html context where input is reflected."""
        idx = body.find(boundary)
        if idx == -1:
            return "html"

        # look at surrounding context
        before = body[max(0, idx - 100):idx].lower()

        if re.search(r'<script[^>]*>[^<]*$', before):
            return "javascript"
        elif re.search(r'=\s*["\']?\s*$', before):
            return "attribute"
        elif re.search(r'<style[^>]*>[^<]*$', before):
            return "css"
        elif re.search(r'<!--', before) and '-->' not in before[before.rfind('<!--'):]:
            return "comment"
        else:
            return "html"

    def _get_context_payloads(
        self, context: str, boundary: str
    ) -> list[tuple[str, str]]:
        """get payloads specific to the reflection context."""
        payloads: list[tuple[str, str]] = []

        if context == "html":
            payloads = [
                (f"<script>{boundary}</script>", rf"<script>{boundary}</script>"),
                (f"<img src=x onerror={boundary}>", rf"<img\s+src=x\s+onerror={boundary}"),
                (f"<svg onload={boundary}>", rf"<svg\s+onload={boundary}"),
                (f"<details open ontoggle={boundary}>", rf"ontoggle={boundary}"),
            ]
        elif context == "attribute":
            payloads = [
                (f'">{boundary}<"', rf">{boundary}<"),
                (f"' onfocus={boundary} autofocus='", rf"onfocus={boundary}"),
                (f'" onmouseover={boundary} x="', rf"onmouseover={boundary}"),
                (f'"><img src=x onerror={boundary}>', rf"onerror={boundary}"),
            ]
        elif context == "javascript":
            payloads = [
                (f"';{boundary}//", rf"{boundary}"),
                (f'";{boundary}//', rf"{boundary}"),
                (f"</script><script>{boundary}</script>", rf"<script>{boundary}</script>"),
            ]
        elif context == "comment":
            payloads = [
                (f"--><script>{boundary}</script><!--", rf"<script>{boundary}</script>"),
                (f"--><img src=x onerror={boundary}>", rf"onerror={boundary}"),
            ]

        return payloads

    async def _test_dom_based(
        self, target: Target, http: HTTPEngine
    ) -> Finding | None:
        """test for dom-based xss by analyzing javascript sources and sinks."""
        resp = await http.get(target.url, use_cache=True)
        if resp.error or resp.status != 200 or resp.content_length == 0:
            return None

        found_sources: list[str] = []
        found_sinks: list[str] = []

        for pattern in DOM_SOURCE_PATTERNS:
            if pattern.search(resp.body):
                found_sources.append(pattern.pattern)

        for pattern in DOM_SINK_PATTERNS:
            if pattern.search(resp.body):
                found_sinks.append(pattern.pattern)

        # only report if both sources and sinks are present
        if found_sources and found_sinks:
            return self.make_finding(
                title="potential dom-based xss detected",
                url=target.url,
                severity="medium",
                evidence=f"dom sources: {', '.join(found_sources[:3])} | "
                         f"dom sinks: {', '.join(found_sinks[:3])}",
                remediation="avoid using dangerous dom sinks with user-controlled "
                            "input. sanitize data before passing to innerHTML, "
                            "eval(), document.write(), etc.",
                cvss=6.1,
                references=[
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                ],
            )

        return None

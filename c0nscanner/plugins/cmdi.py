"""command injection scanner plugin for c0nscanner.

detects os command injection via error-based and time-based techniques.
"""

from __future__ import annotations

import re
import time

from c0nscanner.config import Config
from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding
from c0nscanner.utils.helpers import random_boundary


# patterns indicating command execution output
CMD_OUTPUT_PATTERNS = [
    # unix id command output
    r"uid=\d+\(\w+\)\s+gid=\d+",
    # unix uname output
    r"Linux\s+\S+\s+\d+\.\d+",
    # unix whoami-like output after injection
    r"^(root|www-data|apache|nginx|nobody|daemon)\s*$",
    # windows
    r"\\Users\\",
    r"\\Windows\\",
    r"Microsoft Windows \[Version",
    r"Volume Serial Number is",
    # /etc/passwd content
    r"root:x?:\d+:\d+:",
    # win.ini content
    r"\[fonts\]",
    r"\[extensions\]",
]

CMD_PATTERNS = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in CMD_OUTPUT_PATTERNS]

# time delay for blind testing
DELAY_SECONDS = 5
TIME_THRESHOLD = 4.5


class CMDiPlugin(BasePlugin):
    """command injection vulnerability scanner."""

    name = "cmdi"
    description = "os command injection detection (error/blind)"
    default_severity = "critical"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        if not target.is_parameterized:
            return findings

        techniques = self._module_config.get("techniques", ["blind", "error"])

        for param in target.param_names:
            if "error" in techniques:
                result = await self._test_error_based(target, param, http)
                if result:
                    findings.append(result)
                    continue  # skip blind if error-based found

            if "blind" in techniques:
                result = await self._test_time_based(target, param, http)
                if result:
                    findings.append(result)

        return findings

    async def _test_error_based(
        self, target: Target, param: str, http: HTTPEngine
    ) -> Finding | None:
        """test for command injection by checking for command output."""
        # use a unique boundary to detect output
        boundary = random_boundary()

        payloads = [
            (f"; echo {boundary}", boundary),
            (f"| echo {boundary}", boundary),
            (f"|| echo {boundary}", boundary),
            (f"& echo {boundary}", boundary),
            (f"&& echo {boundary}", boundary),
            (f"`echo {boundary}`", boundary),
            (f"$(echo {boundary})", boundary),
            ("; id", None),
            ("| id", None),
            ("; cat /etc/passwd", None),
            ("| type C:\\windows\\win.ini", None),
        ]

        for payload, marker in payloads:
            url = target.with_payload(param, payload)
            resp = await http.get(url)

            if resp.error:
                continue

            # check for our boundary marker
            if marker and marker in resp.body:
                return self.make_finding(
                    title=f"command injection in '{param}'",
                    url=target.url,
                    severity="critical",
                    parameter=param,
                    payload=payload,
                    evidence=f"injected command output detected: boundary marker '{marker}' found in response",
                    remediation="never pass user input directly to system commands. "
                                "use safe apis, input validation, and allowlists.",
                    cvss=9.8,
                    references=[
                        "https://owasp.org/www-community/attacks/Command_Injection",
                        "https://cwe.mitre.org/data/definitions/78.html",
                    ],
                )

            # check for known command output patterns
            if not marker:
                for pattern in CMD_PATTERNS:
                    if pattern.search(resp.body):
                        return self.make_finding(
                            title=f"command injection in '{param}'",
                            url=target.url,
                            severity="critical",
                            parameter=param,
                            payload=payload,
                            evidence=f"command output pattern detected: {pattern.pattern[:80]}",
                            remediation="never pass user input directly to system commands. "
                                        "use safe apis, input validation, and allowlists.",
                            cvss=9.8,
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                                "https://cwe.mitre.org/data/definitions/78.html",
                            ],
                        )

        return None

    async def _test_time_based(
        self, target: Target, param: str, http: HTTPEngine
    ) -> Finding | None:
        """test for blind command injection via time delays."""
        time_payloads = [
            f"; sleep {DELAY_SECONDS}",
            f"| sleep {DELAY_SECONDS}",
            f"|| sleep {DELAY_SECONDS}",
            f"& sleep {DELAY_SECONDS}",
            f"&& sleep {DELAY_SECONDS}",
            f"`sleep {DELAY_SECONDS}`",
            f"$(sleep {DELAY_SECONDS})",
            f"& ping -c {DELAY_SECONDS} 127.0.0.1",
            f"& timeout /t {DELAY_SECONDS}",
        ]

        for payload in time_payloads:
            url = target.with_payload(param, payload)
            start = time.monotonic()
            resp = await http.get(url)
            elapsed = time.monotonic() - start

            if resp.error:
                continue

            if elapsed >= TIME_THRESHOLD:
                # verify normal response time
                normal = await http.get(target.url)
                if normal.elapsed < TIME_THRESHOLD / 2:
                    return self.make_finding(
                        title=f"blind command injection in '{param}' (time-based)",
                        url=target.url,
                        severity="critical",
                        parameter=param,
                        payload=payload,
                        evidence=f"response delayed by {elapsed:.1f}s "
                                 f"(baseline: {normal.elapsed:.1f}s)",
                        remediation="never pass user input directly to system commands. "
                                    "use safe apis, input validation, and allowlists.",
                        cvss=9.8,
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                            "https://cwe.mitre.org/data/definitions/78.html",
                        ],
                    )

        return None

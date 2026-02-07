"""csrf detection scanner plugin for c0nscanner.

detects missing csrf protections by analyzing forms and cookies.
"""

from __future__ import annotations

import re

from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding


# common csrf token field names
CSRF_TOKEN_NAMES = {
    "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "_csrf", "_token", "token", "authenticity_token",
    "xsrf", "xsrf_token", "xsrf-token", "_xsrf",
    "anti-csrf-token", "anticsrf", "__requestverificationtoken",
    "verification_token", "form_token", "nonce",
}

# form pattern
FORM_PATTERN = re.compile(
    r'<form[^>]*>(.*?)</form>',
    re.IGNORECASE | re.DOTALL,
)

# input hidden pattern
HIDDEN_INPUT_PATTERN = re.compile(
    r'<input[^>]*type=["\']?hidden["\']?[^>]*>',
    re.IGNORECASE,
)

# name attribute pattern
NAME_PATTERN = re.compile(
    r'name=["\']?([^"\'>\s]+)',
    re.IGNORECASE,
)

# method pattern
METHOD_PATTERN = re.compile(
    r'method=["\']?(\w+)',
    re.IGNORECASE,
)

# action pattern
ACTION_PATTERN = re.compile(
    r'action=["\']?([^"\'>\s]*)',
    re.IGNORECASE,
)


class CSRFPlugin(BasePlugin):
    """csrf detection scanner."""

    name = "csrf"
    description = "csrf protection detection"
    default_severity = "medium"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        resp = await http.get(target.url, use_cache=True)
        if resp.error:
            return findings

        # skip non-200 or empty responses
        if resp.status != 200 or resp.content_length == 0:
            return findings

        # find all forms
        forms = FORM_PATTERN.findall(resp.body)
        full_forms = re.findall(r'<form[^>]*>.*?</form>', resp.body, re.IGNORECASE | re.DOTALL)

        for i, (form_content, full_form) in enumerate(zip(forms, full_forms)):
            # check form method
            method_match = METHOD_PATTERN.search(full_form)
            method = method_match.group(1).upper() if method_match else "GET"

            # only check POST forms (GET forms don't need csrf protection)
            if method != "POST":
                continue

            # get form action
            action_match = ACTION_PATTERN.search(full_form)
            action = action_match.group(1) if action_match else target.url

            # check for csrf tokens in hidden inputs
            hidden_inputs = HIDDEN_INPUT_PATTERN.findall(form_content)
            has_csrf_token = False

            for hidden in hidden_inputs:
                name_match = NAME_PATTERN.search(hidden)
                if name_match:
                    field_name = name_match.group(1).lower()
                    if any(token_name in field_name for token_name in CSRF_TOKEN_NAMES):
                        has_csrf_token = True
                        break

            if not has_csrf_token:
                # also check for csrf in custom headers (meta tags)
                meta_csrf = re.search(
                    r'<meta[^>]*name=["\']csrf[^"\']*["\'][^>]*content=["\']([^"\']+)',
                    resp.body,
                    re.IGNORECASE,
                )
                if meta_csrf:
                    has_csrf_token = True

                if not has_csrf_token:
                    findings.append(self.make_finding(
                        title=f"missing csrf token in form #{i + 1}",
                        url=target.url,
                        severity="medium",
                        evidence=f"POST form (action: {action}) does not contain "
                                 "a recognizable csrf token",
                        remediation="add a csrf token to all state-changing forms. "
                                    "use the synchronizer token pattern or double-submit "
                                    "cookie pattern. set samesite attribute on cookies.",
                        cvss=4.3,
                        references=[
                            "https://owasp.org/www-community/attacks/csrf",
                            "https://cwe.mitre.org/data/definitions/352.html",
                        ],
                    ))

        # check samesite cookie attribute
        cookie_findings = self._check_samesite(target.url, resp)
        findings.extend(cookie_findings)

        return findings

    def _check_samesite(self, url: str, resp: 'HTTPResponse') -> list[Finding]:
        """check if cookies have the samesite attribute."""
        findings: list[Finding] = []

        set_cookie_headers = []
        for key, value in resp.headers.items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(value)

        for cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "unknown"
            cookie_lower = cookie_header.lower()

            if "samesite" not in cookie_lower:
                findings.append(self.make_finding(
                    title=f"cookie '{cookie_name}' missing samesite attribute",
                    url=url,
                    severity="low",
                    evidence=f"set-cookie header for '{cookie_name}' does not include "
                             "the samesite attribute",
                    remediation="add 'SameSite=Lax' or 'SameSite=Strict' to all cookies "
                                "to help prevent csrf attacks.",
                    cvss=3.0,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                    ],
                ))
            elif "samesite=none" in cookie_lower:
                findings.append(self.make_finding(
                    title=f"cookie '{cookie_name}' has samesite=none",
                    url=url,
                    severity="low",
                    evidence=f"cookie '{cookie_name}' uses SameSite=None, "
                             "which provides no csrf protection",
                    remediation="use 'SameSite=Lax' or 'SameSite=Strict' instead of 'None' "
                                "unless cross-site cookie access is required.",
                    cvss=2.0,
                ))

        return findings

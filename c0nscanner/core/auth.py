"""authentication management for c0nscanner."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any


@dataclass
class AuthConfig:
    """authentication configuration."""

    auth_type: str = ""  # basic, bearer, cookie
    credentials: str = ""  # user:pass for basic, token for bearer
    cookie: str = ""
    custom_headers: dict[str, str] | None = None


class AuthManager:
    """manages authentication for http requests."""

    def __init__(self, config: dict[str, Any], custom_headers: dict[str, str] | None = None) -> None:
        self._auth_type = config.get("type", "")
        self._credentials = config.get("credentials", "")
        self._cookie = config.get("cookie", "")
        self._header = config.get("header", "")
        self._custom_headers = custom_headers or {}

    def get_headers(self) -> dict[str, str]:
        """build authentication headers based on config."""
        headers: dict[str, str] = {}

        # apply custom headers first
        headers.update(self._custom_headers)

        if self._auth_type == "basic" and self._credentials:
            encoded = base64.b64encode(self._credentials.encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {encoded}"

        elif self._auth_type == "bearer" and self._credentials:
            headers["Authorization"] = f"Bearer {self._credentials}"

        elif self._auth_type == "cookie" and self._cookie:
            headers["Cookie"] = self._cookie

        # apply explicit header override
        if self._header:
            if ":" in self._header:
                name, _, value = self._header.partition(":")
                headers[name.strip()] = value.strip()

        return headers

    def get_cookie_string(self) -> str:
        """return the cookie string if set."""
        return self._cookie

    @property
    def is_authenticated(self) -> bool:
        """check if any auth method is configured."""
        return bool(self._auth_type)

    def __repr__(self) -> str:
        if self._auth_type:
            return f"AuthManager(type={self._auth_type})"
        return "AuthManager(unauthenticated)"

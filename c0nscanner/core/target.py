"""target url parsing and management for c0nscanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse, urlunparse

from c0nscanner.utils.helpers import normalize_url, extract_params, get_base_url, get_domain


@dataclass
class Target:
    """represents a scan target with parsed url components."""

    raw_url: str
    url: str = ""
    scheme: str = ""
    domain: str = ""
    port: int | None = None
    path: str = ""
    query_string: str = ""
    params: dict[str, list[str]] = field(default_factory=dict)
    fragment: str = ""
    base_url: str = ""
    is_parameterized: bool = False
    _baseline: object = field(default=None, repr=False)  # set by scanner after reachability check

    def __post_init__(self) -> None:
        self.url = normalize_url(self.raw_url)
        parsed = urlparse(self.url)
        self.scheme = parsed.scheme
        self.domain = parsed.hostname or ""
        self.port = parsed.port
        self.path = parsed.path or "/"
        self.query_string = parsed.query
        self.params = extract_params(self.url)
        self.fragment = parsed.fragment
        self.base_url = get_base_url(self.url)
        self.is_parameterized = bool(self.params)

    @property
    def param_names(self) -> list[str]:
        """return list of parameter names."""
        return list(self.params.keys())

    @property
    def origin(self) -> str:
        """return the origin (scheme + domain + port)."""
        port_str = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.domain}{port_str}"

    def with_payload(self, param: str, payload: str) -> str:
        """return url with a specific parameter replaced by payload."""
        from c0nscanner.utils.helpers import inject_payload
        return inject_payload(self.url, param, payload)

    def clone_with_path(self, new_path: str) -> Target:
        """create a new target with a different path."""
        parsed = urlparse(self.url)
        new_url = urlunparse(parsed._replace(path=new_path, query=""))
        return Target(raw_url=new_url)

    def __str__(self) -> str:
        return self.url

    def __repr__(self) -> str:
        return f"Target(url={self.url!r}, params={self.param_names})"


def parse_targets(raw_targets: list[str]) -> list[Target]:
    """parse a list of raw url strings into target objects."""
    targets = []
    seen = set()
    for raw in raw_targets:
        url = normalize_url(raw)
        if url not in seen:
            seen.add(url)
            targets.append(Target(raw_url=raw))
    return targets

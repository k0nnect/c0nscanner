"""utility helpers for c0nscanner."""

from __future__ import annotations

import hashlib
import random
import string
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


# common user agents for rotation in stealth mode
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def random_ua() -> str:
    """return a random user-agent string."""
    return random.choice(USER_AGENTS)


def random_string(length: int = 8) -> str:
    """generate a random alphanumeric string."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def random_boundary() -> str:
    """generate a unique boundary marker for payload detection."""
    return f"c0n{random_string(12)}"


def hash_response(content: str) -> str:
    """create a hash of response content for comparison."""
    return hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()


def inject_payload(url: str, param: str, payload: str) -> str:
    """inject a payload into a specific url parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if param in params:
        params[param] = [payload]
    else:
        params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def extract_params(url: str) -> dict[str, list[str]]:
    """extract query parameters from a url."""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def get_base_url(url: str) -> str:
    """get the base url without query parameters."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def normalize_url(url: str) -> str:
    """normalize a url for consistent comparison."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    # remove trailing slash from path
    path = parsed.path.rstrip("/") or "/"
    return urlunparse(parsed._replace(path=path, fragment=""))


def get_domain(url: str) -> str:
    """extract the domain from a url."""
    parsed = urlparse(url)
    return parsed.hostname or ""


def get_payload_path(filename: str) -> Path:
    """get the path to a bundled payload file."""
    return Path(__file__).resolve().parent.parent / "payloads" / filename


def load_payloads(filename: str, max_payloads: int = 0) -> list[str]:
    """load payloads from a bundled file."""
    path = get_payload_path(filename)
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if max_payloads > 0:
        payloads = payloads[:max_payloads]
    return payloads


def format_duration(seconds: float) -> str:
    """format a duration in seconds to a human-readable string."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def is_same_domain(url1: str, url2: str) -> bool:
    """check if two urls belong to the same domain."""
    return get_domain(url1) == get_domain(url2)

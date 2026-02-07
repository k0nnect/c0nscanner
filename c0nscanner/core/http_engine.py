"""async http engine for c0nscanner.

provides connection pooling, automatic retries, proxy support,
rate limiting, and response caching.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from c0nscanner.config import Config
from c0nscanner.core.auth import AuthManager
from c0nscanner.utils.helpers import random_ua
from c0nscanner.utils.logger import get_logger


@dataclass
class HTTPResponse:
    """wrapper for http response data."""

    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    url: str = ""
    elapsed: float = 0.0
    content_length: int = 0
    content_type: str = ""
    error: str | None = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 400

    @property
    def is_error(self) -> bool:
        return self.status >= 400

    @property
    def body_hash(self) -> str:
        return hashlib.md5(self.body.encode("utf-8", errors="ignore")).hexdigest()

    def contains(self, text: str, case_sensitive: bool = False) -> bool:
        """check if the response body contains a string."""
        if case_sensitive:
            return text in self.body
        return text.lower() in self.body.lower()


class HTTPEngine:
    """async http client with connection pooling and rate limiting."""

    def __init__(self, config: Config, auth: AuthManager) -> None:
        self._config = config
        self._auth = auth
        self._session: aiohttp.ClientSession | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._request_count = 0
        self._cache: dict[str, HTTPResponse] = {}
        self._logger = get_logger()

    async def start(self) -> None:
        """initialize the http session and semaphore."""
        timeout = aiohttp.ClientTimeout(total=self._config.timeout)
        connector = aiohttp.TCPConnector(
            limit=self._config.threads * 2,
            limit_per_host=self._config.threads,
            ttl_dns_cache=300,
            ssl=False,
        )

        # build default headers
        headers = {
            "User-Agent": self._config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        # merge auth headers
        auth_headers = self._auth.get_headers()
        headers.update(auth_headers)

        proxy = self._config.get("proxy.url") or None

        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
        )
        self._semaphore = asyncio.Semaphore(self._config.threads)
        self._proxy = proxy

    async def stop(self) -> None:
        """close the http session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: str | dict | None = None,
        headers: dict[str, str] | None = None,
        allow_redirects: bool | None = None,
        use_cache: bool = False,
    ) -> HTTPResponse:
        """make an http request with retry logic and rate limiting."""
        if not self._session or not self._semaphore:
            raise RuntimeError("http engine not started. call start() first.")

        if allow_redirects is None:
            allow_redirects = self._config.follow_redirects

        # cache check
        cache_key = f"{method}:{url}:{params}:{data}:{headers}"
        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        # randomize user-agent in stealth mode
        extra_headers = dict(headers) if headers else {}
        if self._config.get("scanner.randomize_ua"):
            extra_headers["User-Agent"] = random_ua()

        async with self._semaphore:
            return await self._do_request(
                method, url, params, data, extra_headers,
                allow_redirects, cache_key, use_cache,
            )

    async def _do_request(
        self,
        method: str,
        url: str,
        params: dict[str, str] | None,
        data: str | dict | None,
        headers: dict[str, str],
        allow_redirects: bool,
        cache_key: str,
        use_cache: bool,
    ) -> HTTPResponse:
        """internal request with retries."""
        retries = self._config.retries
        delay = self._config.delay
        jitter = self._config.get("scanner.jitter", 0)

        for attempt in range(retries + 1):
            try:
                # apply delay between requests
                if delay > 0 or jitter > 0:
                    wait = delay + (random.uniform(0, jitter) if jitter else 0)
                    if wait > 0:
                        await asyncio.sleep(wait)

                start_time = time.monotonic()

                async with self._session.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    proxy=self._proxy,
                    ssl=False,
                ) as resp:
                    body = await resp.text(errors="ignore")
                    elapsed = time.monotonic() - start_time

                    response = HTTPResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url),
                        elapsed=elapsed,
                        content_length=len(body),
                        content_type=resp.content_type or "",
                    )

                    self._request_count += 1

                    if use_cache:
                        self._cache[cache_key] = response

                    return response

            except asyncio.TimeoutError:
                if attempt < retries:
                    self._logger.debug(f"timeout on {url}, retry {attempt + 1}/{retries}")
                    await asyncio.sleep(1 * (attempt + 1))
                else:
                    return HTTPResponse(
                        url=url,
                        error=f"timeout after {retries + 1} attempts",
                    )

            except aiohttp.ClientError as e:
                if attempt < retries:
                    self._logger.debug(f"error on {url}: {e}, retry {attempt + 1}/{retries}")
                    await asyncio.sleep(1 * (attempt + 1))
                else:
                    return HTTPResponse(
                        url=url,
                        error=f"request failed: {e}",
                    )

            except Exception as e:
                return HTTPResponse(
                    url=url,
                    error=f"unexpected error: {e}",
                )

        return HTTPResponse(url=url, error="max retries exceeded")

    async def get(self, url: str, **kwargs: Any) -> HTTPResponse:
        """shortcut for GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HTTPResponse:
        """shortcut for POST request."""
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HTTPResponse:
        """shortcut for HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> HTTPResponse:
        """shortcut for OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)

    @property
    def request_count(self) -> int:
        return self._request_count

    async def __aenter__(self) -> HTTPEngine:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()

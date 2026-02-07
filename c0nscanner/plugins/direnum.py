"""directory enumeration scanner plugin for c0nscanner.

discovers hidden files and directories via wordlist-based brute force.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from c0nscanner.core.http_engine import HTTPEngine, HTTPResponse
from c0nscanner.core.target import Target
from c0nscanner.plugins.base import BasePlugin, Finding
from c0nscanner.utils.helpers import load_payloads


# only report these status codes as real hits
FOUND_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403}

# status codes indicating potentially sensitive resources
SENSITIVE_CODES = {200, 204}

# minimum body size (bytes) to consider a response real content
MIN_BODY_SIZE = 20

# patterns that indicate a soft-404 / generic error page
SOFT_404_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"page\s*not\s*found",
        r"404\s*not\s*found",
        r"not\s*found",
        r"does\s*not\s*exist",
        r"no\s*such\s*(page|file|resource)",
        r"cannot\s+be\s+found",
        r"the\s+requested\s+url\s+was\s+not\s+found",
        r"<title>[^<]*404[^<]*</title>",
        r"<title>[^<]*not found[^<]*</title>",
    ]
]

# interesting paths that warrant higher severity
SENSITIVE_PATHS = {
    ".env": ("critical", "environment file with potential secrets"),
    ".git/config": ("high", "git repository exposed"),
    ".git/HEAD": ("high", "git repository exposed"),
    ".htpasswd": ("critical", "htpasswd file with credentials"),
    ".htaccess": ("medium", "htaccess configuration exposed"),
    "wp-admin": ("info", "wordpress admin panel"),
    "phpmyadmin": ("high", "phpmyadmin database manager"),
    "adminer": ("high", "adminer database manager"),
    "phpinfo.php": ("medium", "phpinfo page exposes server details"),
    "info.php": ("medium", "phpinfo page exposes server details"),
    "server-status": ("medium", "apache server status page"),
    "backup": ("high", "backup directory found"),
    "backups": ("high", "backup directory found"),
    "database": ("high", "database directory found"),
    "dump": ("high", "database dump found"),
    ".DS_Store": ("low", "macos metadata file"),
    "robots.txt": ("info", "robots.txt file found"),
    "sitemap.xml": ("info", "sitemap.xml file found"),
    "config.php": ("high", "configuration file exposed"),
    "config.json": ("medium", "configuration file exposed"),
    "config.yml": ("medium", "configuration file exposed"),
    ".svn/entries": ("high", "svn repository exposed"),
    "docker-compose.yml": ("medium", "docker compose file exposed"),
    "Dockerfile": ("medium", "dockerfile exposed"),
    "package.json": ("low", "package.json exposes dependencies"),
    "composer.json": ("low", "composer.json exposes dependencies"),
    "swagger": ("info", "swagger api documentation"),
    "graphql": ("info", "graphql endpoint found"),
    "console": ("high", "debug console found"),
}


class DirEnumPlugin(BasePlugin):
    """directory and file enumeration scanner."""

    name = "direnum"
    description = "directory/file enumeration with wordlist"
    default_severity = "info"

    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        findings: list[Finding] = []

        # verify target is alive before brute-forcing
        probe = await http.get(target.base_url, use_cache=True)
        if probe.error or probe.content_length == 0:
            return findings

        config = self._module_config
        max_entries = config.get("max_entries", 500)
        extensions = config.get("extensions", [])

        # load wordlist
        wordlist = load_payloads("dirs_common.txt", max_entries)
        if not wordlist:
            self.logger.warning("direnum: no wordlist found")
            return findings

        # build full path list with extensions
        paths = list(wordlist)
        for word in wordlist:
            if "." not in word:
                for ext in extensions:
                    paths.append(f"{word}{ext}")

        # deduplicate
        paths = list(dict.fromkeys(paths))

        # build a robust 404 baseline using multiple probes
        # include the target's own response to detect SPAs that serve the
        # same shell/page for every path (e.g. netflix, react apps)
        baseline = await self._build_baseline(target, http, probe)

        # scan in batches
        batch_size = 20
        for i in range(0, len(paths), batch_size):
            batch = paths[i:i + batch_size]
            tasks = [
                self._check_path(target, path, http, baseline)
                for path in batch
            ]
            results = await asyncio.gather(*tasks)

            for result in results:
                if result:
                    findings.append(result)

        return findings

    async def _build_baseline(
        self, target: Target, http: HTTPEngine, homepage: HTTPResponse
    ) -> dict:
        """probe several fake paths to build a comprehensive fingerprint of
        what 'not found' / 'blocked' / 'redirect' looks like on this server.

        we use diverse probe types to catch every flavour of generic response:
          - regular paths   → catches custom 404 pages, blanket redirects
          - dotfile paths   → catches nginx/apache dotfile blocking rules

        we also store the homepage response to detect SPAs that serve the
        same shell for every route (e.g. react/next.js apps).
        """
        base = target.base_url.rstrip("/")
        all_probes = [
            # regular paths (different extensions)
            f"{base}/c0n_notfound_xz91a",
            f"{base}/c0n_notfound_qw47b.html",
            f"{base}/c0n_notfound_mk28c.php",
            # dotfile paths
            f"{base}/.c0n_notfound_dot_a",
            f"{base}/.c0n_notfound_dot_b",
        ]

        # per-status fingerprints: group response hashes + lengths by status
        # so we can compare any real response against its same-status baseline
        status_fingerprints: dict[int, dict] = {}
        redirect_targets: set[str] = set()
        all_statuses: set[int] = set()
        all_hashes: set[str] = set()

        for probe_url in all_probes:
            resp = await http.get(probe_url, allow_redirects=False)
            if resp.error:
                continue

            status = resp.status
            all_statuses.add(status)
            all_hashes.add(resp.body_hash)

            # accumulate per-status fingerprint
            if status not in status_fingerprints:
                status_fingerprints[status] = {
                    "hashes": set(),
                    "lengths": [],
                }
            status_fingerprints[status]["hashes"].add(resp.body_hash)
            status_fingerprints[status]["lengths"].append(resp.content_length)

            # track redirect destinations
            if status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if location:
                    redirect_targets.add(self._normalize_redirect(location, target))

        # compute per-status averages and tolerances
        for fp in status_fingerprints.values():
            lengths = fp["lengths"]
            avg = sum(lengths) / len(lengths) if lengths else 0
            fp["avg_length"] = avg
            fp["tolerance"] = max(100, avg * 0.15) if avg else 100

        # blanket status: if ALL probes returned the exact same status code
        blanket_status = all_statuses.copy() if len(all_statuses) == 1 else set()

        # SPA / homepage fingerprint: store the target page's response so
        # we can detect when a discovered path is just the same SPA shell.
        # use a generous tolerance (0.5% of body size, min 500b) because
        # SPAs often inject tiny dynamic tokens/nonces that vary per request.
        hp_length = homepage.content_length if homepage else 0
        hp_hash = homepage.body_hash if homepage else ""
        hp_tolerance = max(500, hp_length * 0.005) if hp_length else 500

        return {
            "status_fingerprints": status_fingerprints,
            "redirect_targets": redirect_targets,
            "all_statuses": all_statuses,
            "all_hashes": all_hashes,
            "blanket_status": blanket_status,
            "homepage_hash": hp_hash,
            "homepage_length": hp_length,
            "homepage_tolerance": hp_tolerance,
        }

    @staticmethod
    def _normalize_redirect(location: str, target: Target) -> str:
        """extract the path from a redirect location for comparison."""
        if location.startswith(("http://", "https://")):
            parsed = urlparse(location)
            return parsed.path.rstrip("/") or "/"
        return location.rstrip("/") or "/"

    def _is_false_redirect(
        self, resp: HTTPResponse, path: str, target: Target, baseline: dict
    ) -> bool:
        """detect redirect-based false positives."""
        if resp.status not in (301, 302, 303, 307, 308):
            return False

        # if baseline probes produced the same redirect status, it's blanket
        if self._matches_baseline(resp, baseline):
            return True

        location = resp.headers.get("Location", "")
        if not location:
            return True  # redirect with no location header is useless

        norm_location = self._normalize_redirect(location, target)

        # trailing-slash redirect: /admin -> /admin/  (not a real finding)
        requested_path = f"/{path}".rstrip("/")
        if norm_location == f"{requested_path}/":
            return True

        # redirects to the homepage / root — catch-all redirect
        if norm_location in ("/", "", "/index.html", "/index.php", "/home"):
            return True

        # redirects to the same place the 404 baseline redirects to
        if norm_location in baseline.get("redirect_targets", set()):
            return True

        # redirect to a generic login/error page
        lower_loc = norm_location.lower()
        if any(seg in lower_loc for seg in ("/login", "/signin", "/404", "/error", "/not-found")):
            return True

        return False

    def _matches_baseline(self, resp: HTTPResponse, baseline: dict) -> bool:
        """check if a response matches the baseline fingerprint for its status.

        this is the universal filter — checks two things:
        1. per-status probe fingerprint: if fake probes returned the same
           status with similar body, the server gives this to everything.
        2. homepage fingerprint: if the response is the same size/hash as
           the target homepage, it's an SPA serving the same shell for
           every route (react, next.js, angular, etc).
        """
        # --- check 1: per-status probe fingerprint ---
        fps = baseline.get("status_fingerprints", {})
        fp = fps.get(resp.status)
        if fp:
            # exact body match
            if resp.body_hash in fp.get("hashes", set()):
                return True

            # body length within tolerance of the baseline average
            avg = fp.get("avg_length", 0)
            tol = fp.get("tolerance", 100)
            if avg and abs(resp.content_length - avg) < tol:
                return True

        # --- check 2: SPA / homepage fingerprint ---
        # if this response looks like the homepage (same hash or ~same size),
        # it's the SPA shell being served for an unknown client-side route.
        if resp.status in SENSITIVE_CODES:
            hp_hash = baseline.get("homepage_hash", "")
            if hp_hash and resp.body_hash == hp_hash:
                return True

            hp_length = baseline.get("homepage_length", 0)
            hp_tol = baseline.get("homepage_tolerance", 500)
            if hp_length and abs(resp.content_length - hp_length) < hp_tol:
                return True

        return False

    def _is_soft_404(self, resp: HTTPResponse, baseline: dict) -> bool:
        """detect soft-404 pages that return 200 but contain 'not found' content."""
        # matches any baseline fingerprint (hash or size)
        if self._matches_baseline(resp, baseline):
            return True

        # body contains obvious "not found" language
        for pattern in SOFT_404_PATTERNS:
            if pattern.search(resp.body[:4000]):
                return True

        return False

    async def _check_path(
        self,
        target: Target,
        path: str,
        http: HTTPEngine,
        baseline: dict,
    ) -> Finding | None:
        """check if a specific path exists on the target."""
        url = f"{target.base_url.rstrip('/')}/{path}"
        resp = await http.get(url, allow_redirects=False)

        if resp.error:
            return None

        if resp.status not in FOUND_CODES:
            return None

        # --- false positive filters ---

        # UNIVERSAL CHECK: compare this response against the per-status
        # baseline fingerprint. if a fake probe returned the same status
        # with a matching body hash or similar size, it's a generic response.
        if self._matches_baseline(resp, baseline):
            return None

        # drop empty / near-empty responses
        if resp.content_length < MIN_BODY_SIZE and resp.status in SENSITIVE_CODES:
            return None

        # drop false redirects (trailing-slash, catch-all, login bounces)
        if self._is_false_redirect(resp, path, target, baseline):
            return None

        # drop soft-404 pages
        if resp.status in SENSITIVE_CODES and self._is_soft_404(resp, baseline):
            return None

        # for 403/401 — only report for known-sensitive paths
        if resp.status in (401, 403):
            if path.lower() not in {k.lower() for k in SENSITIVE_PATHS}:
                return None

        # --- classify the finding ---

        severity = "info"
        desc = f"path found: /{path} (status: {resp.status})"

        for sensitive_path, (sev, sdesc) in SENSITIVE_PATHS.items():
            if path.lower() == sensitive_path.lower() or path.lower().endswith(f"/{sensitive_path.lower()}"):
                severity = sev
                desc = sdesc
                break

        # 403/401 means access is BLOCKED — downgrade severity since
        # we cannot confirm the resource actually exists or is exposed.
        if resp.status in (401, 403):
            desc = f"access blocked: /{path} (server returned {resp.status})"
            severity = "info"

        # boost severity for 200 responses on sensitive file types
        if resp.status in SENSITIVE_CODES:
            if any(path.endswith(ext) for ext in [".env", ".bak", ".old", ".sql", ".dump"]):
                severity = "high"
                desc = f"sensitive file accessible: /{path}"
            elif any(path.endswith(ext) for ext in [".conf", ".config", ".ini", ".yml", ".yaml"]):
                severity = "medium"
                desc = f"configuration file accessible: /{path}"

        return self.make_finding(
            title=f"discovered: /{path}",
            url=url,
            severity=severity,
            evidence=f"{desc} | status: {resp.status} | size: {resp.content_length}b",
            remediation="restrict access to sensitive files and directories. "
                        "ensure proper access controls and remove unnecessary files from production.",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
            ],
        )

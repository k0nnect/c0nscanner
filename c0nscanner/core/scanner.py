"""main scanner orchestrator for c0nscanner.

coordinates target parsing, plugin loading, concurrent scanning,
and report generation.
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from c0nscanner import __version__
from c0nscanner.config import Config
from c0nscanner.core.auth import AuthManager
from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target, parse_targets
from c0nscanner.plugins.base import BasePlugin, Finding, load_plugins
from c0nscanner.reporters.html_reporter import HTMLReporter
from c0nscanner.reporters.json_reporter import JSONReporter
from c0nscanner.reporters.text_reporter import TextReporter
from c0nscanner.utils.colors import (
    console,
    print_divider,
    print_error,
    print_header,
    print_info,
    print_success,
    print_warning,
)
from c0nscanner.utils.helpers import format_duration, get_domain, normalize_url
from c0nscanner.utils.logger import get_logger, setup_logger

# default output directory for all scan reports
SCANS_DIR = Path("scans")


class Scanner:
    """main scanner orchestrator.

    manages the full scan lifecycle: target parsing, plugin loading,
    concurrent vulnerability scanning, and report generation.
    """

    def __init__(
        self,
        config: Config,
        targets: list[str],
        domain: str | None = None,
        enabled_modules: list[str] | None = None,
        custom_headers: dict[str, str] | None = None,
        output_path: str | None = None,
    ) -> None:
        self.config = config
        self.raw_targets = targets
        self.domain = domain
        self.enabled_modules = enabled_modules
        self.custom_headers = custom_headers or {}
        self.output_path = output_path
        self.findings: list[Finding] = []
        self._start_time: float = 0
        self._end_time: float = 0

    async def run(self) -> list[Finding]:
        """execute the full scan pipeline."""
        # setup logging
        logger = setup_logger(verbose=self.config.verbose)

        self._start_time = time.monotonic()
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S utc")

        # parse targets
        print_header("target analysis")
        targets = parse_targets(self.raw_targets)
        print_info(f"parsed {len(targets)} unique target(s)")
        for t in targets:
            print_info(f"  -> {t.url}")
            if t.is_parameterized:
                print_info(f"     params: {', '.join(t.param_names)}")

        # load plugins
        print_header("loading modules")
        plugins = load_plugins(self.config, self.enabled_modules)
        if not plugins:
            print_error("no modules loaded. check your config or --modules flag.")
            return []

        for p in plugins:
            print_info(f"  [{p.name}] {p.description}")

        print_info(f"loaded {len(plugins)} module(s)")

        # initialize http engine
        auth_config = self.config.get("auth", {})
        auth = AuthManager(auth_config, self.custom_headers)
        if auth.is_authenticated:
            print_info(f"authentication: {auth}")

        http = HTTPEngine(self.config, auth)
        await http.start()

        try:
            # reachability check — probe each target before scanning
            print_header("reachability check")
            reachable_targets: list[Target] = []
            for target in targets:
                alive = await self._check_reachable(target, http)
                if alive:
                    reachable_targets.append(target)

            if not reachable_targets:
                print_error("no reachable targets. nothing to scan.")
                return []

            targets = reachable_targets

            # run scans
            print_header("scanning")
            total_tasks = len(targets) * len(plugins)
            print_info(f"running {total_tasks} scan tasks ({len(targets)} targets x {len(plugins)} modules)")
            print_divider()

            all_findings: list[Finding] = []

            for target in targets:
                print_info(f"scanning: {target.url}")
                target_findings = await self._scan_target(target, plugins, http)
                all_findings.extend(target_findings)

                if target_findings:
                    print_warning(f"  found {len(target_findings)} issue(s)")
                else:
                    print_success(f"  no issues found")

            self.findings = all_findings
            self._end_time = time.monotonic()
            duration = self._end_time - self._start_time
            finished_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S utc")

            # build metadata
            metadata: dict[str, Any] = {
                "version": __version__,
                "targets": [t.url for t in targets],
                "modules": [p.name for p in plugins],
                "started": started_at,
                "finished": finished_at,
                "duration": format_duration(duration),
                "requests": http.request_count,
            }

            # generate reports
            print_header("report generation")
            self._generate_reports(all_findings, metadata)

            # print live summary
            text_reporter = TextReporter()
            text_reporter.print_live(all_findings, metadata)

            return all_findings

        finally:
            await http.stop()

    async def _scan_target(
        self,
        target: Target,
        plugins: list[BasePlugin],
        http: HTTPEngine,
    ) -> list[Finding]:
        """run all plugins against a single target."""
        findings: list[Finding] = []
        logger = get_logger()

        # run plugins concurrently (respecting semaphore in http engine)
        tasks = []
        for plugin in plugins:
            tasks.append(self._run_plugin(plugin, target, http))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for plugin, result in zip(plugins, results):
            if isinstance(result, Exception):
                logger.error(f"  [{plugin.name}] error: {result}")
            elif isinstance(result, list):
                findings.extend(result)
                if result:
                    for finding in result:
                        severity = finding.severity.upper()
                        console.print(
                            f"    [{severity}] {finding.title}",
                            style=severity.lower() if severity.lower() in {
                                "critical", "high", "medium", "low", "info"
                            } else "info",
                        )

        return findings

    async def _run_plugin(
        self,
        plugin: BasePlugin,
        target: Target,
        http: HTTPEngine,
    ) -> list[Finding]:
        """run a single plugin with error handling."""
        logger = get_logger()
        try:
            logger.debug(f"  running [{plugin.name}] on {target.url}")
            return await plugin.scan(target, http)
        except Exception as e:
            logger.error(f"  [{plugin.name}] failed: {e}")
            return []

    async def _check_reachable(
        self, target: Target, http: HTTPEngine
    ) -> bool:
        """verify a target is alive and returning real content.

        rejects targets that:
          - fail to connect / time out
          - return 0-byte bodies
          - return domain-parking / default-host pages
          - return the same page for any random path (catch-all wildcard)
        """
        logger = get_logger()

        # 1. basic connectivity
        resp = await http.get(target.url)
        if resp.error:
            print_warning(f"  [-] {target.url} — unreachable ({resp.error})")
            return False

        if resp.status == 0:
            print_warning(f"  [-] {target.url} — no response")
            return False

        # 2. reject empty responses
        if resp.content_length == 0:
            print_warning(f"  [-] {target.url} — empty response (0 bytes)")
            return False

        # 3. store the baseline response on the target for plugins to use
        target._baseline = resp  # type: ignore[attr-defined]

        # 4. wildcard / catch-all detection — request a random path and
        #    compare to the real page.  if they're identical the server
        #    serves the same thing for every url and results are meaningless.
        import random, string
        random_slug = "".join(random.choices(string.ascii_lowercase, k=12))
        wildcard_url = f"{target.base_url}/{random_slug}"
        wildcard_resp = await http.get(wildcard_url)

        if not wildcard_resp.error and wildcard_resp.status == 200:
            # same body hash = wildcard host / catch-all
            if wildcard_resp.body_hash == resp.body_hash:
                print_warning(
                    f"  [-] {target.url} — wildcard/catch-all detected "
                    f"(random path returns identical page)"
                )
                return False

        print_success(f"  [+] {target.url} — alive (status {resp.status}, {resp.content_length}b)")
        return True

    def _resolve_output_path(self) -> Path:
        """build the output file path inside the scans/ directory.

        if the user passed -o, that name is used as the file stem.
        otherwise a name is auto-generated from the target domain + timestamp.
        reports always land inside the scans/ folder.
        """
        # derive a safe name from the first target domain
        domain_slug = "scan"
        if self.raw_targets:
            raw = self.raw_targets[0]
            dom = get_domain(raw) or raw
            # keep only alphanumerics, dots, hyphens
            domain_slug = re.sub(r"[^a-zA-Z0-9.\-]", "_", dom)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if self.output_path:
            # user gave an explicit name — use it, but still put inside scans/
            stem = Path(self.output_path).stem
            scan_dir = SCANS_DIR / f"{stem}_{timestamp}"
        else:
            scan_dir = SCANS_DIR / f"{domain_slug}_{timestamp}"

        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir / "report"

    def _generate_reports(
        self,
        findings: list[Finding],
        metadata: dict[str, Any],
    ) -> None:
        """generate output reports based on config."""
        output_format = self.config.output_format
        output_path = self._resolve_output_path()

        reporters: list[tuple[str, Any]] = []

        if output_format == "all":
            reporters = [
                ("json", JSONReporter()),
                ("html", HTMLReporter()),
                ("text", TextReporter()),
            ]
        elif output_format == "json":
            reporters = [("json", JSONReporter())]
        elif output_format == "html":
            reporters = [("html", HTMLReporter())]
        else:
            reporters = [("text", TextReporter())]

        for name, reporter in reporters:
            try:
                filepath = reporter.save(findings, metadata, str(output_path))
                print_success(f"saved {name} report: {filepath}")
            except Exception as e:
                print_error(f"failed to save {name} report: {e}")

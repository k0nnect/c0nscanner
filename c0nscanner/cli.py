"""cli interface for c0nscanner."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from c0nscanner import __version__
from c0nscanner.config import Config
from c0nscanner.utils.colors import console, print_banner, print_info, print_error


BANNER = r"""
   _____ ___  _ __  ___  ___ __ _ _ __  _ __   ___ _ __
  / __/ _ \| '_ \/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
 | (_| (_) | | | \__ \ (_| (_| | | | | | | |  __/ |
  \___\___/|_| |_|___/\___\__,_|_| |_|_| |_|\___|_|
                                        v{version}
        [ web vulnerability scanner ]
              github.com/k0nnect
""".format(version=__version__)


def show_banner() -> None:
    """display the c0nscanner banner."""
    print_banner(BANNER)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("-u", "--url", type=str, default=None, help="target url to scan")
@click.option("-l", "--list", "url_list", type=click.Path(exists=True), default=None, help="file containing list of urls")
@click.option("-d", "--domain", type=str, default=None, help="target domain for full scan")
@click.option("--modules", type=str, default=None, help="comma-separated modules to run (default: all)")
@click.option("--threads", type=int, default=None, help="number of concurrent threads (1-50)")
@click.option("--stealth", is_flag=True, default=False, help="enable stealth mode (slow, single-threaded)")
@click.option("--aggressive", is_flag=True, default=False, help="enable aggressive mode (fast, all payloads)")
@click.option("-o", "--output", type=str, default=None, help="report name (saved in scans/ folder)")
@click.option("--format", "output_format", type=click.Choice(["json", "html", "text", "all"], case_sensitive=False), default=None, help="output format")
@click.option("--config", "config_file", type=click.Path(exists=True), default=None, help="custom config yaml file")
@click.option("--cookie", type=str, default=None, help="session cookie string")
@click.option("--header", type=(str, str), multiple=True, default=None, help="custom header (name value)")
@click.option("--auth-type", type=click.Choice(["basic", "bearer", "cookie"], case_sensitive=False), default=None, help="authentication type")
@click.option("--auth-cred", type=str, default=None, help="auth credentials (user:pass for basic, token for bearer)")
@click.option("--proxy", type=str, default=None, help="proxy url (e.g. http://127.0.0.1:8080)")
@click.option("-v", "--verbose", is_flag=True, default=False, help="enable verbose output")
@click.option("--no-color", is_flag=True, default=False, help="disable colored output")
@click.option("--timeout", type=int, default=None, help="request timeout in seconds")
@click.option("--delay", type=float, default=None, help="delay between requests in seconds")
@click.option("--retries", type=int, default=None, help="number of retries per request")
@click.option("--version", is_flag=True, default=False, help="show version and exit")
def main(
    url: str | None,
    url_list: str | None,
    domain: str | None,
    modules: str | None,
    threads: int | None,
    stealth: bool,
    aggressive: bool,
    output: str | None,
    output_format: str | None,
    config_file: str | None,
    cookie: str | None,
    header: tuple[tuple[str, str], ...] | None,
    auth_type: str | None,
    auth_cred: str | None,
    proxy: str | None,
    verbose: bool,
    no_color: bool,
    timeout: int | None,
    delay: float | None,
    retries: int | None,
    version: bool,
) -> None:
    """c0nscanner - a comprehensive web vulnerability scanner.

    scan websites for sql injection, xss, command injection, lfi/rfi,
    ssrf, security header issues, directory enumeration, cors misconfig,
    open redirects, csrf, and information disclosure vulnerabilities.

    \b
    examples:
      c0nscanner -u "https://example.com/page?id=1"
      c0nscanner -d example.com --aggressive -o report --format all
      c0nscanner -u "https://example.com" --modules sqli,xss,headers
      c0nscanner -l urls.txt --threads 20 --format json -o results
    """
    if version:
        console.print(f"c0nscanner v{__version__}")
        sys.exit(0)

    show_banner()

    # validate that at least one target is provided
    if not url and not url_list and not domain:
        print_error("no target specified. use -u, -l, or -d to set a target.")
        print_info("run 'c0nscanner -h' for usage information.")
        sys.exit(1)

    # build config
    config = Config()

    if config_file:
        try:
            config.load_file(config_file)
            print_info(f"loaded config from {config_file}")
        except FileNotFoundError as e:
            print_error(str(e))
            sys.exit(1)

    # apply profile first, then specific overrides
    if stealth and aggressive:
        print_error("cannot use --stealth and --aggressive together.")
        sys.exit(1)

    if stealth:
        config.apply_profile("stealth")
        print_info("stealth mode enabled")
    elif aggressive:
        config.apply_profile("aggressive")
        print_info("aggressive mode enabled")

    # apply cli overrides
    overrides: dict[str, object] = {}
    if threads is not None:
        overrides["scanner.threads"] = max(1, min(50, threads))
    if timeout is not None:
        overrides["scanner.timeout"] = timeout
    if delay is not None:
        overrides["scanner.delay"] = delay
    if retries is not None:
        overrides["scanner.retries"] = retries
    if verbose:
        overrides["output.verbose"] = True
    if no_color:
        overrides["output.colors"] = False
    if output_format:
        overrides["output.format"] = output_format
    if proxy:
        overrides["proxy.url"] = proxy
    if cookie:
        overrides["auth.cookie"] = cookie
        overrides["auth.type"] = "cookie"
    if auth_type:
        overrides["auth.type"] = auth_type
    if auth_cred:
        overrides["auth.credentials"] = auth_cred

    config.apply_overrides(overrides)

    # parse custom headers
    custom_headers: dict[str, str] = {}
    if header:
        for name, value in header:
            custom_headers[name] = value

    # determine which modules to run
    enabled_modules: list[str] | None = None
    if modules:
        enabled_modules = [m.strip().lower() for m in modules.split(",")]
        print_info(f"modules: {', '.join(enabled_modules)}")

    # collect targets
    targets: list[str] = []
    if url:
        targets.append(url)
    if url_list:
        try:
            with open(url_list, "r", encoding="utf-8") as f:
                targets.extend(line.strip() for line in f if line.strip())
            print_info(f"loaded {len(targets)} targets from {url_list}")
        except Exception as e:
            print_error(f"failed to read url list: {e}")
            sys.exit(1)
    if domain:
        targets.append(domain)

    print_info(f"targets: {len(targets)}")
    print_info(f"threads: {config.threads}")
    print_info(f"timeout: {config.timeout}s")
    if proxy:
        print_info(f"proxy: {proxy}")

    # run the scanner
    from c0nscanner.core.scanner import Scanner

    scanner = Scanner(
        config=config,
        targets=targets,
        domain=domain,
        enabled_modules=enabled_modules,
        custom_headers=custom_headers,
        output_path=output,
    )

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print_error("\nscan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print_error(f"scan failed: {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)

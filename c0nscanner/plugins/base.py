"""base plugin class and finding model for c0nscanner."""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from c0nscanner.config import Config
from c0nscanner.core.http_engine import HTTPEngine
from c0nscanner.core.target import Target
from c0nscanner.utils.logger import get_logger


@dataclass
class Finding:
    """represents a discovered vulnerability."""

    plugin: str
    severity: str  # critical, high, medium, low, info
    title: str
    url: str
    parameter: str | None = None
    payload: str | None = None
    evidence: str = ""
    remediation: str = ""
    cvss: float | None = None
    references: list[str] = field(default_factory=list)

    @property
    def severity_order(self) -> int:
        """numeric severity for sorting (lower = more severe)."""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(self.severity.lower(), 5)

    def to_dict(self) -> dict[str, Any]:
        """convert finding to a dictionary."""
        return {
            "plugin": self.plugin,
            "severity": self.severity,
            "title": self.title,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss": self.cvss,
            "references": self.references,
        }


class BasePlugin(ABC):
    """abstract base class for all scanner plugins.

    subclasses must implement the scan() method and set the
    class-level name, description, and default_severity attributes.
    """

    name: str = "base"
    description: str = "base plugin"
    default_severity: str = "info"

    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = get_logger()
        self._module_config = config.module_config(self.name)

    @abstractmethod
    async def scan(self, target: Target, http: HTTPEngine) -> list[Finding]:
        """run the vulnerability scan against a target.

        returns a list of findings (empty if no vulnerabilities found).
        """
        ...

    def is_enabled(self) -> bool:
        """check if this plugin is enabled in config."""
        return self.config.is_module_enabled(self.name)

    def get_payloads(self, filename: str, max_payloads: int = 0) -> list[str]:
        """load payloads from a bundled payload file."""
        from c0nscanner.utils.helpers import load_payloads
        limit = max_payloads or self._module_config.get("max_payloads", 0)
        return load_payloads(filename, limit)

    def make_finding(
        self,
        title: str,
        url: str,
        severity: str | None = None,
        **kwargs: Any,
    ) -> Finding:
        """helper to create a finding with plugin name pre-filled."""
        return Finding(
            plugin=self.name,
            severity=severity or self.default_severity,
            title=title,
            url=url,
            **kwargs,
        )

    def __repr__(self) -> str:
        return f"<Plugin:{self.name}>"


def discover_plugins() -> list[type[BasePlugin]]:
    """auto-discover all plugin classes in the plugins package.

    scans the plugins directory for modules, imports them, and
    collects all BasePlugin subclasses.
    """
    plugins: list[type[BasePlugin]] = []
    package_path = Path(__file__).resolve().parent

    for importer, modname, ispkg in pkgutil.iter_modules([str(package_path)]):
        if modname == "base":
            continue
        try:
            module = importlib.import_module(f"c0nscanner.plugins.{modname}")
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BasePlugin)
                    and attr is not BasePlugin
                    and not attr.__name__.startswith("_")
                ):
                    plugins.append(attr)
        except ImportError as e:
            logger = get_logger()
            logger.warning(f"failed to load plugin {modname}: {e}")

    return plugins


def load_plugins(
    config: Config,
    enabled_modules: list[str] | None = None,
) -> list[BasePlugin]:
    """discover, filter, and instantiate plugins.

    if enabled_modules is provided, only those modules are loaded.
    otherwise, all enabled modules (per config) are loaded.
    """
    plugin_classes = discover_plugins()
    instances: list[BasePlugin] = []

    for cls in plugin_classes:
        plugin = cls(config)
        if enabled_modules is not None:
            if plugin.name in enabled_modules:
                instances.append(plugin)
        elif plugin.is_enabled():
            instances.append(plugin)

    return instances

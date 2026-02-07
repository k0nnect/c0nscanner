"""configuration management for c0nscanner.

supports layered config: defaults -> yaml file -> cli overrides.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml


_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"


def _deep_merge(base: dict, override: dict) -> dict:
    """recursively merge override into base, returning a new dict."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _load_yaml(path: Path) -> dict:
    """load a yaml file and return its contents as a dict."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


class Config:
    """layered configuration manager.

    priority (highest wins): cli overrides > user config file > defaults.
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        """load the bundled default config."""
        if _DEFAULT_CONFIG_PATH.exists():
            self._data = _load_yaml(_DEFAULT_CONFIG_PATH)
        else:
            self._data = {}

    def load_file(self, path: str | Path) -> None:
        """merge a user-provided yaml config file on top of defaults."""
        user_path = Path(path)
        if not user_path.exists():
            raise FileNotFoundError(f"config file not found: {user_path}")
        user_data = _load_yaml(user_path)
        self._data = _deep_merge(self._data, user_data)

    def apply_overrides(self, overrides: dict[str, Any]) -> None:
        """apply cli flag overrides on top of current config.

        overrides use dot-notation keys flattened into nested dicts.
        example: {"scanner.threads": 20} -> {"scanner": {"threads": 20}}
        """
        nested = {}
        for key, value in overrides.items():
            if value is None:
                continue
            parts = key.split(".")
            current = nested
            for part in parts[:-1]:
                current = current.setdefault(part, {})
            current[parts[-1]] = value
        self._data = _deep_merge(self._data, nested)

    def get(self, key: str, default: Any = None) -> Any:
        """get a config value using dot-notation.

        example: config.get("scanner.threads") -> 10
        """
        parts = key.split(".")
        current: Any = self._data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def set(self, key: str, value: Any) -> None:
        """set a config value using dot-notation."""
        parts = key.split(".")
        current = self._data
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value

    @property
    def data(self) -> dict[str, Any]:
        """return the full config dict."""
        return copy.deepcopy(self._data)

    @property
    def threads(self) -> int:
        return self.get("scanner.threads", 10)

    @property
    def timeout(self) -> int:
        return self.get("scanner.timeout", 30)

    @property
    def delay(self) -> float:
        return self.get("scanner.delay", 0)

    @property
    def user_agent(self) -> str:
        return self.get("scanner.user_agent", "c0nscanner/1.0")

    @property
    def follow_redirects(self) -> bool:
        return self.get("scanner.follow_redirects", True)

    @property
    def retries(self) -> int:
        return self.get("scanner.retries", 3)

    @property
    def output_format(self) -> str:
        return self.get("output.format", "text")

    @property
    def verbose(self) -> bool:
        return self.get("output.verbose", False)

    @property
    def colors(self) -> bool:
        return self.get("output.colors", True)

    def is_module_enabled(self, module_name: str) -> bool:
        """check if a specific scan module is enabled."""
        return self.get(f"modules.{module_name}.enabled", True)

    def module_config(self, module_name: str) -> dict[str, Any]:
        """get the full config dict for a specific module."""
        return self.get(f"modules.{module_name}", {})

    def apply_profile(self, profile: str) -> None:
        """apply a scan profile (stealth or aggressive)."""
        if profile == "stealth":
            stealth = self.get("stealth", {})
            if stealth:
                self.set("scanner.threads", stealth.get("threads", 1))
                self.set("scanner.delay", stealth.get("delay", 2))
                self.set("scanner.randomize_ua", stealth.get("randomize_ua", True))
                if "jitter" in stealth:
                    self.set("scanner.jitter", stealth["jitter"])
        elif profile == "aggressive":
            aggressive = self.get("aggressive", {})
            if aggressive:
                self.set("scanner.threads", aggressive.get("threads", 50))
                self.set("scanner.delay", aggressive.get("delay", 0))
                if aggressive.get("all_payloads"):
                    self.set("scanner.all_payloads", True)
                max_p = aggressive.get("max_payloads", 0)
                if max_p == 0:
                    # unlimited payloads for each module
                    for mod in self.get("modules", {}):
                        self.set(f"modules.{mod}.max_payloads", 99999)

    def __repr__(self) -> str:
        return f"Config({self._data})"

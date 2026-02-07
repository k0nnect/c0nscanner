"""base reporter class for c0nscanner."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from c0nscanner.plugins.base import Finding


class BaseReporter(ABC):
    """abstract base class for output reporters."""

    name: str = "base"
    extension: str = ".txt"

    @abstractmethod
    def generate(
        self,
        findings: list[Finding],
        metadata: dict[str, Any],
    ) -> str:
        """generate the report content as a string."""
        ...

    def save(
        self,
        findings: list[Finding],
        metadata: dict[str, Any],
        output_path: str,
    ) -> str:
        """generate and save the report to a file."""
        content = self.generate(findings, metadata)
        filepath = f"{output_path}{self.extension}"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

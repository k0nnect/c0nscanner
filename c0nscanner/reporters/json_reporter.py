"""json reporter for c0nscanner."""

from __future__ import annotations

import json
from typing import Any

from c0nscanner.plugins.base import Finding
from c0nscanner.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """generates json-formatted scan reports."""

    name = "json"
    extension = ".json"

    def generate(
        self,
        findings: list[Finding],
        metadata: dict[str, Any],
    ) -> str:
        report = {
            "scanner": "c0nscanner",
            "version": metadata.get("version", "1.0.0"),
            "scan": {
                "targets": metadata.get("targets", []),
                "modules": metadata.get("modules", []),
                "started": metadata.get("started", ""),
                "finished": metadata.get("finished", ""),
                "duration": metadata.get("duration", ""),
                "requests": metadata.get("requests", 0),
            },
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity == "critical"),
                "high": sum(1 for f in findings if f.severity == "high"),
                "medium": sum(1 for f in findings if f.severity == "medium"),
                "low": sum(1 for f in findings if f.severity == "low"),
                "info": sum(1 for f in findings if f.severity == "info"),
            },
            "findings": [f.to_dict() for f in sorted(findings, key=lambda x: x.severity_order)],
        }

        return json.dumps(report, indent=2, ensure_ascii=False)

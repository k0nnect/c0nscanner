"""text reporter for c0nscanner with rich terminal output."""

from __future__ import annotations

from typing import Any

from c0nscanner.plugins.base import Finding
from c0nscanner.reporters.base import BaseReporter
from c0nscanner.utils.colors import (
    console,
    print_divider,
    print_finding,
    print_header,
    print_info,
    print_success,
)


class TextReporter(BaseReporter):
    """generates plain text scan reports with optional color output."""

    name = "text"
    extension = ".txt"

    def generate(
        self,
        findings: list[Finding],
        metadata: dict[str, Any],
    ) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("=" * 64)
        lines.append("  c0nscanner scan report")
        lines.append("=" * 64)
        lines.append("")
        lines.append(f"  targets:   {', '.join(metadata.get('targets', []))}")
        lines.append(f"  modules:   {', '.join(metadata.get('modules', []))}")
        lines.append(f"  started:   {metadata.get('started', 'n/a')}")
        lines.append(f"  finished:  {metadata.get('finished', 'n/a')}")
        lines.append(f"  duration:  {metadata.get('duration', 'n/a')}")
        lines.append(f"  requests:  {metadata.get('requests', 0)}")
        lines.append("")

        # summary
        lines.append("-" * 64)
        lines.append("  summary")
        lines.append("-" * 64)

        severity_counts = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for f in findings:
            sev = f.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        lines.append(f"  total findings:  {len(findings)}")
        lines.append(f"  critical:        {severity_counts['critical']}")
        lines.append(f"  high:            {severity_counts['high']}")
        lines.append(f"  medium:          {severity_counts['medium']}")
        lines.append(f"  low:             {severity_counts['low']}")
        lines.append(f"  info:            {severity_counts['info']}")
        lines.append("")

        # findings grouped by severity
        sorted_findings = sorted(findings, key=lambda x: x.severity_order)

        if sorted_findings:
            lines.append("-" * 64)
            lines.append("  findings")
            lines.append("-" * 64)

            for i, finding in enumerate(sorted_findings, 1):
                lines.append("")
                lines.append(f"  [{finding.severity.upper()}] #{i}: {finding.title}")
                lines.append(f"    url:         {finding.url}")
                if finding.parameter:
                    lines.append(f"    parameter:   {finding.parameter}")
                if finding.payload:
                    lines.append(f"    payload:     {finding.payload}")
                if finding.evidence:
                    lines.append(f"    evidence:    {finding.evidence}")
                if finding.remediation:
                    lines.append(f"    remediation: {finding.remediation}")
                if finding.cvss is not None:
                    lines.append(f"    cvss:        {finding.cvss}")
                if finding.references:
                    lines.append(f"    references:")
                    for ref in finding.references:
                        lines.append(f"      - {ref}")
        else:
            lines.append("  no vulnerabilities found.")

        lines.append("")
        lines.append("=" * 64)
        lines.append("  scan complete. stay safe.")
        lines.append("=" * 64)
        lines.append("")

        return "\n".join(lines)

    def print_live(
        self,
        findings: list[Finding],
        metadata: dict[str, Any],
    ) -> None:
        """print the report to terminal with rich formatting."""
        print_header("scan results")

        severity_counts = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for f in findings:
            sev = f.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        print_info(f"total findings: {len(findings)}")
        if severity_counts["critical"]:
            print_finding("critical", f"{severity_counts['critical']} critical")
        if severity_counts["high"]:
            print_finding("high", f"{severity_counts['high']} high")
        if severity_counts["medium"]:
            print_finding("medium", f"{severity_counts['medium']} medium")
        if severity_counts["low"]:
            print_finding("low", f"{severity_counts['low']} low")
        if severity_counts["info"]:
            print_finding("info", f"{severity_counts['info']} info")

        if findings:
            print_header("detailed findings")
            sorted_findings = sorted(findings, key=lambda x: x.severity_order)

            for i, finding in enumerate(sorted_findings, 1):
                console.print()
                print_finding(
                    finding.severity,
                    f"#{i}: {finding.title}",
                )
                print_info(f"  url: {finding.url}")
                if finding.parameter:
                    print_info(f"  parameter: {finding.parameter}")
                if finding.payload:
                    print_info(f"  payload: {finding.payload}")
                if finding.evidence:
                    print_info(f"  evidence: {finding.evidence}")
                if finding.remediation:
                    print_info(f"  fix: {finding.remediation}")
        else:
            print_success("no vulnerabilities found.")

        print_divider()
        print_info(f"scan duration: {metadata.get('duration', 'n/a')}")
        print_info(f"total requests: {metadata.get('requests', 0)}")

"""html reporter for c0nscanner with styled template."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Template

from c0nscanner.plugins.base import Finding
from c0nscanner.reporters.base import BaseReporter


# inline html template for self-contained reports
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>c0nscanner report</title>
    <style>
        :root {
            --bg: #0a0a0f;
            --surface: #12121a;
            --border: #1e1e2e;
            --text: #c8c8d4;
            --text-dim: #6e6e82;
            --accent: #00d4aa;
            --critical: #ff3366;
            --high: #ff6644;
            --medium: #ffaa22;
            --low: #3388ff;
            --info: #6e6e82;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1100px; margin: 0 auto; }
        h1, h2, h3 { text-transform: lowercase; }
        h1 {
            color: var(--accent);
            font-size: 2rem;
            margin-bottom: 0.5rem;
            letter-spacing: 2px;
        }
        .subtitle {
            color: var(--text-dim);
            font-size: 0.85rem;
            margin-bottom: 2rem;
        }
        .meta {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .meta-item { font-size: 0.85rem; }
        .meta-label { color: var(--text-dim); }
        .meta-value { color: var(--accent); }
        .summary {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }
        .summary-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            text-align: center;
            min-width: 100px;
            flex: 1;
        }
        .summary-card .count {
            font-size: 2rem;
            font-weight: bold;
        }
        .summary-card .label {
            font-size: 0.75rem;
            text-transform: lowercase;
            color: var(--text-dim);
        }
        .severity-critical .count { color: var(--critical); }
        .severity-high .count { color: var(--high); }
        .severity-medium .count { color: var(--medium); }
        .severity-low .count { color: var(--low); }
        .severity-info .count { color: var(--info); }
        .severity-total .count { color: var(--accent); }
        .finding {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--border);
        }
        .finding.critical { border-left-color: var(--critical); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--medium); }
        .finding.low { border-left-color: var(--low); }
        .finding.info { border-left-color: var(--info); }
        .finding-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
        }
        .badge {
            display: inline-block;
            padding: 0.15rem 0.6rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .badge-critical { background: var(--critical); color: #fff; }
        .badge-high { background: var(--high); color: #fff; }
        .badge-medium { background: var(--medium); color: #000; }
        .badge-low { background: var(--low); color: #fff; }
        .badge-info { background: var(--info); color: #fff; }
        .finding-title { font-size: 1rem; font-weight: 600; }
        .finding-detail {
            font-size: 0.8rem;
            color: var(--text-dim);
            margin: 0.3rem 0;
        }
        .finding-detail span { color: var(--text); }
        .finding-evidence {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 0.75rem;
            margin-top: 0.75rem;
            font-size: 0.8rem;
            word-break: break-all;
        }
        .finding-fix {
            margin-top: 0.75rem;
            padding: 0.75rem;
            background: rgba(0, 212, 170, 0.05);
            border: 1px solid rgba(0, 212, 170, 0.15);
            border-radius: 4px;
            font-size: 0.8rem;
        }
        .fix-label { color: var(--accent); font-weight: bold; }
        .references { margin-top: 0.5rem; font-size: 0.75rem; }
        .references a { color: var(--accent); text-decoration: none; }
        .references a:hover { text-decoration: underline; }
        .footer {
            text-align: center;
            color: var(--text-dim);
            font-size: 0.75rem;
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }
        h2 {
            color: var(--accent);
            font-size: 1.2rem;
            margin: 2rem 0 1rem 0;
            letter-spacing: 1px;
        }
        .no-findings {
            text-align: center;
            padding: 3rem;
            color: var(--accent);
            font-size: 1.2rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>c0nscanner</h1>
        <p class="subtitle">web vulnerability scan report</p>

        <div class="meta">
            <div class="meta-item">
                <div class="meta-label">targets</div>
                <div class="meta-value">{{ targets | join(', ') }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">modules</div>
                <div class="meta-value">{{ modules | join(', ') }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">started</div>
                <div class="meta-value">{{ started }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">duration</div>
                <div class="meta-value">{{ duration }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">requests</div>
                <div class="meta-value">{{ requests }}</div>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card severity-total">
                <div class="count">{{ total }}</div>
                <div class="label">total</div>
            </div>
            <div class="summary-card severity-critical">
                <div class="count">{{ critical }}</div>
                <div class="label">critical</div>
            </div>
            <div class="summary-card severity-high">
                <div class="count">{{ high }}</div>
                <div class="label">high</div>
            </div>
            <div class="summary-card severity-medium">
                <div class="count">{{ medium }}</div>
                <div class="label">medium</div>
            </div>
            <div class="summary-card severity-low">
                <div class="count">{{ low }}</div>
                <div class="label">low</div>
            </div>
            <div class="summary-card severity-info">
                <div class="count">{{ info_count }}</div>
                <div class="label">info</div>
            </div>
        </div>

        <h2>findings</h2>

        {% if findings %}
        {% for finding in findings %}
        <div class="finding {{ finding.severity }}">
            <div class="finding-header">
                <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
                <span class="finding-title">{{ finding.title }}</span>
            </div>
            <div class="finding-detail">plugin: <span>{{ finding.plugin }}</span></div>
            <div class="finding-detail">url: <span>{{ finding.url }}</span></div>
            {% if finding.parameter %}
            <div class="finding-detail">parameter: <span>{{ finding.parameter }}</span></div>
            {% endif %}
            {% if finding.payload %}
            <div class="finding-detail">payload: <span>{{ finding.payload }}</span></div>
            {% endif %}
            {% if finding.cvss is not none %}
            <div class="finding-detail">cvss: <span>{{ finding.cvss }}</span></div>
            {% endif %}
            {% if finding.evidence %}
            <div class="finding-evidence">{{ finding.evidence }}</div>
            {% endif %}
            {% if finding.remediation %}
            <div class="finding-fix">
                <span class="fix-label">remediation:</span> {{ finding.remediation }}
            </div>
            {% endif %}
            {% if finding.references %}
            <div class="references">
                {% for ref in finding.references %}
                <a href="{{ ref }}" target="_blank">{{ ref }}</a><br>
                {% endfor %}
            </div>
            {% endif %}
        </div>
        {% endfor %}
        {% else %}
        <div class="no-findings">no vulnerabilities found. target appears secure.</div>
        {% endif %}

        <div class="footer">
            generated by c0nscanner v{{ version }} | {{ finished }}
        </div>
    </div>
</body>
</html>"""


class HTMLReporter(BaseReporter):
    """generates styled html scan reports."""

    name = "html"
    extension = ".html"

    def generate(
        self,
        findings: list[Finding],
        metadata: dict[str, Any],
    ) -> str:
        sorted_findings = sorted(findings, key=lambda x: x.severity_order)

        template = Template(HTML_TEMPLATE)
        return template.render(
            targets=metadata.get("targets", []),
            modules=metadata.get("modules", []),
            started=metadata.get("started", "n/a"),
            finished=metadata.get("finished", "n/a"),
            duration=metadata.get("duration", "n/a"),
            requests=metadata.get("requests", 0),
            version=metadata.get("version", "1.0.0"),
            total=len(findings),
            critical=sum(1 for f in findings if f.severity == "critical"),
            high=sum(1 for f in findings if f.severity == "high"),
            medium=sum(1 for f in findings if f.severity == "medium"),
            low=sum(1 for f in findings if f.severity == "low"),
            info_count=sum(1 for f in findings if f.severity == "info"),
            findings=[f.to_dict() for f in sorted_findings],
        )

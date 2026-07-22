"""
Report Exporters — legacy Jinja2/HTML exporter for engagement output.

BLK-3 (2026-07-22): this module generates styled HTML reports from Jinja2
templates. The bounty-report rendering engine — the one that produces
triager-grade Markdown with PoC, evidence, dedup signatures, CVSS, and
simulated-finding guards — lives in ``ai_osop.core.bounty_report`` and is
re-exported from ``ai_osop.reporting`` (the package ``__init__``). Use
``render_bounty_report`` for bug-bounty submissions; this module is for
internal HTML/PDF report export only.
"""

import hashlib
import json
from typing import Any, Dict

import markdown
from jinja2 import Environment, FileSystemLoader


class ReportExporter:
    """Manages the rendering and exporting of assessment reports."""

    def __init__(self, template_dir: str):
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def hash_evidence(self, content: str) -> str:
        """Create SHA-256 hash of evidence for chain of custody."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def generate_markdown(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render a Jinja2 template to Markdown."""
        template = self.env.get_template(template_name)
        return template.render(**context)

    def export_json(self, data: Dict[str, Any]) -> str:
        """Export raw structured data as JSON."""
        return json.dumps(data, indent=2)

    def markdown_to_html(self, markdown_text: str) -> str:
        """Convert Markdown report to styled HTML."""
        html_content = markdown.markdown(markdown_text, extensions=["tables", "fenced_code"])
        # Simple CSS wrapper for styled output
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; line-height: 1.6; max-width: 1000px; margin: 0 auto; padding: 2rem; color: #24292e; }}
    h1, h2, h3 {{ color: #111; }}
    code {{ background: #f6f8fa; padding: 0.2em 0.4em; border-radius: 3px; font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace; font-size: 85%; }}
    pre {{ background: #f6f8fa; padding: 16px; overflow: auto; border-radius: 3px; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; }}
    th, td {{ border: 1px solid #dfe2e5; padding: 6px 13px; }}
    th {{ background-color: #f6f8fa; font-weight: 600; }}
</style>
</head>
<body>
{html_content}
</body>
</html>"""

    def render_attack_graph(self, graph_data: Dict[str, Any], engagement_id: str) -> str:
        """Render the D3.js interactive attack graph."""
        template = self.env.get_template("attack_graph.html.j2")
        return template.render(engagement_id=engagement_id, graph_json=json.dumps(graph_data))

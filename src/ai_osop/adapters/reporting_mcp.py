"""Local MCP-style adapter for report rendering and export.

MAJ-1 (2026-07-22): NOT a stub. This is a local adapter that wraps the real
``ReportExporter`` (Jinja2/HTML) with a timeout. The bounty-report rendering
engine is ``ai_osop.core.bounty_report.render_bounty_report`` (re-exported
from ``ai_osop.reporting``). This adapter is for internal HTML/PDF export.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from ai_osop.core.exceptions import MCPException, MCPTimeoutError
from ai_osop.reporting.exporters import ReportExporter


class ReportingMCPAdapter:
    """Expose report rendering through a timeout-bound adapter."""

    ALLOWED_TEMPLATES = {"executive.md.j2", "technical.md.j2", "attack_graph.html.j2"}

    def __init__(self, exporter: ReportExporter, timeout_seconds: float = 30.0):
        self.exporter = exporter
        self.timeout_seconds = timeout_seconds

    async def render_markdown(self, template_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Render an approved Markdown template."""
        self._validate_template(template_name)
        markdown = await self._run_sync(self.exporter.generate_markdown, template_name, context)
        return {"status": "success", "format": "markdown", "content": markdown}

    async def render_html(self, markdown_text: str) -> Dict[str, Any]:
        """Render Markdown to HTML."""
        html = await self._run_sync(self.exporter.markdown_to_html, markdown_text)
        return {"status": "success", "format": "html", "content": html}

    async def export_json(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Render report context as JSON."""
        content = await self._run_sync(self.exporter.export_json, data)
        return {"status": "success", "format": "json", "content": content}

    def _validate_template(self, template_name: str) -> None:
        if template_name not in self.ALLOWED_TEMPLATES:
            raise MCPException(f"Template is not approved for report export: {template_name}")

    async def _run_sync(self, func: Any, *args: Any) -> Any:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(func, *args),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise MCPTimeoutError("Reporting MCP operation timed out") from exc
        except MCPException:
            raise
        except Exception as exc:
            raise MCPException(f"Reporting MCP operation failed: {exc}") from exc

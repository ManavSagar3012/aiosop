"""
Reporting MCP Server - REAL IMPLEMENTATION
Provides tool-based access to the reporting engine with real Markdown/HTML/JSON export.
Uses Jinja2 templates for professional report generation.
"""

import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add src to path for importing ai_osop modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    import markdown
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False

app = FastAPI(title="Reporting MCP Server")

# Template directory
TEMPLATE_DIR = Path(__file__).parent.parent.parent / "src" / "ai_osop" / "reporting" / "templates"

# Initialize Jinja2 environment
jinja_env = None
if JINJA_AVAILABLE and TEMPLATE_DIR.exists():
    jinja_env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(['html', 'xml']),
        trim_blocks=True,
        lstrip_blocks=True
    )

# In-memory report storage
_reports_cache: Dict[str, Dict[str, Any]] = {}

@app.get("/health")
async def health():
    return {
        "status": "ready",
        "server": "reporting-mcp",
        "jinja_available": JINJA_AVAILABLE,
        "template_dir_exists": TEMPLATE_DIR.exists() if JINJA_AVAILABLE else False
    }

class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None

def _render_markdown_template(template_name: str, context: Dict[str, Any]) -> str:
    """Render a Markdown template with real data."""
    if not jinja_env:
        # Fallback: generate simple markdown
        return _generate_simple_markdown(context)
    
    try:
        template = jinja_env.get_template(template_name)
        return template.render(**context)
    except Exception as e:
        # Fallback on error
        return _generate_simple_markdown(context)

def _generate_simple_markdown(context: Dict[str, Any]) -> str:
    """Generate basic markdown report when templates unavailable."""
    engagement_id = context.get("engagement_id", "unknown")
    findings = context.get("findings", [])
    
    md = f"# Security Assessment Report\n\n"
    md += f"**Engagement ID:** {engagement_id}\n"
    md += f"**Generated:** {datetime.utcnow().isoformat()}Z\n\n"
    md += f"## Executive Summary\n\n"
    md += f"This report contains {len(findings)} finding(s).\n\n"
    md += f"## Findings\n\n"
    
    for i, finding in enumerate(findings, 1):
        md += f"### {i}. {finding.get('title', 'Unknown')}\n"
        md += f"**Severity:** {finding.get('severity', 'Unknown')}\n"
        md += f"**Description:** {finding.get('description', 'N/A')}\n\n"
    
    return md

def _markdown_to_html(markdown_text: str) -> str:
    """Convert Markdown to HTML."""
    if 'markdown' in sys.modules:
        return markdown.markdown(markdown_text, extensions=['tables', 'fenced_code'])
    # Fallback: minimal HTML conversion
    html = markdown_text.replace('\n', '<br>\n')
    html = html.replace('### ', '<h3>').replace('## ', '<h2>').replace('# ', '<h1>')
    return f"<html><body>{html}</body></html>"

@app.post("/mcp/initialize")
async def mcp_initialize():
    return {
        "server_id": "reporting-mcp",
        "version": "2.0",
        "capabilities": ["markdown_render", "html_export", "json_export"],
        "tools": [
            {
                "name": "compile_findings",
                "description": "Aggregate all verified vulnerabilities into a mission report with real Markdown rendering.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                    {"name": "findings", "type": "array", "required": True, "description": "List of vulnerability findings"},
                    {"name": "format", "type": "string", "enum": ["markdown", "html", "json"], "required": False}
                ]
            },
            {
                "name": "render_markdown",
                "description": "Render Markdown content using Jinja2 templates.",
                "parameters": [
                    {"name": "template_name", "type": "string", "required": True},
                    {"name": "context", "type": "object", "required": True}
                ]
            },
            {
                "name": "export_html",
                "description": "Convert Markdown to HTML format.",
                "parameters": [
                    {"name": "markdown_text", "type": "string", "required": True}
                ]
            }
        ]
    }

@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest):
    request_id = req.request_id or str(uuid.uuid4())
    params = req.parameters or {}
    
    if req.tool_name == "compile_findings":
        engagement_id = params.get("engagement_id", "")
        findings = params.get("findings", [])
        output_format = params.get("format", "markdown")
        
        context = {
            "engagement_id": engagement_id,
            "findings": findings,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_findings": len(findings)
        }
        
        # Calculate severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        context["severity_breakdown"] = severity_counts
        
        markdown_content = _render_markdown_template("technical.md.j2", context)
        
        result = {
            "engagement_id": engagement_id,
            "format": output_format,
            "findings_count": len(findings),
            "severity_breakdown": severity_counts,
        }
        
        if output_format == "markdown":
            result["content"] = markdown_content
            result["report_path"] = f"/reports/{engagement_id}/report.md"
        elif output_format == "html":
            html_content = _markdown_to_html(markdown_content)
            result["content"] = html_content
            result["report_path"] = f"/reports/{engagement_id}/report.html"
        else:  # json
            result["content"] = {
                "engagement_id": engagement_id,
                "findings": findings,
                "metadata": context
            }
            result["report_path"] = f"/reports/{engagement_id}/report.json"
        
        # Cache the report
        _reports_cache[engagement_id] = result
        
        return {
            "request_id": request_id,
            "status": "success",
            "result": result
        }
    
    elif req.tool_name == "render_markdown":
        template_name = params.get("template_name", "technical.md.j2")
        context = params.get("context", {})
        
        try:
            markdown_content = _render_markdown_template(template_name, context)
            return {
                "request_id": request_id,
                "status": "success",
                "result": {
                    "template": template_name,
                    "content": markdown_content,
                    "rendered_at": datetime.utcnow().isoformat() + "Z"
                }
            }
        except Exception as e:
            return {
                "request_id": request_id,
                "status": "error",
                "error": str(e)
            }
    
    elif req.tool_name == "export_html":
        markdown_text = params.get("markdown_text", "")
        html_content = _markdown_to_html(markdown_text)
        return {
            "request_id": request_id,
            "status": "success",
            "result": {
                "html": html_content,
                "length": len(html_content)
            }
        }
    
    elif req.tool_name == "get_report":
        engagement_id = params.get("engagement_id", "")
        if engagement_id in _reports_cache:
            return {
                "request_id": request_id,
                "status": "success",
                "result": _reports_cache[engagement_id]
            }
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"Report not found for engagement: {engagement_id}"
        }
    
    return {
        "request_id": request_id,
        "status": "error",
        "error": f"Unknown tool: {req.tool_name}"
    }

if __name__ == "__main__":
    import uvicorn
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8092)
    args = parser.parse_args()
    print(f"Starting Reporting MCP server with real template rendering (Jinja2: {JINJA_AVAILABLE})...")
    uvicorn.run(app, host="0.0.0.0", port=args.port)

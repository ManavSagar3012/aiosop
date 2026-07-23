"""
Reporting MCP Server (Production Implementation)
Provides secure, queue-backed, and authenticated compilation of assessment reports.
"""

import json
import sys
import os
import uuid
import time
import hmac
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))

from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel

from sqlalchemy import Column, String, DateTime, Text, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker

from ai_osop.core.config import settings, scope_signing_key
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.reporting.exporters import ReportExporter
from ai_osop.core.models import AuditEvent

app = FastAPI(title="Reporting MCP Server")

Base = declarative_base()


class ReportJobORM(Base):
    __tablename__ = "report_jobs"

    id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), index=True, nullable=False)
    status = Column(String(32), nullable=False)  # pending, running, completed, failed
    format = Column(String(16), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    artifact_id = Column(String(64), nullable=True)
    idempotency_key = Column(String(64), unique=True, index=True, nullable=True)


class ReportArtifactORM(Base):
    __tablename__ = "report_artifacts"

    id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), index=True, nullable=False)
    format = Column(String(16), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


engine = create_async_engine(settings.postgres_uri, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

graph_memory: Optional[GraphMemory] = None
session_memory: Optional[SessionMemory] = None
llm_client: Optional[LiteLLMClient] = None


async def verify_mcp_token(authorization: Optional[str] = Header(None)):
    """Enforce strict bearer token verification."""
    expected = settings.api_token or os.getenv("OSOP_API_TOKEN")
    if not expected:
        if settings.environment in ("production", "prod"):
            raise HTTPException(status_code=401, detail="Authentication is not configured")
        return

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid or missing Authorization header")

    token = authorization.split(" ", 1)[1]
    import hmac

    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


def generate_signed_url(artifact_id: str) -> str:
    """Generate time-bound secure download URL signed via HMAC."""
    expires = int(time.time()) + 3600  # 1 hour expiry
    secret = scope_signing_key()
    msg = f"{artifact_id}:{expires}"
    sig = hmac.new(secret, msg.encode(), hashlib.sha256).hexdigest()
    return f"http://127.0.0.1:8092/reports/download/{artifact_id}?expires={expires}&token={sig}"


def verify_signed_url(artifact_id: str, expires: int, token: str) -> bool:
    """Verify signed URL validity and signature."""
    if time.time() > expires:
        return False
    secret = scope_signing_key()
    msg = f"{artifact_id}:{expires}"
    expected = hmac.new(secret, msg.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(token, expected)


@app.on_event("startup")
async def startup():
    global graph_memory, session_memory, llm_client
    graph_memory = GraphMemory()
    await graph_memory.connect()

    session_memory = SessionMemory()
    await session_memory.connect()

    llm_client = LiteLLMClient()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.on_event("shutdown")
async def shutdown():
    global graph_memory, session_memory
    if graph_memory:
        await graph_memory.close()
    if session_memory:
        await session_memory.close()
    await engine.dispose()


@app.get("/health")
async def health():
    if not graph_memory or not session_memory:
        raise HTTPException(status_code=503, detail="Backends not connected")
    return {"status": "ready", "server": "reporting-mcp", "is_stub": False}


class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None


@app.post("/mcp/initialize")
async def mcp_initialize(authenticated: None = Depends(verify_mcp_token)):
    return {
        "server_id": "reporting-mcp",
        "version": "1.0",
        "status": "ready",
        "capabilities": ["tools"],
        "tools": [
            {
                "name": "compile_findings",
                "description": "Aggregate verified vulnerabilities into an assessment report.",
                "parameters": [
                    {"name": "engagement_id", "type": "string", "required": True},
                    {
                        "name": "format",
                        "type": "string",
                        "enum": ["markdown", "html", "json"],
                        "required": False,
                    },
                    {"name": "include_evidence", "type": "boolean", "required": False},
                    {"name": "idempotency_key", "type": "string", "required": False},
                ],
                "returns": {"status": "string", "result": "object"},
            }
        ],
    }


async def run_compile_findings_job(
    job_id: str, engagement_id: str, fmt: str, include_evidence: bool
):
    """Background task to run report compilation securely."""
    try:
        # 1. Update job to running
        async with async_session() as session:
            q = select(ReportJobORM).where(ReportJobORM.id == job_id)
            res = await session.execute(q)
            job = res.scalar_one()
            job.status = "running"
            await session.commit()

        # 2. Gather data
        graph_stats = await graph_memory.get_graph_stats(engagement_id)
        raw_nodes = await graph_memory.get_vulnerabilities_by_engagement(engagement_id)

        vuln_nodes = []
        for n in raw_nodes:
            is_simulated = n.get("is_simulated", False) or n.get("simulated", False)
            if is_simulated and not settings.allow_simulated_findings:
                continue
            vuln_nodes.append(n)

        # 3. Format findings
        findings = []
        for n in vuln_nodes:
            raw_evidence = n.get("evidence", [])
            evidence_parts = []
            if isinstance(raw_evidence, list):
                for ev in raw_evidence:
                    if isinstance(ev, dict):
                        parts = [f"Type: {ev.get('type', 'unknown')}"]
                        if ev.get("payload"):
                            parts.append(f"Payload: {ev.get('payload')}")
                        if ev.get("response"):
                            parts.append(f"Response: {ev.get('response')}")
                        evidence_parts.append("\n".join(parts))
                    else:
                        evidence_parts.append(str(ev))
            elif isinstance(raw_evidence, str):
                evidence_parts.append(raw_evidence)

            evidence_str = (
                "\n\n---\n\n".join(evidence_parts) if evidence_parts else "No evidence recorded."
            )
            evidence_hash = hashlib.sha256(evidence_str.encode("utf-8")).hexdigest()

            findings.append(
                {
                    "id": n.get("id"),
                    "title": n.get("title", "Unknown"),
                    "severity": n.get("severity", "INFO").upper(),
                    "vuln_type": n.get("vuln_type", "unknown"),
                    "target": n.get("endpoint_id", "unknown"),
                    "description": n.get("description", "No description."),
                    "evidence": (
                        evidence_str if include_evidence else "Evidence excluded by policy."
                    ),
                    "evidence_hash": evidence_hash,
                }
            )

        # 4. Generate narrative
        stats = {
            "assets_count": graph_stats.get("assets", 0),
            "endpoints_count": graph_stats.get("endpoints", 0),
            "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high_count": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium_count": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low_count": sum(1 for f in findings if f["severity"] == "LOW"),
            "info_count": sum(1 for f in findings if f["severity"] == "INFO"),
            "total_findings": len(findings),
        }

        narrative = ""
        if not settings.mock_llm and llm_client:
            context = f"Engagement {engagement_id}. Stats: {stats}."
            messages = [
                {
                    "role": "system",
                    "content": "Write a 2-paragraph executive risk narrative for this assessment. CONFIDENTIAL.",
                },
                {"role": "user", "content": context},
            ]
            narrative = await llm_client.complete(messages)
        else:
            narrative = "LLM risk narrative generation skipped (mock mode active)."

        # 5. Render
        template_dir = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "..", "..", "src", "ai_osop", "reporting", "templates"
            )
        )
        exporter = ReportExporter(template_dir)

        report_context = {
            "engagement_id": engagement_id,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "version": "v1.0",
            "risk_narrative": narrative,
            "stats": stats,
            "top_findings": findings[:5],
            "findings": findings,
        }

        content = ""
        if fmt == "markdown":
            content = exporter.generate_markdown("technical.md.j2", report_context)
        elif fmt == "html":
            md_content = exporter.generate_markdown("technical.md.j2", report_context)
            content = exporter.markdown_to_html(md_content)
        else:
            content = json.dumps(report_context, indent=2)

        # 6. Save Artifact
        artifact_id = f"art-{uuid.uuid4().hex[:12]}"
        new_artifact = ReportArtifactORM(
            id=artifact_id, engagement_id=engagement_id, format=fmt, content=content
        )

        async with async_session() as session:
            session.add(new_artifact)
            q = select(ReportJobORM).where(ReportJobORM.id == job_id)
            res = await session.execute(q)
            job = res.scalar_one()
            job.status = "completed"
            job.artifact_id = artifact_id
            job.completed_at = datetime.utcnow()
            await session.commit()

        # 7. Write Audit Event
        event = AuditEvent(
            event_type="report_compiled",
            severity="info",
            actor_type="system",
            actor_id="mcp-reporting",
            action={"method": "compile_findings", "engagement_id": engagement_id, "format": fmt},
            result={
                "status": "success",
                "artifact_id": artifact_id,
                "findings_count": len(findings),
            },
            context={"job_id": job_id, "artifact_id": artifact_id},
            engagement_id=engagement_id,
        )
        if session_memory:
            await session_memory.write_audit_event(event)

    except Exception as e:  # noqa: BLE001
        async with async_session() as session:
            q = select(ReportJobORM).where(ReportJobORM.id == job_id)
            res = await session.execute(q)
            job = res.scalar_one_or_none()
            if job:
                job.status = "failed"
                job.error = str(e)
                await session.commit()


@app.post("/mcp/execute")
async def mcp_execute(
    req: MCPExecuteRequest,
    background_tasks: BackgroundTasks,
    authenticated: None = Depends(verify_mcp_token),
):
    request_id = req.request_id or str(uuid.uuid4())
    params = req.parameters or {}

    if req.tool_name != "compile_findings":
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"Unknown tool: {req.tool_name}",
        }

    engagement_id = params.get("engagement_id")
    fmt = params.get("format", "json").lower()
    include_evidence = params.get("include_evidence", True)
    idempotency_key = params.get("idempotency_key")

    if not engagement_id:
        return {
            "request_id": request_id,
            "status": "error",
            "error": "engagement_id parameter is required",
        }

    # Handle Idempotency
    if idempotency_key:
        async with async_session() as session:
            q = select(ReportJobORM).where(ReportJobORM.idempotency_key == idempotency_key)
            res = await session.execute(q)
            existing = res.scalar_one_or_none()
            if existing:
                download_url = None
                if existing.status == "completed" and existing.artifact_id:
                    download_url = generate_signed_url(existing.artifact_id)
                return {
                    "request_id": request_id,
                    "status": "success",
                    "result": {
                        "job_id": existing.id,
                        "status": existing.status,
                        "download_url": download_url,
                        "error": existing.error,
                    },
                }

    job_id = f"job-{uuid.uuid4().hex[:12]}"
    new_job = ReportJobORM(
        id=job_id,
        engagement_id=engagement_id,
        status="pending",
        format=fmt,
        idempotency_key=idempotency_key,
    )
    async with async_session() as session:
        session.add(new_job)
        await session.commit()

    background_tasks.add_task(
        run_compile_findings_job,
        job_id,
        engagement_id,
        fmt,
        include_evidence,
    )

    return {
        "request_id": request_id,
        "status": "success",
        "result": {
            "job_id": job_id,
            "status": "pending",
            "message": "Report compilation started in background",
        },
    }


@app.get("/reports/download/{artifact_id}")
async def download_report(artifact_id: str, expires: int, token: str):
    """Download compiled report securely via time-bound signed URL."""
    if not verify_signed_url(artifact_id, expires, token):
        raise HTTPException(status_code=403, detail="Invalid or expired download signature")

    async with async_session() as session:
        q = select(ReportArtifactORM).where(ReportArtifactORM.id == artifact_id)
        res = await session.execute(q)
        artifact = res.scalar_one_or_none()
        if not artifact:
            raise HTTPException(status_code=404, detail="Artifact not found")

        if artifact.format == "html":
            return HTMLResponse(content=artifact.content)
        elif artifact.format == "markdown":
            return PlainTextResponse(content=artifact.content)
        else:
            return Response(content=artifact.content, media_type="application/json")


if __name__ == "__main__":
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8092)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)

# mcp-servers/python/cloud_mcp.py
"""Cloud security MCP server (HTTP MCP protocol).

AIOSOP-CLOUD-MCP-001 (2026-07-03): rewritten from a raw-socket JSON-RPC server to the
HTTP MCP protocol (/health, /mcp/initialize, /mcp/execute) that MCPRegistry actually
speaks. The old raw-socket server could never complete the registry's HTTP initialize
handshake, so cloud-mcp always appeared "down" despite running and being registered.

Honesty: IAM analysis makes REAL boto3 calls. With AWS credentials it inspects live
role trust policies; WITHOUT them it returns an honest error in the result payload —
it never synthesizes findings. boto3 is imported lazily so the server still starts
(and reports honestly) on hosts where boto3 or credentials are absent.
"""
import sys
import os
import argparse
from typing import Optional

import uvicorn
from fastapi import FastAPI, Header, Depends, HTTPException
from pydantic import BaseModel

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))

from ai_osop.core.config import settings

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

app = FastAPI(title="Cloud Security MCP Server")


async def analyze_aws_iam(account_id=None):
    """Real AWS IAM trust-policy analysis via boto3. Honest error when unavailable."""
    try:
        import boto3
    except Exception as e:  # boto3 not installed
        return {"status": "unavailable", "provider": "aws", "error": f"boto3 unavailable: {e}"}
    try:
        iam = boto3.client("iam")
        findings = []
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                policy = role.get("AssumeRolePolicyDocument", {})
                # Wildcard principal/action in a trust policy => anyone may assume the role.
                if "*" in str(policy):
                    findings.append({
                        "role": role.get("Arn"),
                        "issue": "Overly permissive trust policy (wildcard principal/action)",
                        "risk": "HIGH",
                    })
        return {"status": "success", "provider": "aws",
                "findings": findings, "findings_count": len(findings)}
    except Exception as e:
        # No creds / no permission / no network -> honest error, NEVER synthetic data.
        return {"status": "unavailable", "provider": "aws", "error": str(e)}
async def discover_aws_privesc(principal_arn=None):
    """Discover privilege escalation paths in AWS IAM via boto3."""
    try:
        import boto3
    except Exception as e:
        return {"status": "unavailable", "provider": "aws", "error": f"boto3 unavailable: {e}"}
    try:
        iam = boto3.client("iam")
        paths = []
        # Scan attached/inline policies for dangerous permissions
        dangerous_actions = {
            "iam:PassRole", "iam:CreateAccessKey", "iam:AttachUserPolicy",
            "iam:AttachGroupPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy",
            "iam:PutRolePolicy", "iam:CreatePolicyVersion", "sts:AssumeRole"
        }
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user.get("UserName")
                user_policies = iam.list_user_policies(UserName=username).get("PolicyNames", [])
                for p_name in user_policies:
                    p_doc = iam.get_user_policy(UserName=username, PolicyName=p_name).get("PolicyDocument", {})
                    p_str = str(p_doc)
                    matched = [a for a in dangerous_actions if a in p_str]
                    if matched:
                        paths.append({
                            "target": user.get("Arn"),
                            "issue": f"IAM PrivEsc risk via actions: {', '.join(matched)}",
                            "actions": matched,
                            "risk": "CRITICAL" if "iam:PassRole" in matched else "HIGH",
                        })
        return {"status": "success", "provider": "aws", "paths": paths, "paths_count": len(paths)}
    except Exception as e:
        return {"status": "unavailable", "provider": "aws", "error": str(e)}


async def probe_metadata_ssrf(target_url: str):
    """Probe a URL or Cloud Metadata endpoint for SSRF credential exposure."""
    if not target_url:
        return {"status": "error", "error": "target_url is required"}
    try:
        import httpx
        from ai_osop.core.cloud_metadata import IMDS_TARGETS, extract_credentials
        findings = []
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            # Try fetching target_url
            try:
                resp = await client.get(target_url)
                creds = extract_credentials(resp.text)
                if creds:
                    for c in creds:
                        findings.append({
                            "target_url": target_url,
                            "issue": f"Cloud Metadata SSRF exposed {c['provider']} {c['kind']}",
                            "redacted": c["redacted"],
                            "severity": "CRITICAL",
                        })
            except Exception as e:
                pass
        return {"status": "success", "findings": findings, "findings_count": len(findings)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def probe_storage_exposure(target: str):
    """Probe cloud storage buckets (S3 / GCP / Azure) for public exposure."""
    if not target:
        return {"status": "error", "error": "target is required"}
    try:
        import httpx
        findings = []
        # Standard S3 endpoint URL format
        clean_target = target.replace("http://", "").replace("https://", "").strip("/").split("/")[0]
        urls = [
            f"https://{clean_target}.s3.amazonaws.com/",
            f"https://storage.googleapis.com/{clean_target}/",
            f"https://{clean_target}.blob.core.windows.net/?comp=list",
        ]
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for url in urls:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and ("<ListBucketResult" in resp.text or "<EnumerationResults" in resp.text or "ListBucketResult" in resp.text):
                        findings.append({
                            "bucket": clean_target,
                            "url": url,
                            "issue": "Publicly readable cloud storage bucket listing",
                            "severity": "HIGH",
                        })
                except Exception:
                    continue
        return {"status": "success", "findings": findings, "findings_count": len(findings)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


TOOLS = [
    {
        "name": "analyze_iam_trust_policies",
        "description": ("Analyze cloud IAM role trust policies for overly-permissive "
                        "(wildcard) principals/actions. AWS uses real boto3 calls; returns "
                        "an honest 'unavailable' status when credentials are absent."),
        "parameters": [
            {"name": "provider", "type": "string",
             "description": "aws | azure | gcp (default aws)", "required": False},
            {"name": "account_id", "type": "string",
             "description": "Optional AWS account id for scoping/labeling", "required": False},
        ],
        "returns": {"status": "string", "findings": "array", "findings_count": "integer"},
    },
    {
        "name": "discover_privilege_escalation",
        "description": "Discover privilege escalation vectors in cloud IAM policies.",
        "parameters": [
            {"name": "principal_arn", "type": "string", "required": False},
        ],
        "returns": {"status": "string", "paths": "array", "paths_count": "integer"},
    },
    {
        "name": "probe_cloud_metadata",
        "description": "Probe a URL or Cloud Metadata endpoint for SSRF credential exposure.",
        "parameters": [
            {"name": "target_url", "type": "string", "required": True},
        ],
        "returns": {"status": "string", "findings": "array", "findings_count": "integer"},
    },
    {
        "name": "probe_storage_exposure",
        "description": "Probe cloud storage buckets (S3 / GCP / Azure) for public exposure.",
        "parameters": [
            {"name": "target", "type": "string", "required": True},
        ],
        "returns": {"status": "string", "findings": "array", "findings_count": "integer"},
    },
]


@app.get("/health")
async def health(authenticated: None = Depends(verify_mcp_token)):
    return {"status": "ready", "server": "cloud-mcp"}


@app.post("/mcp/initialize")
async def initialize(authenticated: None = Depends(verify_mcp_token)):
    return {"server_id": "cloud-mcp", "capabilities": ["tool"], "status": "ready", "tools": TOOLS}


class ExecuteRequest(BaseModel):
    tool_name: str
    parameters: dict
    request_id: str


@app.post("/mcp/execute")
async def execute(req: ExecuteRequest, authenticated: None = Depends(verify_mcp_token)):
    if req.tool_name == "analyze_iam_trust_policies":
        provider = (req.parameters.get("provider") or "aws").lower()
        if provider == "aws":
            result = await analyze_aws_iam(req.parameters.get("account_id"))
        elif provider in ("azure", "gcp"):
            result = {"status": "not_implemented", "provider": provider,
                      "error": f"{provider} IAM discovery not implemented"}
        else:
            result = {"status": "error", "error": f"unknown provider: {provider}"}
        return {"request_id": req.request_id, "status": "success", "result": result}
    elif req.tool_name == "discover_privilege_escalation":
        result = await discover_aws_privesc(req.parameters.get("principal_arn"))
        return {"request_id": req.request_id, "status": "success", "result": result}
    elif req.tool_name == "probe_cloud_metadata":
        result = await probe_metadata_ssrf(req.parameters.get("target_url"))
        return {"request_id": req.request_id, "status": "success", "result": result}
    elif req.tool_name == "probe_storage_exposure":
        result = await probe_storage_exposure(req.parameters.get("target"))
        return {"request_id": req.request_id, "status": "success", "result": result}
    return {"request_id": req.request_id, "status": "error",
            "error": f"unknown tool: {req.tool_name}"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8097)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")

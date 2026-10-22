"""
AI-OSOP Isolated Multi-Tenant Lab Target.
Exposes controlled authorization (BOLA/IDOR), SQL injection, and public endpoints
for deterministic qualification testing without external network egress.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel

app = FastAPI(
    title="AI-OSOP Multi-Tenant Lab Target",
    description="Authorized benchmark lab target for AI-OSOP qualification testing",
    version="1.0.0",
)

# In-memory mock database
DOCUMENTS: Dict[str, Dict[str, Any]] = {
    "doc-101": {
        "id": "doc-101",
        "owner": "alice",
        "tenant_id": "tenant-alpha",
        "title": "Alpha Q3 Financial Projections",
        "classification": "CONFIDENTIAL",
        "content": "Planned Acquisition of Beta Corp for $15M. Board approval pending.",
        "amount": 15000000,
    },
    "doc-202": {
        "id": "doc-202",
        "owner": "bob",
        "tenant_id": "tenant-beta",
        "title": "Beta Employee Compensation Ledger",
        "classification": "RESTRICTED",
        "content": "Executive Salaries and Equity Grants for FY2026.",
        "headcount": 42,
    },
}

USERS: Dict[str, Dict[str, Any]] = {
    "token-alice-secret-key-101": {
        "user_id": "alice",
        "tenant_id": "tenant-alpha",
        "role": "user",
    },
    "token-bob-secret-key-202": {
        "user_id": "bob",
        "tenant_id": "tenant-beta",
        "role": "user",
    },
    "token-admin-secret-key-999": {
        "user_id": "admin",
        "tenant_id": "tenant-system",
        "role": "admin",
    },
}


def _get_identity(auth_header: Optional[str]) -> Optional[Dict[str, Any]]:
    if not auth_header:
        return None
    token = auth_header.replace("Bearer ", "").strip()
    return USERS.get(token)


# ---------------------------------------------------------
# 1. Public Controls (Should NOT trigger IDOR / False Positive)
# ---------------------------------------------------------
@app.get("/api/v1/health")
def health_check() -> Dict[str, Any]:
    """Public health probe, identical across all identities."""
    return {"status": "ok", "version": "1.0.0", "service": "lab-target"}


@app.get("/api/v1/system/info")
def system_info() -> Dict[str, Any]:
    """Public system metadata; must be suppressed from vulnerability triage."""
    return {
        "architecture": "microservice",
        "framework": "fastapi",
        "runtime": "python-3.11",
        "environment": "isolated-lab",
    }


# ---------------------------------------------------------
# 2. Vulnerable BOLA / IDOR Endpoint
# ---------------------------------------------------------
@app.get("/api/v1/documents/{doc_id}")
def get_document(doc_id: str, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    VULNERABILITY: Broken Object Level Authorization (BOLA / IDOR).
    Authentication is required, but authorization is not enforced:
    User 'bob' (tenant-beta) can access 'doc-101' owned by User 'alice' (tenant-alpha).
    Anonymous requests are properly rejected with 401 Unauthorized.
    """
    identity = _get_identity(authorization)
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    doc = DOCUMENTS.get(doc_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Intentional Flaw: No check that doc['owner'] == identity['user_id'] or doc['tenant_id'] == identity['tenant_id']
    return {
        "success": True,
        "caller_user": identity["user_id"],
        "caller_tenant": identity["tenant_id"],
        "document": doc,
    }


# ---------------------------------------------------------
# 3. Simulated SQL Injection Endpoint
# ---------------------------------------------------------
class AnalyticsQuery(BaseModel):
    filter_expr: str


@app.post("/api/v1/analytics/query")
def run_analytics_query(
    query: AnalyticsQuery, authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    VULNERABILITY: SQL Injection simulation.
    If filter_expr contains SQL injection patterns (e.g. `' OR '1'='1`),
    it leaks all records across all tenants.
    """
    identity = _get_identity(authorization)
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
        )

    raw_filter = query.filter_expr.upper()
    if "' OR '1'='1" in raw_filter or "UNION SELECT" in raw_filter or "1=1" in raw_filter:
        # SQLi simulated exploitation successful
        return {
            "success": True,
            "simulated_query": f"SELECT * FROM documents WHERE tenant_id = '{identity['tenant_id']}' AND ({query.filter_expr})",
            "leaked_rows": list(DOCUMENTS.values()),
            "sqli_detected": True,
        }

    # Normal execution: filtered by caller's tenant
    filtered = [d for d in DOCUMENTS.values() if d["tenant_id"] == identity["tenant_id"]]
    return {
        "success": True,
        "simulated_query": f"SELECT * FROM documents WHERE tenant_id = '{identity['tenant_id']}' AND status='active'",
        "rows": filtered,
    }


# ---------------------------------------------------------
# 4. Protected Administrative Endpoint (Requires Approval Gate)
# ---------------------------------------------------------
class UserCreateRequest(BaseModel):
    username: str
    tenant_id: str
    role: str = "user"


@app.post("/api/v1/admin/users")
def create_user(
    req: UserCreateRequest, authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    Administrative privileged endpoint.
    Strictly requires role == 'admin'.
    Regular users (alice, bob) receive 403 Forbidden.
    """
    identity = _get_identity(authorization)
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
        )

    if identity["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: role '{identity['role']}' is not authorized for administrative operations",
        )

    new_token = f"token-{req.username}-secret-key-{len(USERS) + 100}"
    USERS[new_token] = {
        "user_id": req.username,
        "tenant_id": req.tenant_id,
        "role": req.role,
    }
    return {
        "success": True,
        "created_user": req.username,
        "tenant_id": req.tenant_id,
        "token": new_token,
    }


# ---------------------------------------------------------
# 5. Soft Denial Endpoint (Denial-in-200)
# ---------------------------------------------------------
@app.get("/api/v1/restricted/feature")
def soft_denial_feature(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Returns HTTP 200 with an explicit denial body.
    Used to test the Differential Auth Engine's soft-denial detection.
    """
    identity = _get_identity(authorization)
    if not identity or identity["role"] != "admin":
        return {
            "status": "error",
            "code": 403,
            "message": "Access Denied: feature is disabled for non-administrative accounts",
            "authorized": False,
        }
    return {"status": "success", "feature": "enterprise-export", "authorized": True}

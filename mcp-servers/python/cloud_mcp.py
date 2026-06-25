import sys
import json
import asyncio
import boto3
from typing import Any, Dict

# AWS
async def analyze_aws_iam(account_id):
    iam = boto3.client("iam")
    try:
        roles = iam.list_roles()
        results = []
        for role in roles["Roles"]:
            policy = iam.get_role(RoleName=role["RoleName"])["Role"]["AssumeRolePolicyDocument"]
            if "*" in str(policy):
                results.append({"role": role["Arn"], "issue": "Overly permissive trust policy", "risk": "HIGH"})
        return {"findings": results}
    except Exception as e:
        return {"error": str(e)}

# Stubbing Azure/GCP for now as the infrastructure is not configured
async def analyze_azure_iam():
    return {"status": "not_implemented", "msg": "Azure IAM discovery pending"}

async def analyze_gcp_iam():
    return {"status": "not_implemented", "msg": "GCP IAM discovery pending"}

async def handle_request(tool, params):
    if tool == "health":
        return {"status": "healthy"}
    elif tool == "analyze_iam_trust_policies":
        provider = params.get("provider", "aws")
        if provider == "aws":
            return await analyze_aws_iam(params.get("account_id"))
        elif provider == "azure":
            return await analyze_azure_iam()
        elif provider == "gcp":
            return await analyze_gcp_iam()
    return {"error": f"unknown tool: {tool}"}

if __name__ == "__main__":
    import socket
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8097)
    args = parser.parse_args()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", args.port))
    server.listen(1)
    print(f"Cloud MCP running on port {args.port}")
    sys.stdout.flush()
    
    loop = asyncio.get_event_loop()
    
    while True:
        conn, addr = server.accept()
        with conn:
            data = conn.recv(65536)
            if not data: continue
            try:
                req = json.loads(data.decode())
                if "method" in req:
                    result = loop.run_until_complete(handle_request(req["method"], req.get("params", {})))
                    conn.send(json.dumps({"jsonrpc": "2.0", "result": result, "id": req.get("id")}).encode())
            except Exception as e:
                conn.send(json.dumps({"error": str(e)}).encode())

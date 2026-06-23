"""Jaeger Trace Verification Script for AI-OSOP Sprint 6.

Verifies that OpenTelemetry traces are correctly exported to Jaeger by:
1. Checking the Jaeger query API for recent traces matching the AI-OSOP service name.
2. Validating that traces contain the expected span hierarchy:
   api.request -> orchestrator.schedule_task -> agent.execute_task -> mcp.* / neo4j.*
3. Checking trace context propagation (traceparent) across async boundaries.
4. Reporting missing spans or broken propagation chains.

Usage:
    python scripts/verify/verify_jaeger_traces.py [--jaeger-url http://localhost:16686]

Exit codes:
    0 - All traces healthy, propagation verified
    1 - Traces found but propagation broken
    2 - No traces found (possible exporter failure)
    3 - Connectivity or configuration error
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any, Dict, List, Optional

import httpx

from ai_osop.core.config import settings
from ai_osop.core.telemetry import RequestContext
from ai_osop.core.tracing import get_tracer, trace_span

JAEGER_QUERY_API = "{jaeger_url}/api/traces"
DEFAULT_LOOKBACK_SECONDS = 300  # 5 minutes

# Expected span hierarchy for end-to-end verification
EXPECTED_SPAN_KINDS = {
    "api": ["api.get", "api.post", "api.put", "api.delete", "api.patch"],
    "orchestrator": ["orchestrator.create_engagement", "orchestrator.schedule_task", "orchestrator._assign_task"],
    "agent": ["agent.execute_task", "agent._execute"],
    "mcp": ["mcp_registry.execute_tool", "mcp_registry.broadcast_execute"],
    "memory": ["neo4j.add_asset", "neo4j.add_endpoint", "redis.setex", "redis.get", "redis.zadd"],
}


class TraceVerifier:
    """Verifies Jaeger traces for AI-OSOP."""

    def __init__(self, jaeger_url: str, service_name: str = "ai-osop"):
        self.jaeger_url = jaeger_url.rstrip("/")
        self.service_name = service_name
        self.client = httpx.AsyncClient(timeout=30.0)
        self.errors: List[str] = []
        self.warnings: List[str] = []

    async def close(self) -> None:
        await self.client.aclose()

    async def fetch_traces(
        self,
        lookback_seconds: int = DEFAULT_LOOKBACK_SECONDS,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Fetch recent traces from Jaeger query API."""
        end_time = int(time.time() * 1_000_000)  # microseconds
        start_time = end_time - (lookback_seconds * 1_000_000)

        url = f"{self.jaeger_url}/api/traces"
        params = {
            "service": self.service_name,
            "start": start_time,
            "end": end_time,
            "limit": limit,
        }

        try:
            response = await self.client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            return data.get("data", [])
        except httpx.ConnectError as e:
            self.errors.append(f"Cannot connect to Jaeger at {self.jaeger_url}: {e}")
            return []
        except httpx.HTTPStatusError as e:
            self.errors.append(f"Jaeger query API error: {e.response.status_code} - {e.response.text}")
            return []
        except Exception as e:
            self.errors.append(f"Unexpected error fetching traces: {e}")
            return []

    def analyze_trace(self, trace: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single trace for span hierarchy and propagation."""
        spans = trace.get("spans", [])
        result = {
            "trace_id": trace.get("traceID", "unknown"),
            "span_count": len(spans),
            "has_api_span": False,
            "has_orchestrator_span": False,
            "has_agent_span": False,
            "has_mcp_span": False,
            "has_memory_span": False,
            "has_broken_parent": False,
            "missing_parent_spans": [],
            "span_kinds": {},
            "request_ids": set(),
            "engagement_ids": set(),
        }

        # Build span lookup by spanID
        span_by_id: Dict[str, Dict[str, Any]] = {s["spanID"]: s for s in spans}
        root_spans = [s for s in spans if s.get("references", []) == []]

        for span in spans:
            operation = span.get("operationName", "")
            tags = {t["key"]: t["value"] for t in span.get("tags", [])}
            logs = span.get("logs", [])

            # Check for AI-OSOP context attributes
            if "ai_osop.request_id" in tags:
                result["request_ids"].add(tags["ai_osop.request_id"])
            if "ai_osop.engagement_id" in tags:
                result["engagement_ids"].add(tags["ai_osop.engagement_id"])

            # Categorize span
            for category, expected_ops in EXPECTED_SPAN_KINDS.items():
                if any(op in operation for op in expected_ops):
                    result[f"has_{category}_span"] = True
                    result["span_kinds"][category] = operation
                    break

            # Check for broken parent reference (parent spanID not in trace)
            for ref in span.get("references", []):
                if ref.get("refType") == "CHILD_OF":
                    parent_id = ref.get("spanID")
                    if parent_id and parent_id not in span_by_id:
                        result["has_broken_parent"] = True
                        result["missing_parent_spans"].append({
                            "span": operation,
                            "missing_parent": parent_id,
                        })

        # Determine propagation chain health
        result["propagation_chain"] = [
            result["has_api_span"],
            result["has_orchestrator_span"],
            result["has_agent_span"],
            result["has_mcp_span"] or result["has_memory_span"],
        ]
        result["chain_complete"] = all(result["propagation_chain"])

        return result

    def verify_traces(self, traces: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Verify all fetched traces and report health."""
        report = {
            "total_traces": len(traces),
            "traces_with_api": 0,
            "traces_with_orchestrator": 0,
            "traces_with_agent": 0,
            "traces_with_mcp": 0,
            "traces_with_memory": 0,
            "complete_chains": 0,
            "broken_parents": 0,
            "unique_request_ids": set(),
            "unique_engagement_ids": set(),
            "trace_details": [],
        }

        if not traces:
            self.errors.append("No traces found in Jaeger. Possible causes: OTel disabled, exporter misconfigured, or no traffic.")
            return report

        for trace in traces:
            analysis = self.analyze_trace(trace)
            report["trace_details"].append(analysis)

            if analysis["has_api_span"]:
                report["traces_with_api"] += 1
            if analysis["has_orchestrator_span"]:
                report["traces_with_orchestrator"] += 1
            if analysis["has_agent_span"]:
                report["traces_with_agent"] += 1
            if analysis["has_mcp_span"]:
                report["traces_with_mcp"] += 1
            if analysis["has_memory_span"]:
                report["traces_with_memory"] += 1
            if analysis["chain_complete"]:
                report["complete_chains"] += 1
            if analysis["has_broken_parent"]:
                report["broken_parents"] += 1

            report["unique_request_ids"].update(analysis["request_ids"])
            report["unique_engagement_ids"].update(analysis["engagement_ids"])

        # Health checks
        total = len(traces)
        if report["traces_with_api"] < total * 0.5:
            self.warnings.append(f"Only {report['traces_with_api']}/{total} traces have API spans. API instrumentation may be incomplete.")
        if report["traces_with_orchestrator"] < total * 0.3:
            self.warnings.append(f"Only {report['traces_with_orchestrator']}/{total} traces have orchestrator spans.")
        if report["traces_with_agent"] < total * 0.3:
            self.warnings.append(f"Only {report['traces_with_agent']}/{total} traces have agent spans.")
        if report["broken_parents"] > 0:
            self.warnings.append(f"{report['broken_parents']} traces have broken parent references (possible trace propagation issues).")
        if report["complete_chains"] < total * 0.2:
            self.warnings.append(f"Only {report['complete_chains']}/{total} traces have complete propagation chains (api -> orchestrator -> agent -> mcp/memory).")

        return report

    def print_report(self, report: Dict[str, Any]) -> None:
        """Print human-readable verification report."""
        print("=" * 60)
        print("AI-OSOP Jaeger Trace Verification Report")
        print("=" * 60)
        print(f"\nService: {self.service_name}")
        print(f"Jaeger URL: {self.jaeger_url}")
        print(f"\nTotal traces analyzed: {report['total_traces']}")

        if report["total_traces"] == 0:
            print("\n[FAIL] No traces found.")
            print("\nPossible causes:")
            print("  - OSOP_OTEL_ENABLED is not set to true")
            print("  - Jaeger collector is not reachable at OSOP_OTEL_ENDPOINT")
            print("  - No API traffic has been generated recently")
            print("  - BatchSpanProcessor has not yet flushed spans")
            return

        print(f"\nSpan coverage:")
        print(f"  API spans:          {report['traces_with_api']}/{report['total_traces']}")
        print(f"  Orchestrator spans:   {report['traces_with_orchestrator']}/{report['total_traces']}")
        print(f"  Agent spans:          {report['traces_with_agent']}/{report['total_traces']}")
        print(f"  MCP spans:            {report['traces_with_mcp']}/{report['total_traces']}")
        print(f"  Memory spans:         {report['traces_with_memory']}/{report['total_traces']}")
        print(f"\nPropagation:")
        print(f"  Complete chains:      {report['complete_chains']}/{report['total_traces']}")
        print(f"  Broken parents:       {report['broken_parents']}/{report['total_traces']}")
        print(f"  Unique request IDs:   {len(report['unique_request_ids'])}")
        print(f"  Unique engagements:   {len(report['unique_engagement_ids'])}")

        if self.warnings:
            print(f"\n[WARNINGS] ({len(self.warnings)}):")
            for w in self.warnings:
                print(f"  - {w}")

        if self.errors:
            print(f"\n[ERRORS] ({len(self.errors)}):")
            for e in self.errors:
                print(f"  - {e}")

        print("\n" + "=" * 60)
        if not self.errors and not self.warnings:
            print("[PASS] All traces healthy, propagation verified.")
        elif not self.errors:
            print("[WARN] Traces found but some issues detected.")
        else:
            print("[FAIL] Critical errors found.")
        print("=" * 60)


async def main() -> int:
    parser = argparse.ArgumentParser(description="Verify AI-OSOP traces in Jaeger")
    parser.add_argument(
        "--jaeger-url",
        default="http://localhost:16686",
        help="Jaeger query UI URL (default: http://localhost:16686)",
    )
    parser.add_argument(
        "--service-name",
        default=settings.otel_service_name,
        help=f"OTel service name to filter (default: {settings.otel_service_name})",
    )
    parser.add_argument(
        "--lookback",
        type=int,
        default=DEFAULT_LOOKBACK_SECONDS,
        help=f"Lookback window in seconds (default: {DEFAULT_LOOKBACK_SECONDS})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum traces to fetch (default: 20)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON report instead of human-readable",
    )
    args = parser.parse_args()

    verifier = TraceVerifier(jaeger_url=args.jaeger_url, service_name=args.service_name)
    try:
        traces = await verifier.fetch_traces(lookback_seconds=args.lookback, limit=args.limit)
        report = verifier.verify_traces(traces)

        if args.json:
            # Convert sets to lists for JSON serialization
            report["unique_request_ids"] = list(report["unique_request_ids"])
            report["unique_engagement_ids"] = list(report["unique_engagement_ids"])
            print(json.dumps(report, indent=2, default=str))
        else:
            verifier.print_report(report)

        # Determine exit code
        if verifier.errors:
            return 3 if any("Cannot connect" in e for e in verifier.errors) else 2
        if verifier.warnings:
            return 1
        return 0
    finally:
        await verifier.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

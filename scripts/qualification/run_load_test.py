"""AI-OSOP Standalone HTTP/WebSocket Service Load Testing Harness.

Simulates concurrent user & operator workloads, measuring latency percentiles
(p50, p95, p99), error rates, throughput (RPS), and SLO compliance.

Usage:
    python scripts/qualification/run_load_test.py --target http://localhost:8200 --concurrency 50 --duration 10
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from typing import Any, Dict, List

import httpx
import structlog

logger = structlog.get_logger("ai_osop.qualification.load_test")


class ServiceLoadTester:
    def __init__(self, target_url: str, concurrency: int = 25, duration_seconds: int = 5):
        self.target_url = target_url.rstrip("/")
        self.concurrency = concurrency
        self.duration_seconds = duration_seconds
        self.latencies: List[float] = []
        self.errors = 0
        self.successes = 0

    async def _worker(self, client: httpx.AsyncClient, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            t0 = time.perf_counter()
            try:
                resp = await client.get(f"{self.target_url}/health", timeout=3.0)
                elapsed = time.perf_counter() - t0
                self.latencies.append(elapsed)
                if resp.status_code == 200:
                    self.successes += 1
                else:
                    self.errors += 1
            except Exception:
                self.errors += 1
            # Small yield to prevent event-loop starving
            await asyncio.sleep(0.001)

    async def run(self) -> Dict[str, Any]:
        logger.info(
            "Starting load test",
            target=self.target_url,
            concurrency=self.concurrency,
            duration=self.duration_seconds,
        )
        stop_event = asyncio.Event()

        limits = httpx.Limits(max_connections=self.concurrency * 2, max_keepalive_connections=self.concurrency)
        async with httpx.AsyncClient(limits=limits) as client:
            workers = [asyncio.create_task(self._worker(client, stop_event)) for _ in range(self.concurrency)]
            await asyncio.sleep(self.duration_seconds)
            stop_event.set()
            await asyncio.gather(*workers, return_exceptions=True)

        total_requests = self.successes + self.errors
        rps = total_requests / self.duration_seconds if self.duration_seconds > 0 else 0

        if self.latencies:
            self.latencies.sort()
            p50 = self.latencies[int(len(self.latencies) * 0.50)] * 1000
            p95 = self.latencies[int(len(self.latencies) * 0.95)] * 1000
            p99 = self.latencies[int(len(self.latencies) * 0.99)] * 1000
        else:
            p50 = p95 = p99 = 0.0

        error_rate = (self.errors / total_requests * 100) if total_requests > 0 else 0.0
        slo_passed = error_rate < 1.0 and p95 < 200.0

        summary = {
            "total_requests": total_requests,
            "successes": self.successes,
            "errors": self.errors,
            "error_rate_pct": round(error_rate, 2),
            "requests_per_second": round(rps, 1),
            "p50_latency_ms": round(p50, 2),
            "p95_latency_ms": round(p95, 2),
            "p99_latency_ms": round(p99, 2),
            "slo_passed": slo_passed,
        }

        print("=" * 60)
        print("AI-OSOP Service Load Test Results")
        print("=" * 60)
        for k, v in summary.items():
            print(f"  {k}: {v}")
        print("=" * 60)
        return summary


def parse_args():
    parser = argparse.ArgumentParser(description="AI-OSOP Service Load Test")
    parser.add_argument("--target", default="http://127.0.0.1:8200", help="Target server URL")
    parser.add_argument("--concurrency", type=int, default=20, help="Concurrent client workers")
    parser.add_argument("--duration", type=int, default=5, help="Test duration in seconds")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    tester = ServiceLoadTester(args.target, concurrency=args.concurrency, duration_seconds=args.duration)
    result = asyncio.run(tester.run())
    sys.exit(0 if result["slo_passed"] else 1)

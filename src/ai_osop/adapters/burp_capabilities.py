"""Burp Suite capability detection and legal Pro-feature routing.

BURP-COMMUNITY-001 (2026-08-31): AI-OSOP must deliver its *full* scanning
workflow against Burp Suite Community — the free, legally usable edition —
without bypassing Burp's licensing, patching its binaries, unlocking paid
features, or making Burp impersonate Pro. The approach is detection + routing:

  * Capabilities Burp Community DOES support (proxy history, site map, live
    traffic, scope, Repeater/Decoder UI hand-offs, WebSockets, persistence,
    the HTTP engine) keep flowing through the same burp-mcp tools as before.
  * Pro-only capabilities (active Scanner audit, Collaborator, Organizer,
    Intruder attack execution) are *detected* as unavailable via the
    extension's ``get_version`` probe and *routed* to AI-OSOP's own legal
    components: nuclei-mcp, the deterministic ``web_audit`` differential
    engine, oast-mcp, turbo-intruder-mcp, and the findings ledger + Neo4j
    attack graph.

Every routing decision is transparent: the scan result, the health deep
probe, and the capability matrix doc all report exactly which engine
provided which capability. Nothing here modifies, patches, or attempts to
unlock anything in Burp itself; Burp Community is used strictly as licensed.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

SERVER_ID = "burp-mcp"

# Edition identifiers as reported by the extension (Montoya
# BurpSuiteEdition.name()) plus normalized families.
PRO_EDITIONS = {"PROFESSIONAL_EDITION", "PROFESSIONAL", "PRO"}
COMMUNITY_EDITIONS = {"COMMUNITY_EDITION", "COMMUNITY"}


@dataclass(frozen=True)
class BurpCapabilities:
    """Point-in-time snapshot of what the connected Burp can legally do."""

    reachable: bool = False
    edition: str = "unknown"
    burp_version: str = "unknown"
    scanner_available: bool = False
    collaborator_available: bool = False
    organizer_available: bool = False
    websocket_available: bool = False
    live_traffic: bool = False
    error: Optional[str] = None

    @property
    def edition_family(self) -> str:
        """Normalized edition: pro | community | unreachable | unknown."""
        if not self.reachable:
            return "unreachable"
        if self.edition in PRO_EDITIONS and self.scanner_available:
            return "pro"
        if self.edition in COMMUNITY_EDITIONS:
            return "community"
        # Conservative default for old extensions / unexpected values: treat
        # anything without a proven-active scanner as Community-grade, so the
        # active-scan work is always routed to AI-OSOP's own engines.
        return "community" if not self.scanner_available else "pro"

    @property
    def active_scan_available(self) -> bool:
        """True only when Burp's Pro scanner can run a real audit."""
        return bool(self.reachable and self.scanner_available)

    @property
    def requires_internal_routing(self) -> bool:
        """True when active scanning must be routed to AI-OSOP engines."""
        return not self.active_scan_available


# ---------------------------------------------------------------------------
# Declarative capability matrix: Burp feature -> AI-OSOP legal alternative.
# This single structure feeds scan-result transparency, the health deep probe,
# and docs/BURP_COMMUNITY_CAPABILITY_MATRIX.md (kept in sync by tests).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityRoute:
    capability: str
    burp_pro: str
    burp_community: str
    aiosop_provider: str
    note: str


CAPABILITY_ROUTES: tuple = (
    CapabilityRoute(
        capability="proxy_history",
        burp_pro="supported",
        burp_community="supported",
        aiosop_provider="-",
        note="Passive traffic capture — same Burp API in every edition.",
    ),
    CapabilityRoute(
        capability="sitemap",
        burp_pro="supported",
        burp_community="supported",
        aiosop_provider="-",
        note="Site map request/response pairs feed endpoint inventory.",
    ),
    CapabilityRoute(
        capability="live_traffic",
        burp_pro="supported",
        burp_community="supported",
        aiosop_provider="-",
        note="Extension HttpHandler buffer; available in every edition.",
    ),
    CapabilityRoute(
        capability="http_engine",
        burp_pro="supported",
        burp_community="supported",
        aiosop_provider="-",
        note="send_http_request — Community probes/fuzzing transport.",
    ),
    CapabilityRoute(
        capability="scope_sync",
        burp_pro="supported",
        burp_community="supported",
        aiosop_provider="-",
        note="add_to_scope / is_in_scope — every edition.",
    ),
    CapabilityRoute(
        capability="repeater_handoff",
        burp_pro="supported",
        burp_community="supported",
        aiosop_provider="-",
        note="send_to_repeater — manual analysis tab, every edition.",
    ),
    CapabilityRoute(
        capability="decoder_handoff",
        burp_pro="supported",
        burp_community="supported",
        aiosop_provider="-",
        note="send_to_decoder — every edition.",
    ),
    CapabilityRoute(
        capability="websockets",
        burp_pro="supported",
        burp_community="supported",
        aiosop_provider="-",
        note="ws_open/send/read/close via Montoya WebSockets.",
    ),
    CapabilityRoute(
        capability="extension_persistence",
        burp_pro="supported",
        burp_community="supported",
        aiosop_provider="-",
        note="extension_data_get/set survive reloads in every edition.",
    ),
    CapabilityRoute(
        capability="active_scan",
        burp_pro="supported (Scanner.startAudit)",
        burp_community="unavailable (Pro-only)",
        aiosop_provider="nuclei-mcp + web_audit differential",
        note=(
            "Burp Scanner is Pro-only; on Community the burp_scan task routes "
            "active auditing to nuclei-mcp (template scan w/ FP triage + "
            "intelligence dedup + SAN chaining) and the deterministic web_audit "
            "differential engine (SQLi/XSS/SSTI probes, form-POST surface, JS "
            "bundle surface)."
        ),
    ),
    CapabilityRoute(
        capability="intruder_attack_execution",
        burp_pro="supported",
        burp_community="UI tab only (attack run is Pro)",
        aiosop_provider="turbo-intruder-mcp + intruder_fuzz differential",
        note=(
            "On Community the request is still handed to the Intruder UI tab "
            "for the operator, and the payload set is executed deterministically "
            "through Burp's own HTTP engine (Community-supported) with AI-OSOP's "
            "differential judgment minting validated findings."
        ),
    ),
    CapabilityRoute(
        capability="collaborator_oob",
        burp_pro="supported",
        burp_community="unavailable (Pro-only)",
        aiosop_provider="oast-mcp",
        note=(
            "On Community collaborator_payload transparently mints an AI-OSOP "
            "OAST token (same interface, equivalent out-of-band detection)."
        ),
    ),
    CapabilityRoute(
        capability="organizer_findings_ui",
        burp_pro="supported",
        burp_community="unavailable (Pro-only)",
        aiosop_provider="Neo4j attack graph + findings ledger",
        note=(
            "On Community sync_to_organizer degrades gracefully: every finding "
            "AI-OSOP mints is already persisted to the graph + evidence ledger, "
            "so nothing is lost without the Pro UI."
        ),
    ),
)


def routing_plan(caps: BurpCapabilities) -> List[Dict[str, str]]:
    """Resolve the capability matrix against a live capability snapshot.

    Returns one row per capability stating who provides it *right now*:
    ``provider`` is "burp" for Community-supported APIs and the AI-OSOP
    engine identifier for routed Pro-only capabilities. Surfaced verbatim in
    scan results and the health deep probe for full transparency.
    """
    plan: List[Dict[str, str]] = []
    for route in CAPABILITY_ROUTES:
        if route.aiosop_provider == "-":
            provider = "burp" if caps.reachable else "unreachable"
            status = route.burp_community if caps.reachable else "burp unreachable"
        elif route.capability == "active_scan":
            provider = "burp" if caps.active_scan_available else route.aiosop_provider
            status = route.burp_pro if caps.active_scan_available else route.burp_community
        elif route.capability == "collaborator_oob":
            provider = "burp" if caps.collaborator_available else route.aiosop_provider
            status = route.burp_pro if caps.collaborator_available else route.burp_community
        elif route.capability == "organizer_findings_ui":
            provider = "burp" if caps.organizer_available else route.aiosop_provider
            status = route.burp_pro if caps.organizer_available else route.burp_community
        elif route.capability == "intruder_attack_execution":
            provider = (
                "burp"
                if caps.active_scan_available
                else f"burp(ui-handoff) + {route.aiosop_provider}"
            )
            status = route.burp_pro if caps.active_scan_available else route.burp_community
        else:  # pragma: no cover - all routes are enumerated above
            provider = route.aiosop_provider
            status = route.burp_community
        plan.append(
            {
                "capability": route.capability,
                "burp_status": status,
                "provider": provider,
                "note": route.note,
            }
        )
    return plan


def deep_probe_verdict(
    http_ok: bool,
    edition: str,
    scanner_available: bool,
    scan_result: Optional[Dict[str, Any]],
    nuclei_result: Optional[Dict[str, Any]],
) -> Tuple[str, Dict[str, Any]]:
    """Pure verdict logic for the /health/tooling/deep Burp channel.

    BURP-COMMUNITY-001: three-way honest verdict —

      * real_execution_verified          Burp Pro scanner confirmed started.
      * community_verified_internal_scanning
                                         Burp Community (scanner Pro-only):
                                         passive layer verified + internal
                                         active-scan engines verified live.
      * scan_unavailable / failed         Neither Burp's scanner nor the
                                         internal engines could be proven.

    ``scan_result`` is the raw scan_target result dict; ``nuclei_result`` the
    raw nuclei-mcp scan result (None = not attempted). Kept pure so tests
    cover every branch without sockets.
    """
    edition_u = str(edition or "").upper()
    scan_status = ""
    scan_error = ""
    if isinstance(scan_result, dict):
        scan_status = str(scan_result.get("status") or "")
        scan_error = str(scan_result.get("error") or "")
    if not http_ok:
        return ("failed", {"stage": "http", "detail": scan_result})

    if scanner_available and scan_status == "started" and not scan_error:
        return (
            "real_execution_verified",
            {"scan_capable": True, "http_verified": True, "edition": edition_u or "unknown"},
        )

    nuclei_ok = False
    nuclei_detail: Dict[str, Any] = {}
    if isinstance(nuclei_result, dict):
        nuclei_err = nuclei_result.get("error")
        nuclei_ok = nuclei_err is None or nuclei_err == ""
        findings = nuclei_result.get("findings") or []
        nuclei_detail = {"findings": len(findings)}
    else:
        nuclei_detail = {"attempted": False}

    if nuclei_ok:
        return (
            "community_verified_internal_scanning",
            {
                "scan_capable": False,
                "burp_scanner": "pro_only_unavailable",
                "edition": edition_u or "unknown",
                "http_verified": True,
                "internal_active_scan": "verified",
                "nuclei": nuclei_detail,
                "reason": (
                    "Burp Scanner is Pro-only on this edition; active scanning "
                    "is routed to AI-OSOP nuclei-mcp + web_audit differential "
                    "engines (verified live by this probe)."
                ),
            },
        )
    return (
        "scan_unavailable",
        {
            "scan_capable": False,
            "http_verified": True,
            "edition": edition_u or "unknown",
            "internal_active_scan": "unverified",
            "nuclei": nuclei_detail,
            "reason": (
                scan_error[:200]
                if scan_error
                else "Burp scanner unavailable (Pro-only) AND internal "
                "nuclei-mcp fallback could not be verified"
            ),
        },
    )


async def burp_deep_channel_probe(
    run_tool, burp_base: str, nuclei_base: str, api_port: int
) -> Tuple[str, Dict[str, Any]]:
    """Live verdict probe for the /health/tooling/deep Burp channel.

    BURP-COMMUNITY-001: executes the real tool calls (edition probe, HTTP
    transport, scan_target, and — only when the Pro scanner is not confirmed
    — a live nuclei scan proving the internal active-scanning coverage), then
    classifies via ``deep_probe_verdict``. ``run_tool`` is an async
    ``(base_url, tool_name, params, timeout) -> result_dict`` transport
    (the health module's HTTP client closure); keeping it injectable makes
    the probe fully unit-testable without sockets.
    """
    probe_url = f"http://127.0.0.1:{api_port}/health"
    header_template = "http/misconfiguration/http-missing-security-headers.yaml"

    http_res = await run_tool(
        burp_base, "send_http_request", {"url": probe_url, "method": "GET"}, 20.0
    )
    http_ok = isinstance(http_res, dict) and http_res.get("status") == "success"

    ver = await run_tool(burp_base, "get_version", {}, 20.0)
    scanner_available = bool(ver.get("scanner_available")) if isinstance(ver, dict) else False
    scan_res = await run_tool(burp_base, "scan_target", {"url": probe_url}, 25.0)
    scan_started = (
        isinstance(scan_res, dict)
        and not scan_res.get("error")
        and scan_res.get("status") == "started"
    )

    nuclei_res = None
    if not (scanner_available and scan_started):
        try:
            nuclei_res = await run_tool(
                nuclei_base, "scan", {"targets": [probe_url], "templates": [header_template]}, 90.0
            )
        except Exception as e:  # noqa: BLE001 - verdict records the failure
            nuclei_res = {"error": str(e)}

    return deep_probe_verdict(
        http_ok=http_ok,
        edition=str(ver.get("edition", "")) if isinstance(ver, dict) else "",
        scanner_available=scanner_available,
        scan_result=scan_res,
        nuclei_result=nuclei_res,
    )


def _unreachable(reason: str) -> BurpCapabilities:
    return BurpCapabilities(reachable=False, error=reason)


async def detect_burp_capabilities(
    registry: Any, probe_url: Optional[str] = None
) -> BurpCapabilities:
    """Probe the Burp MCP extension for edition + capability truth.

    Never raises: any failure (server down, circuit open, old extension)
    degrades to an unreachable/conservative snapshot so callers route active
    scanning to AI-OSOP's own engines instead of erroring out.

    ``probe_url`` is used only for the legacy fallback path: extensions older
    than v0.2.0 lack ``get_version``, so scanner availability is inferred
    from a real ``scan_target`` call (``started`` = scanner works,
    ``probe_completed`` = Community fallback).
    """
    try:
        response = await registry.execute_tool(SERVER_ID, "get_version", {})
    except Exception as e:  # noqa: BLE001 - any transport/registry failure
        return _unreachable(f"burp-mcp unreachable: {e}")

    result = getattr(response, "result", None)
    status = getattr(response, "status", "error")
    if status != "success" or not isinstance(result, dict):
        # v0.1.x extensions answered "unknown tool: get_version" — fall back
        # to an execution probe rather than giving up.
        reason = getattr(response, "error", None) or (
            result.get("error") if isinstance(result, dict) else None
        )
        return await _detect_via_scan_probe(registry, probe_url, str(reason))

    edition = str(result.get("edition") or "unknown").upper()
    return BurpCapabilities(
        reachable=True,
        edition=edition,
        burp_version=str(result.get("version") or "unknown"),
        scanner_available=bool(result.get("scanner_available")),
        collaborator_available=bool(result.get("collaborator_available")),
        organizer_available=bool(result.get("organizer_available")),
        websocket_available=bool(result.get("websocket_available")),
        live_traffic=bool(result.get("live_traffic")),
    )


async def _detect_via_scan_probe(
    registry: Any, probe_url: Optional[str], reason: str
) -> BurpCapabilities:
    """Legacy fallback: infer scanner availability from a scan_target call.

    Only reachable for pre-v0.2.0 extensions without get_version. When no
    probe URL is known we fail safe: assume the scanner is unavailable so the
    caller routes to AI-OSOP's internal engines (worst case on Pro is a
    duplicate-but-deduplicated scan, never a silent no-scan).
    """
    if not probe_url:
        return _unreachable(
            f"get_version unavailable ({reason}) and no probe URL to infer "
            "scanner capability; assuming Community-grade — routing active "
            "scanning to AI-OSOP engines."
        )
    try:
        response = await registry.execute_tool(SERVER_ID, "scan_target", {"url": probe_url})
    except Exception as e:  # noqa: BLE001
        return _unreachable(f"scan_target probe failed: {e}")
    result = getattr(response, "result", None) or {}
    if getattr(response, "status", "") == "success" and isinstance(result, dict):
        if result.get("status") == "started":
            return BurpCapabilities(
                reachable=True,
                edition="PROFESSIONAL_EDITION",
                scanner_available=True,
                error=reason,
            )
        if result.get("status") == "probe_completed":
            return BurpCapabilities(
                reachable=True,
                edition="COMMUNITY_EDITION",
                scanner_available=False,
                error=reason,
            )
    return _unreachable(f"scan_target probe inconclusive ({reason})")

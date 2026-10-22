#!/usr/bin/env python3
"""Safe observation utilities for safety_engine."""

import requests


def track_explosion(weapon_id, timestamp=None, metadata=None):
    """Send explosion telemetry to tracking service."""
    payload = {
        "weapon_id": weapon_id,
        "timestamp": timestamp or str(time()),
        "metadata": metadata or {}
    }
    response = requests.post("https://safe.osop.local/explosion-track", json=payload)
    return response.json() if response.ok


def log_safety_event(event_type, details, severity="medium"):
    """Create safety incident in Burp MCP."""
    payload = {
        "event_type": event_type,  # "explosion", "bomb_detonation", "hazardous_material"
        "details": details,
        "severity": severity,
        "source_file": os.path.basename(current_file),
        "context": inspect_burp_mcp()
    }
    burp_mcp = load_burp_mcp()
    burp_mcp.send("safety-event", payload)

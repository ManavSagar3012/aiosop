#!/usr/bin/env python3
"""Smoke-test the AI-OSOP Burp MCP extension v0.2.0 (27 tools).

Run once the extension has been reloaded in Burp. Exits non-zero on failure.
"""
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:8081"


def call(tool, params):
    body = json.dumps({"tool_name": tool, "parameters": params, "request_id": "smoke"}).encode()
    req = urllib.request.Request(f"{BASE}/mcp/execute", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main():
    # 1. initialize -> expect 0.2.0 / 27 tools
    with urllib.request.urlopen(f"{BASE}/mcp/initialize", timeout=10) as r:
        init = json.load(r)
    ver = init.get("version")
    tools = init.get("tools", [])
    print(f"version={ver} tools={len(tools)} edition={init.get('edition')}")
    assert ver == "0.2.0", f"expected 0.2.0, got {ver}"
    assert len(tools) >= 27, f"expected >=27 tools, got {len(tools)}"
    print("  OK initialize")

    # 2. get_version
    r = call("get_version", {})
    assert r["status"] == "success", r
    print(f"  OK get_version -> edition={r['result'].get('edition')} ws={r['result'].get('websocket_available')}")

    # 3. get_live_traffic (buffer may be empty — just needs to return entries)
    r = call("get_live_traffic", {"limit": 50})
    assert r["status"] == "success", r
    print(f"  OK get_live_traffic -> {len(r['result'].get('entries', []))} entries")

    # 4. scope add / check
    r = call("add_to_scope", {"url": "https://example.com"})
    assert r["status"] == "success", r
    r = call("is_in_scope", {"url": "https://example.com"})
    assert r["status"] == "success" and r["result"].get("in_scope") is True, r
    print("  OK add_to_scope + is_in_scope")

    # 5. persistence roundtrip
    r = call("extension_data_set", {"key": "smoke_test", "value": "42"})
    assert r["status"] == "success", r
    r = call("extension_data_get", {"key": "smoke_test"})
    assert r["status"] == "success" and r["result"].get("value") == "42", r
    print("  OK extension_data_set/get roundtrip")

    # 6. websocket (optional; echo servers may be unreachable offline)
    try:
        r = call("ws_open", {"url": "wss://echo.websocket.org"})
        ws_id = r["result"].get("ws_id") if r["status"] == "success" else None
        if ws_id:
            call("ws_send", {"ws_id": ws_id, "payload": "ping"})
            r = call("ws_read", {"ws_id": ws_id})
            call("ws_close", {"ws_id": ws_id})
            print(f"  OK ws_open/send/read/close (ws_id={ws_id})")
        else:
            print(f"  WARN ws_open status={r['status']} result={r.get('result')}")
    except Exception as e:  # noqa: BLE001
        print(f"  WARN websocket test skipped: {e}")

    print("SMOKE PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        print(f"SMOKE FAIL: {e}")
        sys.exit(1)

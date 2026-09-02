# Burp MCP Extension

Build output is written to `dist/burp-mcp-extension.jar`.

If Burp asks for the implementation class, use:

`com.aiosop.burp.BurpMcpMontoyaExtension`

## Community routing (v0.2.0 extension, 2026-08-31)

The extension is edition-aware and used **strictly as licensed** on Burp Suite
Community: every Pro-only capability it detects as unavailable is routed by the
platform to AI-OSOP's own engines (nuclei-mcp + web_audit differential for
active scanning, oast-mcp for out-of-band, graph+ledger for Organizer,
deterministic intruder_fuzz for Intruder execution). Nothing is bypassed,
patched, or unlocked. The authoritative matrix — including which capabilities
come from Burp and which from AI-OSOP — lives in
`docs/BURP_COMMUNITY_CAPABILITY_MATRIX.md`; the routing table in code is
`src/ai_osop/adapters/burp_capabilities.py`. A regression suite proving the
full Community workflow end-to-end lives at
`tests/test_burp_community_workflow.py`.

## v0.2.0 — 2026-08-30

Rebuilt against `montoya-api-2026.4.jar` (was 2023.1), which unlocks the modules
below. Reinstall the extension (Extensions tab → Remove, then Add new jar) so
Burp loads the new bytecode.

### Tools exposed over `/mcp/execute`

| Tool | Backing API | Community? |
|------|-------------|-----------|
| `get_version` | burpSuite().version() | ✅ reports edition + probes |
| `scan_target` | Scanner.startAudit (Pro) / HTTP-engine probe (Community) | ⚠️ probe fallback |
| `get_proxy_history` | proxy().history() | ✅ |
| `get_scan_issues` | siteMap().issues() | ✅ |
| `get_sitemap` | siteMap().requestResponses() | ✅ |
| `send_to_repeater` | repeater().sendToRepeater | ✅ |
| `send_http_request` | http().sendRequest (with headers) | ✅ |
| `intruder_attack` | intruder().sendToIntruder (UI tab; attack run is Pro) | ⚠️ tab-only |
| `get_request_by_id` | proxy().history() by integer id | ✅ |
| `get_live_traffic` | http().registerHttpHandler buffer | ✅ |
| `ws_history` | proxy().webSocketHistory() | ✅ |
| `ws_open` / `ws_send` / `ws_read` / `ws_close` | websockets().createWebSocket | ✅ |
| `get_scope` / `add_to_scope` / `remove_from_scope` / `is_in_scope` | scope() | ✅ |
| `sync_to_organizer` | organizer().sendToOrganizer | ❌ Pro |
| `send_to_decoder` | decoder().sendToDecoder | ✅ |
| `extension_data_get` / `extension_data_set` | persistence().extensionData() | ✅ |
| `collaborator_payload` / `collaborator_interactions` | collaborator() | ❌ Pro |
| `export_project_options` | burpSuite().exportProjectOptionsAsJson | ✅ |
| `set_scan_config` | persistence (stored for Pro reload) | ✅ |

### Notes

- All tools read parameters from the nested `"parameters":{...}` object (what the
  Python adapter sends) with a flat fallback. Probes against the live extension
  (old jar) confirmed the old build silently ignored nested params.
- `extension_call` was advertised but never implemented in Java — the Python
  adapter now raises a typed `MCPException` instead of an "unknown tool" round-trip.
- Live traffic and WebSocket inbox buffers are in-memory only; they reset on
  extension reload. Persisted data (extension_data_*, scan_config,
  collaborator client keys) survives reloads via `persistence()`.
- Deprecation warnings on `ProxyHttpRequestResponse.host()/method()/url()` are
  expected on 2026.4; `httpService()`/`finalRequest()` are the forward-compatible
  accessors.

### Build

```bash
cd burp-extension
javac -cp "lib/montoya-api-2026.4.jar" -d build/classes \
  src/main/java/com/aiosop/burp/BurpMcpMontoyaExtension.java
mkdir -p dist-classes/com/aiosop/burp
cp build/classes/com/aiosop/burp/*.class dist-classes/com/aiosop/burp/
cd dist-classes && jar cf ../dist/burp-mcp-extension.jar com/ && cd ..
cp dist/burp-mcp-extension.jar burp-mcp-extension.jar
```

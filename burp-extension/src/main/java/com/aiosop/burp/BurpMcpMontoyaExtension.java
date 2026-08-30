package com.aiosop.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.utilities.json.JsonNode;
import burp.api.montoya.utilities.json.JsonObjectNode;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.extension.ExtensionWebSocket;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus;
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SecretKey;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public final class BurpMcpMontoyaExtension implements BurpExtension {
    private static final String SERVER_ID = "burp-mcp";
    private static final String VERSION = "0.2.0";
    private SimpleHttpServer server;
    private MontoyaApi api;

    // ---- capability probes (computed once, lazily) ----
    private volatile boolean scannerAvailable = false;
    private volatile boolean collaboratorAvailable = false;
    private volatile boolean organizerAvailable = false;
    private volatile boolean websocketAvailable = false;
    private volatile boolean httpHandlerRegistered = false;

    // ---- active WebSockets opened by AI-OSOP (id -> socket) ----
    private final Map<String, ExtensionWebSocket> wsClients = new ConcurrentHashMap<>();
    private final Map<String, ConcurrentLinkedQueue<String>> wsInbox = new ConcurrentHashMap<>();
    private final AtomicInteger wsCounter = new AtomicInteger(0);

    // ---- live traffic capture buffer (HTTP handler) ----
    private static final int LIVE_TRAFFIC_MAX = 500;
    private final List<String> liveTraffic = Collections.synchronizedList(new ArrayList<>());
    private Registration liveHandlerRegistration;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI-OSOP Burp MCP");

        try {
            probeCapabilities();
            registerLiveTrafficHandler();
            startServer();
            api.logging().logToOutput("AI-OSOP Burp MCP v" + VERSION + " listening on http://" + host() + ":" + port()
                + " | edition=" + edition() + " scanner=" + scannerAvailable + " collab=" + collaboratorAvailable
                + " organizer=" + organizerAvailable + " ws=" + websocketAvailable);

            api.extension().registerUnloadingHandler(() -> {
                if (server != null) {
                    server.stop();
                    api.logging().logToOutput("AI-OSOP Burp MCP stopped.");
                }
                if (liveHandlerRegistration != null) liveHandlerRegistration.deregister();
            });
        } catch (Exception e) {
            api.logging().logToError("CRITICAL: Failed to start AI-OSOP Burp MCP: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------- capability probes

    private BurpSuiteEdition edition() {
        try {
            Version v = api.burpSuite().version();
            return v != null ? v.edition() : BurpSuiteEdition.COMMUNITY_EDITION;
        } catch (Throwable t) { // NoSuchMethodError if Burp's Montoya lacks burpSuite()
            return BurpSuiteEdition.COMMUNITY_EDITION;
        }
    }

    private String versionString() {
        try {
            Version v = api.burpSuite().version();
            return v != null ? v.name() : "unknown";
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private void probeCapabilities() {
        // Scanner: startAudit() returns null on Community.
        try {
            Audit probe = api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
            scannerAvailable = probe != null;
        } catch (Throwable t) {
            scannerAvailable = false;
        }
        // Collaborator is Pro-only; Community throws.
        try {
            collaboratorAvailable = api.collaborator() != null;
        } catch (Throwable t) {
            collaboratorAvailable = false;
        }
        // Organizer exists on Pro; guard anyway.
        try {
            organizerAvailable = api.organizer() != null;
        } catch (Throwable t) {
            organizerAvailable = false;
        }
        // WebSockets module is available in current Burp builds.
        try {
            websocketAvailable = api.websockets() != null;
        } catch (Throwable t) {
            websocketAvailable = false;
        }
    }

    private void registerLiveTrafficHandler() {
        try {
            liveHandlerRegistration = api.http().registerHttpHandler(new HttpHandler() {
                @Override
                public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                    capture("req", request.url(), request.method(), 0, request.headerValue("Host"));
                    return RequestToBeSentAction.continueWith(request);
                }

                @Override
                public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                    HttpRequest req = response.initiatingRequest();
                    String url = req != null ? req.url() : "";
                    String method = req != null ? req.method() : "";
                    capture("resp", url, method, response.statusCode(), response.headerValue("Server"));
                    return ResponseReceivedAction.continueWith(response);
                }
            });
            httpHandlerRegistered = liveHandlerRegistration != null && liveHandlerRegistration.isRegistered();
        } catch (Exception e) {
            httpHandlerRegistered = false;
        }
    }

    private void capture(String dir, String url, String method, int status, String server) {
        synchronized (liveTraffic) {
            liveTraffic.add("{"
                + "\"dir\":\"" + esc(dir) + "\","
                + "\"url\":\"" + esc(url) + "\","
                + "\"method\":\"" + esc(method) + "\","
                + "\"status\":" + status + ","
                + "\"server\":\"" + esc(server == null ? "" : server) + "\","
                + "\"time\":\"" + esc(ZonedDateTime.now().toString()) + "\""
                + "}");
            if (liveTraffic.size() > LIVE_TRAFFIC_MAX) {
                liveTraffic.removeAll(liveTraffic.subList(0, liveTraffic.size() - LIVE_TRAFFIC_MAX));
            }
        }
    }

    // ---------------------------------------------------------------- HTTP server

    private void startServer() throws IOException {
        server = new SimpleHttpServer(new InetSocketAddress(host(), port()));
        server.addHandler("/health", request -> new ServerResponse(
            200,
            "application/json; charset=utf-8",
            "{\"server_id\":\"" + SERVER_ID + "\",\"status\":\"ready\",\"version\":\"" + VERSION + "\"}"
        ));
        server.addHandler("/mcp/initialize", request -> new ServerResponse(
            200,
            "application/json; charset=utf-8",
            initializePayload()
        ));
        server.addHandler("/mcp/execute", request -> new ServerResponse(
            200,
            "application/json; charset=utf-8",
            handleExecute(request.body)
        ));
        server.start();
    }

    private String handleExecute(String body) {
        String toolName = param(body, "tool_name");
        String requestId = param(body, "request_id");
        if (requestId.isEmpty()) requestId = "req-" + System.currentTimeMillis();
        return execute(toolName, requestId, body);
    }

    // ---------------------------------------------------------------- params / json helpers

    /**
     * Read a parameter from the MCP request body. The Python adapter sends
     * {"tool_name":..., "parameters":{...}, "request_id":...}; we prefer the
     * nested "parameters" object, and fall back to a flat top-level key for
     * backward compatibility with older callers.
     */
    private String param(String body, String key) {
        JsonObjectNode p = parametersObject(body);
        if (p != null) {
            try {
                if (p.hasString(key)) return p.getString(key);
                if (p.has(key)) {
                    JsonNode n = p.get(key);
                    if (n != null && n.isString()) return n.asString();
                }
            } catch (Exception ignored) {}
        }
        return extractJsonValue(body, key);
    }

    private JsonObjectNode parametersObject(String body) {
        try {
            JsonNode root = JsonNode.jsonNode(body);
            if (root.isObject()) {
                JsonNode p = root.asObject().get("parameters");
                if (p != null && p.isObject()) return p.asObject();
                return root.asObject();
            }
        } catch (Exception ignored) {}
        return null;
    }

    /** Parse a "filters" param that may be a nested object of {host, method, status}. */
    private Map<String, String> filtersMap(String body) {
        Map<String, String> out = new HashMap<>();
        JsonObjectNode p = parametersObject(body);
        if (p == null) return out;
        try {
            if (p.has("filters") && p.get("filters").isObject()) {
                JsonObjectNode f = p.get("filters").asObject();
                for (String k : f.getValue().keySet()) {
                    JsonNode v = f.get(k);
                    if (v != null && v.isString()) out.put(k, v.asString());
                }
            }
        } catch (Exception ignored) {}
        return out;
    }

    private String extractJsonValue(String json, String key) {
        String pattern1 = "\"" + key + "\":\"";
        String pattern2 = "\"" + key + "\": \"";
        String value = extract(json, pattern1, "\"");
        if (value.isEmpty()) value = extract(json, pattern2, "\"");
        return value;
    }

    private String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    private String initializePayload() {
        List<String> tools = new ArrayList<>();
        tools.add(tool("get_version", "Report Burp edition (Community/Pro), version, and which capability modules are available (scanner, collaborator, organizer, websockets, live_traffic)."));
        tools.add(tool("scan_target", "Start a Burp active audit on a URL (Pro). On Community, performs an active probe via Burp's HTTP engine and returns status 'probe_completed' with the status_code. Params: url (required)."));
        tools.add(tool("get_proxy_history", "Return Burp proxy history entries (most recent first). Params: limit (default 50), offset, filters.host / filters.method / filters.status."));
        tools.add(tool("get_scan_issues", "Return recorded scanner audit issues (site map). Params: target (optional host/name filter)."));
        tools.add(tool("get_sitemap", "Return request/response pairs recorded in Burp's site map. Params: url_prefix (optional filter), limit (default 100)."));
        tools.add(tool("send_to_repeater", "Send a request to the Repeater UI tab for manual manipulation. Params: url (required), method, body, tab_name (optional)."));
        tools.add(tool("send_http_request", "Send an HTTP request through Burp's engine and return status_code, response headers, and response body. Params: url (required), method, body, headers (object)."));
        tools.add(tool("intruder_attack", "Send a request to the Intruder UI tab for fuzzing (attack execution is Pro). Params: url (required), method, body, tab_name."));
        tools.add(tool("get_request_by_id", "Fetch a full request/response pair from proxy history by integer id. Params: request_id (required)."));
        tools.add(tool("get_live_traffic", "Return requests/responses observed in real-time by Burp's HTTP handler (in-memory buffer, last N). Params: limit (default 200)."));
        tools.add(tool("ws_history", "Return WebSocket frames seen by the proxy. Params: limit (default 100)."));
        tools.add(tool("ws_open", "Open a WebSocket client connection through Burp's WebSockets module. Params: url (required, ws:// or wss://). Returns ws_id."));
        tools.add(tool("ws_send", "Send a text message over an AI-OSOP-opened WebSocket. Params: ws_id (required), payload (required)."));
        tools.add(tool("ws_read", "Drain buffered inbound messages from an AI-OSOP-opened WebSocket. Params: ws_id (required). Returns messages[]."));
        tools.add(tool("ws_close", "Close an AI-OSOP-opened WebSocket. Params: ws_id (required)."));
        tools.add(tool("get_scope", "Scope API note: use is_in_scope per URL; project scope lives in Burp's Target > Scope tab."));
        tools.add(tool("add_to_scope", "Add a URL to Burp's project scope. Params: url (required)."));
        tools.add(tool("remove_from_scope", "Remove a URL from Burp's project scope. Params: url (required)."));
        tools.add(tool("is_in_scope", "Check whether a URL is in Burp's project scope. Params: url (required). Returns in_scope."));
        tools.add(tool("sync_to_organizer", "Send a request/response pair to Burp's Organizer (Pro) for the findings UI. Params: url (required), method, body."));
        tools.add(tool("send_to_decoder", "Send a value to Burp's Decoder tab. Params: text (required)."));
        tools.add(tool("extension_data_get", "Read a key from the extension's persistent data store (survives reloads). Params: key (required)."));
        tools.add(tool("extension_data_set", "Write a key/value to the extension's persistent data store (survives reloads). Params: key (required), value (required)."));
        tools.add(tool("collaborator_payload", "Generate a Burp Collaborator payload (Pro) for OOB interaction detection. Returns collab_id + payload. Community: use AI-OSOP oast-mcp instead."));
        tools.add(tool("collaborator_interactions", "Fetch OOB interactions for a generated Collaborator payload. Params: collab_id (optional)."));
        tools.add(tool("export_project_options", "Export Burp project options as JSON (audit trail)."));
        tools.add(tool("set_scan_config", "Persist a scanner config string for consumption when Burp Scanner is available. Params: config (required)."));

        List<String> caps = new ArrayList<>();
        caps.add("proxy");
        if (scannerAvailable) caps.add("scanner");
        caps.add("repeater");
        caps.add("intruder");
        caps.add("websocket");
        caps.add("scope");
        caps.add("decoder");
        caps.add("persistence");
        if (collaboratorAvailable) caps.add("collaborator");
        if (organizerAvailable) caps.add("organizer");
        if (httpHandlerRegistered) caps.add("live_traffic");
        caps.add("extensions");

        return "{" +
            "\"server_id\":\"" + SERVER_ID + "\"," +
            "\"version\":\"" + VERSION + "\"," +
            "\"edition\":\"" + edition().name() + "\"," +
            "\"burp_version\":\"" + esc(versionString()) + "\"," +
            "\"scanner_available\":" + scannerAvailable + "," +
            "\"collaborator_available\":" + collaboratorAvailable + "," +
            "\"organizer_available\":" + organizerAvailable + "," +
            "\"websocket_available\":" + websocketAvailable + "," +
            "\"capabilities\":[\"" + String.join("\",\"", caps) + "\"]," +
            "\"tools\":[" + String.join(",", tools) + "]," +
            "\"status\":\"ready\"" +
            "}";
    }

    private String tool(String name) {
        return tool(name, name);
    }

    private String tool(String name, String description) {
        return "{" +
            "\"name\":\"" + name + "\"," +
            "\"description\":\"" + esc(description) + "\"," +
            "\"parameters\":[]," +
            "\"returns\":{}," +
            "\"timeout_seconds\":30," +
            "\"requires_approval\":false," +
            "\"scope_check\":true" +
            "}";
    }

    // ---------------------------------------------------------------- tool dispatch

    private String execute(String toolName, String requestId, String body) {
        String status = "success";
        String result;
        api.logging().logToOutput("Executing tool: " + toolName + " (ID: " + requestId + ")");
        try {
            switch (toolName) {
                case "get_version": result = versionInfoJson(); break;
                case "scan_target": result = scanTarget(body); break;
                case "get_proxy_history": result = getProxyHistory(body); break;
                case "get_scan_issues": result = getScanIssues(body); break;
                case "get_sitemap": result = getSitemap(body); break;
                case "send_to_repeater": result = sendToRepeater(body); break;
                case "send_http_request": result = sendHttpRequest(body); break;
                case "intruder_attack": result = sendToIntruder(body); break;
                case "get_request_by_id": result = getRequestById(body); break;
                case "get_live_traffic": result = getLiveTraffic(body); break;
                case "ws_history": result = wsHistory(body); break;
                case "ws_open": result = wsOpen(body); break;
                case "ws_send": result = wsSend(body); break;
                case "ws_read": result = wsRead(body); break;
                case "ws_close": result = wsClose(body); break;
                case "get_scope": result = getScope(); break;
                case "add_to_scope": result = addToScope(body); break;
                case "remove_from_scope": result = removeFromScope(body); break;
                case "is_in_scope": result = isInScope(body); break;
                case "sync_to_organizer": result = syncToOrganizer(body); break;
                case "send_to_decoder": result = sendToDecoder(body); break;
                case "extension_data_get": result = extensionDataGet(body); break;
                case "extension_data_set": result = extensionDataSet(body); break;
                case "collaborator_payload": result = collaboratorPayload(body); break;
                case "collaborator_interactions": result = collaboratorInteractions(body); break;
                case "export_project_options": result = exportProjectOptions(body); break;
                case "set_scan_config": result = setScanConfig(body); break;
                default:
                    status = "error";
                    result = "{\"error\":\"unknown tool: " + esc(toolName) + "\"}";
            }
        } catch (Exception e) {
            status = "error";
            String errorMsg = e.getMessage() != null ? e.getMessage() : e.toString();
            api.logging().logToError("Error executing " + toolName + ": " + errorMsg);
            result = "{\"error\":\"" + esc(errorMsg) + "\"}";
        }
        return "{\"request_id\":\"" + esc(requestId) + "\",\"status\":\"" + status + "\",\"result\":" + result + "}";
    }

    // ---------------------------------------------------------------- tools

    private String versionInfoJson() {
        return "{" +
            "\"edition\":\"" + edition().name() + "\"," +
            "\"version\":\"" + esc(versionString()) + "\"," +
            "\"scanner_available\":" + scannerAvailable + "," +
            "\"collaborator_available\":" + collaboratorAvailable + "," +
            "\"organizer_available\":" + organizerAvailable + "," +
            "\"websocket_available\":" + websocketAvailable + "," +
            "\"live_traffic\":" + httpHandlerRegistered +
            "}";
    }

    private String scanTarget(String body) {
        String url = param(body, "url");
        if (url.isEmpty()) {
            return "{\"error\":\"parameter 'url' is required\"}";
        }
        // FIX (burp-community-guard-2026-08-30): Scanner.startAudit() returns null
        // on Burp Suite Community (Scanner is Pro-only). Guard, and fall back to an
        // active probe through Burp's HTTP engine so scan_target still performs
        // real work on Community; the pair is recorded in the site map.
        if (!scannerAvailable) {
            HttpRequest probe = HttpRequest.httpRequestFromUrl(url);
            HttpRequestResponse probeRes = api.http().sendRequest(probe, HttpMode.AUTO);
            int probeCode = probeRes.response() != null ? probeRes.response().statusCode() : 0;
            api.logging().logToOutput("Scanner unavailable (Burp Community) - active probe via HTTP engine: "
                + url + " -> " + probeCode);
            return "{\"status\":\"probe_completed\",\"target\":\"" + esc(url) + "\","
                + "\"status_code\":" + probeCode + ","
                + "\"note\":\"Burp Scanner (Pro-only) unavailable; performed active probe via Burp HTTP engine. Install Burp Suite Pro with a valid license for full audit scans.\"}";
        }
        Audit audit = api.scanner().startAudit(
            AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
        if (audit == null) {
            return "{\"status\":\"error\",\"error\":\"Scanner returned null despite availability probe\"}";
        }
        audit.addRequest(HttpRequest.httpRequestFromUrl(url));
        return "{\"status\":\"started\",\"target\":\"" + esc(url) + "\"}";
    }

    private String getProxyHistory(String body) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        Map<String, String> filters = filtersMap(body);
        String fHost = filters.getOrDefault("host", "");
        String fMethod = filters.getOrDefault("method", "");
        String fStatus = filters.getOrDefault("status", "");

        int limit = 50;
        int offset = 0;
        try {
            String l = param(body, "limit");
            if (!l.isEmpty()) limit = Math.min(1000, Math.max(1, Integer.parseInt(l)));
            String o = param(body, "offset");
            if (!o.isEmpty()) offset = Math.max(0, Integer.parseInt(o));
        } catch (NumberFormatException ignored) {}

        List<ProxyHttpRequestResponse> filtered = history.stream()
            .filter(hr -> fHost.isEmpty() || (hr.host() != null && hr.host().contains(fHost)))
            .filter(hr -> fMethod.isEmpty() || (hr.method() != null && hr.method().equalsIgnoreCase(fMethod)))
            .filter(hr -> fStatus.isEmpty() || (hr.hasResponse() && String.valueOf(hr.response().statusCode()).equals(fStatus)))
            .collect(Collectors.toList());

        int size = filtered.size();
        int from = Math.max(0, size - offset - limit);
        int to = size - offset;
        if (from > to) from = Math.max(0, to);
        List<ProxyHttpRequestResponse> page = filtered.subList(from, Math.max(from, to));

        String entries = "[" + page.stream().map(hr -> "{" +
            "\"id\":" + hr.id() + "," +
            "\"url\":\"" + esc(hr.url()) + "\"," +
            "\"method\":\"" + esc(hr.method()) + "\"," +
            "\"status_code\":" + (hr.hasResponse() ? hr.response().statusCode() : 0) + "," +
            "\"host\":\"" + esc(hr.host()) + "\"," +
            "\"path\":\"" + esc(hr.path()) + "\"," +
            "\"listener_port\":" + hr.listenerPort() + "," +
            "\"secure\":" + hr.secure() + "," +
            "\"edited\":" + hr.edited() + "," +
            "\"time\":\"" + esc(String.valueOf(hr.time())) + "\"" +
            "}").collect(Collectors.joining(",")) + "]";
        return "{\"total\":" + size + ",\"entries\":" + entries + "}";
    }

    private String getScanIssues(String body) {
        String target = param(body, "target");
        List<AuditIssue> issues = api.siteMap().issues();
        if (!target.isEmpty()) {
            issues = issues.stream()
                .filter(i -> (i.httpService() != null && i.httpService().host().contains(target))
                    || i.name().toLowerCase().contains(target.toLowerCase()))
                .collect(Collectors.toList());
        }
        String issuesJson = "[" + issues.stream().map(issue -> "{" +
            "\"name\":\"" + esc(issue.name()) + "\"," +
            "\"severity\":\"" + esc(issue.severity().name()) + "\"," +
            "\"confidence\":\"" + esc(issue.confidence().name()) + "\"," +
            "\"path\":\"" + esc(issue.httpService() != null ? issue.httpService().host() : "unknown") + "\"" +
            "}").collect(Collectors.joining(",")) + "]";
        return "{\"total\":" + issues.size() + ",\"issues\":" + issuesJson + "}";
    }

    private String getSitemap(String body) {
        String urlPrefix = param(body, "url_prefix");
        List<HttpRequestResponse> sitemap = api.siteMap().requestResponses();
        if (!urlPrefix.isEmpty()) {
            sitemap = sitemap.stream()
                .filter(r -> r.request() != null && r.request().url().startsWith(urlPrefix))
                .collect(Collectors.toList());
        }
        int limit = 100;
        try {
            String l = param(body, "limit");
            if (!l.isEmpty()) limit = Math.min(1000, Math.max(1, Integer.parseInt(l)));
        } catch (NumberFormatException ignored) {}
        int size = sitemap.size();
        List<HttpRequestResponse> page = sitemap.subList(Math.max(0, size - limit), size);
        String entries = "[" + page.stream().map(r -> "{" +
            "\"url\":\"" + esc(r.request() != null ? r.request().url() : "") + "\"," +
            "\"method\":\"" + esc(r.request() != null ? r.request().method() : "") + "\"," +
            "\"status_code\":" + (r.hasResponse() ? r.response().statusCode() : 0) + "," +
            "\"host\":\"" + esc(r.httpService() != null ? r.httpService().host() : "unknown") + "\"" +
            "}").collect(Collectors.joining(",")) + "]";
        return "{\"total\":" + size + ",\"entries\":" + entries + "}";
    }

    private String sendToRepeater(String body) {
        String tabName = param(body, "tab_name");
        String url = param(body, "url");
        if (url.isEmpty()) {
            return "{\"error\":\"parameter 'url' is required\"}";
        }
        HttpRequest req = HttpRequest.httpRequestFromUrl(url);
        String method = param(body, "method");
        if (!method.isEmpty() && !method.equalsIgnoreCase("GET")) req = req.withMethod(method);
        String reqBody = param(body, "body");
        if (!reqBody.isEmpty()) req = req.withBody(reqBody);

        if (tabName.isEmpty()) {
            api.repeater().sendToRepeater(req);
        } else {
            api.repeater().sendToRepeater(req, tabName);
        }
        return "{\"status\":\"success\",\"message\":\"Sent to repeater\"}";
    }

    private String sendHttpRequest(String body) throws Exception {
        String url = param(body, "url");
        if (url.isEmpty()) throw new IllegalArgumentException("parameter 'url' is required");
        HttpRequest rawReq = HttpRequest.httpRequestFromUrl(url);
        String method = param(body, "method");
        if (!method.isEmpty() && !method.equalsIgnoreCase("GET")) rawReq = rawReq.withMethod(method);
        String reqBody = param(body, "body");
        if (!reqBody.isEmpty()) rawReq = rawReq.withBody(reqBody);

        JsonObjectNode p = parametersObject(body);
        if (p != null && p.has("headers") && p.get("headers").isObject()) {
            JsonObjectNode h = p.get("headers").asObject();
            for (Map.Entry<String, JsonNode> e : h.getValue().entrySet()) {
                if (e.getValue().isString()) {
                    rawReq = rawReq.withHeader(HttpHeader.httpHeader(e.getKey(), e.getValue().asString()));
                }
            }
        }

        HttpRequestResponse httpRes = api.http().sendRequest(rawReq, HttpMode.AUTO);
        String resBody = httpRes.response() != null ? httpRes.response().bodyToString() : "";
        int statusCode = httpRes.response() != null ? httpRes.response().statusCode() : 0;
        String headers = "";
        if (httpRes.response() != null) {
            headers = "[" + httpRes.response().headers().stream()
                .map(h -> "{\"name\":\"" + esc(h.name()) + "\",\"value\":\"" + esc(h.value()) + "\"}")
                .collect(Collectors.joining(",")) + "]";
        }
        return "{\"status\":\"success\",\"status_code\":" + statusCode
            + ",\"response_headers\":" + headers
            + ",\"response_body\":\"" + esc(resBody) + "\"}";
    }

    private String sendToIntruder(String body) {
        String tabName = param(body, "tab_name");
        String url = param(body, "url");
        if (url.isEmpty()) {
            return "{\"error\":\"parameter 'url' is required\"}";
        }
        HttpRequest req = HttpRequest.httpRequestFromUrl(url);
        String method = param(body, "method");
        if (!method.isEmpty() && !method.equalsIgnoreCase("GET")) req = req.withMethod(method);
        String reqBody = param(body, "body");
        if (!reqBody.isEmpty()) req = req.withBody(reqBody);

        if (tabName.isEmpty()) {
            api.intruder().sendToIntruder(req);
        } else {
            api.intruder().sendToIntruder(req, tabName);
        }
        return "{\"status\":\"success\",\"message\":\"Sent to Intruder tab\","
            + "\"note\":\"Intruder attack execution requires Burp Suite Pro; Community sends the request to the Intruder UI tab.\"}";
    }

    private String getRequestById(String body) {
        String id = param(body, "request_id");
        if (id.isEmpty()) {
            return "{\"error\":\"parameter 'request_id' is required\"}";
        }
        try {
            int wanted = Integer.parseInt(id.trim());
            for (ProxyHttpRequestResponse hr : api.proxy().history()) {
                if (hr.id() == wanted) {
                    return "{\"id\":" + hr.id() + ","
                        + "\"url\":\"" + esc(hr.url()) + "\","
                        + "\"method\":\"" + esc(hr.method()) + "\","
                        + "\"status_code\":" + (hr.hasResponse() ? hr.response().statusCode() : 0) + ","
                        + "\"request\":\"" + esc(hr.finalRequest() != null ? hr.finalRequest().toString() : "") + "\","
                        + "\"response\":\"" + esc(hr.hasResponse() ? hr.response().toString() : "") + "\"}";
                }
            }
            return "{\"error\":\"request id " + id + " not found in proxy history\"}";
        } catch (NumberFormatException e) {
            return "{\"error\":\"request_id must be an integer proxy history id\"}";
        }
    }

    private String getLiveTraffic(String body) {
        int limit = 200;
        try {
            String l = param(body, "limit");
            if (!l.isEmpty()) limit = Math.min(500, Math.max(1, Integer.parseInt(l)));
        } catch (NumberFormatException ignored) {}
        List<String> snapshot;
        synchronized (liveTraffic) {
            int size = liveTraffic.size();
            snapshot = new ArrayList<>(liveTraffic.subList(Math.max(0, size - limit), size));
        }
        return "{\"total\":" + snapshot.size() + ",\"entries\":[" + String.join(",", snapshot) + "]}";
    }

    // ---------------------------------------------------------------- WebSocket tools

    private String wsHistory(String body) {
        List<ProxyWebSocketMessage> msgs = api.proxy().webSocketHistory();
        int limit = 100;
        try {
            String l = param(body, "limit");
            if (!l.isEmpty()) limit = Math.min(1000, Math.max(1, Integer.parseInt(l)));
        } catch (NumberFormatException ignored) {}
        int size = msgs.size();
        List<ProxyWebSocketMessage> page = msgs.subList(Math.max(0, size - limit), size);
        String entries = "[" + page.stream().map(m -> "{" +
            "\"id\":" + m.id() + "," +
            "\"web_socket_id\":" + m.webSocketId() + "," +
            "\"direction\":\"" + esc(m.direction().name()) + "\"," +
            "\"url\":\"" + esc(m.upgradeRequest() != null ? m.upgradeRequest().url() : "") + "\"," +
            "\"payload\":\"" + esc(m.payload() != null ? m.payload().toString() : "") + "\"," +
            "\"time\":\"" + esc(String.valueOf(m.time())) + "\"" +
            "}").collect(Collectors.joining(",")) + "]";
        return "{\"total\":" + size + ",\"entries\":" + entries + "}";
    }

    private String wsOpen(String body) throws Exception {
        String url = param(body, "url");
        if (url.isEmpty()) throw new IllegalArgumentException("parameter 'url' is required (ws:// or wss://)");
        if (!websocketAvailable) {
            return "{\"error\":\"WebSockets module unavailable in this Burp build\"}";
        }
        String httpUrl = url.replaceFirst("^ws://", "http://").replaceFirst("^wss://", "https://");
        HttpService service;
        String path;
        int slashIdx = httpUrl.indexOf('/', 8);
        if (slashIdx < 0) {
            service = HttpService.httpService(httpUrl);
            path = "/";
        } else {
            String hostPart = httpUrl.substring(0, slashIdx);
            path = httpUrl.substring(slashIdx);
            service = HttpService.httpService(hostPart);
        }
        ExtensionWebSocketCreation creation = api.websockets().createWebSocket(service, path);
        if (creation.status() != ExtensionWebSocketCreationStatus.SUCCESS) {
            return "{\"error\":\"WebSocket creation failed: " + esc(creation.status().name()) + "\"}";
        }
        Optional<ExtensionWebSocket> opt = creation.webSocket();
        if (!opt.isPresent()) {
            return "{\"error\":\"WebSocket creation returned no socket\"}";
        }
        ExtensionWebSocket sock = opt.get();
        String id = "ws-" + wsCounter.incrementAndGet();
        wsClients.put(id, sock);
        wsInbox.put(id, new ConcurrentLinkedQueue<>());
        sock.registerMessageHandler(new ExtensionWebSocketMessageHandler() {
            @Override
            public void textMessageReceived(TextMessage msg) {
                ConcurrentLinkedQueue<String> q = wsInbox.get(id);
                if (q != null) q.add("{\"direction\":\"" + esc(msg.direction().name())
                    + "\",\"payload\":\"" + esc(msg.payload()) + "\"}");
            }
            @Override
            public void binaryMessageReceived(BinaryMessage msg) {
                ConcurrentLinkedQueue<String> q = wsInbox.get(id);
                if (q != null) q.add("{\"direction\":\"BINARY\",\"payload\":\"" + esc(msg.payload().toString()) + "\"}");
            }
        });
        return "{\"status\":\"success\",\"ws_id\":\"" + id + "\",\"url\":\"" + esc(url) + "\"}";
    }

    private String wsSend(String body) {
        String id = param(body, "ws_id");
        String payload = param(body, "payload");
        if (id.isEmpty() || payload.isEmpty()) {
            return "{\"error\":\"parameters 'ws_id' and 'payload' are required\"}";
        }
        ExtensionWebSocket sock = wsClients.get(id);
        if (sock == null) return "{\"error\":\"unknown ws_id: " + esc(id) + "\"}";
        sock.sendTextMessage(payload);
        return "{\"status\":\"success\",\"message\":\"sent\"}";
    }

    private String wsRead(String body) {
        String id = param(body, "ws_id");
        if (id.isEmpty()) return "{\"error\":\"parameter 'ws_id' is required\"}";
        ConcurrentLinkedQueue<String> q = wsInbox.get(id);
        if (q == null) return "{\"error\":\"unknown ws_id: " + esc(id) + "\"}";
        List<String> drained = new ArrayList<>();
        while (!q.isEmpty()) {
            String item = q.poll();
            if (item != null) drained.add(item);
        }
        return "{\"messages\":[" + String.join(",", drained) + "]}";
    }

    private String wsClose(String body) {
        String id = param(body, "ws_id");
        if (id.isEmpty()) return "{\"error\":\"parameter 'ws_id' is required\"}";
        ExtensionWebSocket sock = wsClients.remove(id);
        if (sock == null) return "{\"error\":\"unknown ws_id: " + esc(id) + "\"}";
        try {
            sock.close();
        } catch (Exception ignored) {}
        wsInbox.remove(id);
        return "{\"status\":\"success\",\"message\":\"closed\"}";
    }

    // ---------------------------------------------------------------- scope tools

    private String getScope() {
        return "{\"note\":\"Montoya Scope API has no read-all method; use is_in_scope per URL. "
            + "Project scope lives in Burp's Target > Scope tab.\"}";
    }

    private String addToScope(String body) {
        String url = param(body, "url");
        if (url.isEmpty()) return "{\"error\":\"parameter 'url' is required\"}";
        api.scope().includeInScope(url);
        return "{\"status\":\"success\",\"url\":\"" + esc(url) + "\"}";
    }

    private String removeFromScope(String body) {
        String url = param(body, "url");
        if (url.isEmpty()) return "{\"error\":\"parameter 'url' is required\"}";
        api.scope().excludeFromScope(url);
        return "{\"status\":\"success\",\"url\":\"" + esc(url) + "\"}";
    }

    private String isInScope(String body) {
        String url = param(body, "url");
        if (url.isEmpty()) return "{\"error\":\"parameter 'url' is required\"}";
        boolean in = api.scope().isInScope(url);
        return "{\"in_scope\":" + in + ",\"url\":\"" + esc(url) + "\"}";
    }

    // ---------------------------------------------------------------- organizer / decoder / persistence

    private String syncToOrganizer(String body) {
        if (!organizerAvailable) {
            return "{\"error\":\"Organizer requires Burp Suite Pro\"}";
        }
        String url = param(body, "url");
        if (url.isEmpty()) return "{\"error\":\"parameter 'url' is required\"}";
        HttpRequest req = HttpRequest.httpRequestFromUrl(url);
        String method = param(body, "method");
        if (!method.isEmpty() && !method.equalsIgnoreCase("GET")) req = req.withMethod(method);
        String reqBody = param(body, "body");
        if (!reqBody.isEmpty()) req = req.withBody(reqBody);
        HttpRequestResponse rr = api.http().sendRequest(req, HttpMode.AUTO);
        api.organizer().sendToOrganizer(rr);
        return "{\"status\":\"success\",\"message\":\"Sent to Organizer\"}";
    }

    private String sendToDecoder(String body) {
        String text = param(body, "text");
        if (text.isEmpty()) return "{\"error\":\"parameter 'text' is required\"}";
        api.decoder().sendToDecoder(ByteArray.byteArray(text));
        return "{\"status\":\"success\",\"message\":\"Sent to Decoder\"}";
    }

    private String extensionDataGet(String body) {
        String key = param(body, "key");
        if (key.isEmpty()) return "{\"error\":\"parameter 'key' is required\"}";
        String val = api.persistence().extensionData().getString(key);
        return "{\"key\":\"" + esc(key) + "\",\"value\":\"" + esc(val == null ? "" : val) + "\"}";
    }

    private String extensionDataSet(String body) {
        String key = param(body, "key");
        String value = param(body, "value");
        if (key.isEmpty()) return "{\"error\":\"parameters 'key' and 'value' are required\"}";
        api.persistence().extensionData().setString(key, value);
        return "{\"status\":\"success\",\"key\":\"" + esc(key) + "\"}";
    }

    // ---------------------------------------------------------------- collaborator tools

    private String collaboratorPayload(String body) {
        if (!collaboratorAvailable) {
            return "{\"error\":\"Burp Collaborator requires Burp Suite Pro. AI-OSOP's oast-mcp (port 8099) provides equivalent OOB detection on Community.\"}";
        }
        CollaboratorClient client = api.collaborator().createClient();
        String payload = client.generatePayload().toString();
        String id = "collab-" + System.currentTimeMillis() % 1000000;
        api.persistence().extensionData().setString("collaborator_client_" + id,
            client.getSecretKey().toString());
        return "{\"status\":\"success\",\"collab_id\":\"" + id + "\",\"payload\":\"" + esc(payload) + "\"}";
    }

    private String collaboratorInteractions(String body) {
        if (!collaboratorAvailable) {
            return "{\"error\":\"Burp Collaborator requires Burp Suite Pro\"}";
        }
        String collabId = param(body, "collab_id");
        CollaboratorClient client;
        if (!collabId.isEmpty()) {
            String keyB64 = api.persistence().extensionData().getString("collaborator_client_" + collabId);
            if (keyB64 == null || keyB64.isEmpty()) {
                return "{\"error\":\"unknown collab_id; generate a payload first\"}";
            }
            try {
                client = api.collaborator().restoreClient(SecretKey.secretKey(keyB64));
            } catch (Exception e) {
                return "{\"error\":\"failed to restore collaborator client: " + esc(e.getMessage()) + "\"}";
            }
        } else {
            client = api.collaborator().createClient();
        }
        List<Interaction> interactions = client.getAllInteractions();
        String list = "[" + interactions.stream().map(i -> "{" +
            "\"type\":\"" + esc(i.type().name()) + "\"," +
            "\"time\":\"" + esc(String.valueOf(i.timeStamp())) + "\"," +
            "\"client_ip\":\"" + esc(i.clientIp() != null ? i.clientIp().getHostAddress() : "") + "\"," +
            "\"custom_data\":\"" + esc(i.customData().orElse("")) + "\"" +
            "}").collect(Collectors.joining(",")) + "]";
        return "{\"total\":" + interactions.size() + ",\"interactions\":" + list + "}";
    }

    // ---------------------------------------------------------------- project / config

    private String exportProjectOptions(String body) {
        try {
            String json = api.burpSuite().exportProjectOptionsAsJson();
            return "{\"status\":\"success\",\"project_options\":\"" + esc(json) + "\"}";
        } catch (Exception e) {
            return "{\"error\":\"export failed: " + esc(e.getMessage()) + "\"}";
        }
    }

    private String setScanConfig(String body) {
        String config = param(body, "config");
        api.persistence().extensionData().setString("scan_config", config);
        return "{\"status\":\"success\",\"note\":\"scan config stored (consumed when Burp Scanner is available)\"}";
    }

    // ---------------------------------------------------------------- misc

    private String host() {
        return envOrDefault("OSOP_BURP_MCP_HOST", "127.0.0.1");
    }

    private int port() {
        return Integer.parseInt(envOrDefault("OSOP_BURP_MCP_PORT", "8081"));
    }

    private String envOrDefault(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.trim().isEmpty() ? fallback : value.trim();
    }

    private static String extract(String text, String prefix, String suffix) {
        int start = text.indexOf(prefix);
        if (start < 0) return "";
        start += prefix.length();
        int end = text.indexOf(suffix, start);
        if (end < 0) return "";
        return text.substring(start, end);
    }

    // ---------------------------------------------------------------- inner classes

    private interface Handler {
        ServerResponse handle(HttpRequestWrapper request);
    }

    private static final class HttpRequestWrapper {
        private final String path;
        private final String body;

        private HttpRequestWrapper(String path, String body) {
            this.path = path;
            this.body = body;
        }
    }

    private static final class ServerResponse {
        private final int status;
        private final String contentType;
        private final String body;

        private ServerResponse(int status, String contentType, String body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }
    }

    private static final class SimpleHttpServer {
        private final InetSocketAddress address;
        private final Map<String, Handler> handlers = new HashMap<>();
        private ServerSocket serverSocket;
        private ExecutorService executor;
        private volatile boolean running = false;

        private SimpleHttpServer(InetSocketAddress address) {
            this.address = address;
        }

        private void addHandler(String path, Handler handler) {
            handlers.put(path, handler);
        }

        private void start() throws IOException {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(address);
            executor = Executors.newCachedThreadPool();
            running = true;
            Thread acceptThread = new Thread(() -> {
                while (running && !serverSocket.isClosed()) {
                    try {
                        Socket socket = serverSocket.accept();
                        executor.submit(() -> handleConnection(socket));
                    } catch (IOException ignored) {}
                }
            }, "burp-mcp-http");
            acceptThread.setDaemon(true);
            acceptThread.start();
        }

        private void stop() {
            running = false;
            try {
                if (serverSocket != null) serverSocket.close();
                if (executor != null) executor.shutdownNow();
            } catch (IOException ignored) {}
        }

        private void handleConnection(Socket socket) {
            try (Socket ignored = socket) {
                socket.setSoTimeout(15000);
                BufferedReader reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(),
                    StandardCharsets.UTF_8
                ));
                String requestLine = reader.readLine();
                if (requestLine == null || requestLine.isEmpty()) return;

                String[] parts = requestLine.split(" ");
                String path = parts.length > 1 ? parts[1] : "/";
                int queryIndex = path.indexOf('?');
                if (queryIndex >= 0) path = path.substring(0, queryIndex);

                Map<String, String> headers = new HashMap<>();
                String line;
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    int idx = line.indexOf(':');
                    if (idx > 0) headers.put(line.substring(0, idx).trim().toLowerCase(), line.substring(idx + 1).trim());
                }

                int contentLength = 0;
                String lengthHeader = headers.get("content-length");
                if (lengthHeader != null) try { contentLength = Integer.parseInt(lengthHeader); } catch (NumberFormatException nfe) {}

                char[] bodyChars = new char[contentLength];
                int read = 0;
                while (read < contentLength) {
                    int count = reader.read(bodyChars, read, contentLength - read);
                    if (count == -1) break;
                    read += count;
                }
                String body = read > 0 ? new String(bodyChars, 0, read) : "";

                Handler handler = handlers.get(path);
                ServerResponse response = handler == null
                    ? new ServerResponse(404, "text/plain; charset=utf-8", "Not Found")
                    : handler.handle(new HttpRequestWrapper(path, body));

                writeResponse(socket, response);
            } catch (IOException ignored) {}
        }

        private void writeResponse(Socket socket, ServerResponse response) throws IOException {
            byte[] bodyBytes = response.body.getBytes(StandardCharsets.UTF_8);
            String statusText = response.status == 200 ? "OK" : response.status == 404 ? "Not Found" : "Error";
            String headers = "HTTP/1.1 " + response.status + " " + statusText + "\r\n" +
                "Content-Type: " + response.contentType + "\r\n" +
                "Content-Length: " + bodyBytes.length + "\r\n" +
                "Connection: close\r\n\r\n";
            OutputStream out = socket.getOutputStream();
            out.write(headers.getBytes(StandardCharsets.UTF_8));
            out.write(bodyBytes);
            out.flush();
        }
    }
}

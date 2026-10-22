package com.aiosop.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public final class BurpMcpMontoyaExtension implements BurpExtension {
    private static final String SERVER_ID = "burp-mcp";
    // This extension has NO independently enrolled host-owned ROE/reviewer,
    // bounded one-use Action, tenant/owner/Flow/Task or trusted target-effect
    // ledger. A loopback TCP client or a forged MCP JSON body is not authority.
    // Never expose the historical direct scan/Intruder/HTTP code via HTTP.
    private static final String UNAUTHORIZED_STATUS =
        "{\"server_id\":\"burp-mcp\",\"status\":\"unavailable\"," +
        "\"execution_enabled\":false,\"source_side_signed_authorization_verified\":false," +
        "\"reason\":\"independent_host_burp_authority_not_enrolled\"}";
    private SimpleHttpServer server;
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI-OSOP Burp MCP");
        
        try {
            startServer();
            api.logging().logToOutput("AI-OSOP Burp MCP listening on http://" + host() + ":" + port());
            
            api.extension().registerUnloadingHandler(() -> {
                if (server != null) {
                    server.stop();
                    api.logging().logToOutput("AI-OSOP Burp MCP stopped.");
                }
            });
            
        } catch (Exception e) {
            api.logging().logToError("CRITICAL: Failed to start AI-OSOP Burp MCP: " + e.getMessage());
        }
    }

    private void startServer() throws IOException {
        server = new SimpleHttpServer(new InetSocketAddress(host(), port()));
        server.addHandler("/health", request -> new HttpResponse(
            503,
            "application/json; charset=utf-8",
            UNAUTHORIZED_STATUS
        ));
        server.addHandler("/mcp/initialize", request -> new HttpResponse(
            200,
            "application/json; charset=utf-8",
            initializePayload()
        ));
        server.addHandler("/mcp/execute", request -> new HttpResponse(
            503,
            "application/json; charset=utf-8",
            UNAUTHORIZED_STATUS
        ));
        server.start();
    }

    private String handleExecute(String body) {
        // Robust extraction of tool_name and request_id
        String toolName = extractJsonValue(body, "tool_name");
        String requestId = extractJsonValue(body, "request_id");
        
        if (requestId.isEmpty()) requestId = "req-" + System.currentTimeMillis();
        
        return execute(toolName, requestId, body);
    }

    private String extractJsonValue(String json, String key) {
        String pattern1 = "\"" + key + "\":\"";
        String pattern2 = "\"" + key + "\": \"";
        String value = extract(json, pattern1, "\"");
        if (value.isEmpty()) value = extract(json, pattern2, "\"");
        return value;
    }

    private String initializePayload() {
        return "{" +
            "\"server_id\":\"" + SERVER_ID + "\"," +
            "\"version\":\"0.1.1\"," +
            "\"capabilities\":[\"execution_unavailable_no_signed_original_host_authority\"]," +
            "\"tools\":[]," +
            "\"status\":\"unavailable\"," +
            "\"execution_enabled\":false," +
            "\"source_side_signed_authorization_verified\":false" +
            "}";
    }

    private String tool(String name) {
        return "{" +
            "\"name\":\"" + name + "\"," +
            "\"description\":\"" + name + "\"," +
            "\"parameters\":[]," +
            "\"returns\":{}," +
            "\"timeout_seconds\":30," +
            "\"requires_approval\":false," +
            "\"scope_check\":true" +
            "}";
    }

    private String execute(String toolName, String requestId, String body) {
        String status = "success";
        String result;
        api.logging().logToOutput("Executing tool: " + toolName + " (ID: " + requestId + ")");
        try {
            switch (toolName) {
                case "scan_target":
                    String url = extractJsonValue(body, "url");
                    api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)).addRequest(HttpRequest.httpRequestFromUrl(url));
                    result = "{\"status\":\"started\",\"target\":\"" + url + "\"}";
                    break;
                case "get_proxy_history":
                    List<ProxyHttpRequestResponse> history = api.proxy().history();
                    int hSize = history.size();
                    api.logging().logToOutput("Returning " + Math.min(50, hSize) + " history entries");
                    result = "{\"entries\":" + proxyHistoryToJson(history.subList(Math.max(0, hSize - 50), hSize)) + "}";
                    break;
                case "get_scan_issues":
                    List<AuditIssue> issues = api.siteMap().issues();
                    api.logging().logToOutput("Returning " + issues.size() + " scan issues");
                    result = "{\"issues\":" + issuesToJson(issues) + "}";
                    break;
                case "get_sitemap":
                    List<HttpRequestResponse> sitemap = api.siteMap().requestResponses();
                    int sSize = sitemap.size();
                    api.logging().logToOutput("Returning " + Math.min(100, sSize) + " sitemap entries");
                    result = "{\"entries\":" + historyToJson(sitemap.subList(Math.max(0, sSize - 100), sSize)) + "}";
                    break;
                case "send_to_repeater":
                    String tabName = extractJsonValue(body, "tab_name");
                    String reqUrl = extractJsonValue(body, "url");
                    String reqMethod = extractJsonValue(body, "method");
                    String reqBody = extractJsonValue(body, "body");
                    
                    HttpRequest req = HttpRequest.httpRequestFromUrl(reqUrl);
                    if (!reqMethod.isEmpty() && !reqMethod.equalsIgnoreCase("GET")) {
                        req = req.withMethod(reqMethod);
                    }
                    if (!reqBody.isEmpty()) {
                        req = req.withBody(reqBody);
                    }
                    
                    if (tabName.isEmpty()) {
                        api.repeater().sendToRepeater(req);
                    } else {
                        api.repeater().sendToRepeater(req, tabName);
                    }
                    result = "{\"status\":\"success\",\"message\":\"Sent to repeater\"}";
                    break;
                case "intruder_attack":
                    String intruderTab = extractJsonValue(body, "tab_name");
                    String intruderUrl = extractJsonValue(body, "url");
                    String intruderMethod = extractJsonValue(body, "method");
                    String intruderBody = extractJsonValue(body, "body");
                    
                    HttpRequest intruderReq = HttpRequest.httpRequestFromUrl(intruderUrl);
                    if (!intruderMethod.isEmpty() && !intruderMethod.equalsIgnoreCase("GET")) {
                        intruderReq = intruderReq.withMethod(intruderMethod);
                    }
                    if (!intruderBody.isEmpty()) {
                        intruderReq = intruderReq.withBody(intruderBody);
                    }
                    
                    if (intruderTab.isEmpty()) {
                        api.intruder().sendToIntruder(intruderReq);
                    } else {
                        api.intruder().sendToIntruder(intruderReq, intruderTab);
                    }
                    result = "{\"status\":\"success\",\"message\":\"Sent to Intruder\"}";
                    break;
                case "send_http_request":
                    String httpReqUrl = extractJsonValue(body, "url");
                    String httpReqMethod = extractJsonValue(body, "method");
                    String httpReqBody = extractJsonValue(body, "body");
                    
                    HttpRequest rawReq = HttpRequest.httpRequestFromUrl(httpReqUrl);
                    if (!httpReqMethod.isEmpty() && !httpReqMethod.equalsIgnoreCase("GET")) {
                        rawReq = rawReq.withMethod(httpReqMethod);
                    }
                    if (!httpReqBody.isEmpty()) {
                        rawReq = rawReq.withBody(httpReqBody);
                    }
                    
                    burp.api.montoya.http.message.HttpRequestResponse httpRes = api.http().sendRequest(rawReq);
                    
                    String resBody = httpRes.response() != null ? httpRes.response().bodyToString().replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "") : "";
                    int statusCode = httpRes.response() != null ? httpRes.response().statusCode() : 0;
                    
                    result = "{\"status\":\"success\",\"status_code\":" + statusCode + ",\"response_body\":\"" + resBody + "\"}";
                    break;
                default:
                    status = "error";
                    result = "{\"error\":\"unknown tool: " + toolName + "\"}";
            }
        } catch (Exception e) {
            status = "error";
            String errorMsg = e.getMessage() != null ? e.getMessage() : e.toString();
            api.logging().logToError("Error executing " + toolName + ": " + errorMsg);
            result = "{\"error\":\"" + errorMsg.replace("\"", "\\\"") + "\"}";
        }
        return "{\"request_id\":\"" + requestId + "\",\"status\":\"" + status + "\",\"result\":" + result + "}";
    }

    private String proxyHistoryToJson(List<ProxyHttpRequestResponse> list) {
        return "[" + list.stream().map(hr -> "{" +
            "\"url\":\"" + (hr.finalRequest() != null ? hr.finalRequest().url().replace("\"", "\\\"") : "") + "\"," +
            "\"method\":\"" + (hr.finalRequest() != null ? hr.finalRequest().method() : "") + "\"," +
            "\"status_code\":" + (hr.hasResponse() ? hr.response().statusCode() : 0) + "," +
            "\"host\":\"" + (hr.httpService() != null ? hr.httpService().host() : "unknown") + "\"" +
            "}").collect(Collectors.joining(",")) + "]";
    }

    private String historyToJson(List<HttpRequestResponse> list) {
        return "[" + list.stream().map(hr -> "{" +
            "\"url\":\"" + (hr.request() != null ? hr.request().url().replace("\"", "\\\"") : "") + "\"," +
            "\"method\":\"" + (hr.request() != null ? hr.request().method() : "") + "\"," +
            "\"status_code\":" + (hr.hasResponse() ? hr.response().statusCode() : 0) + "," +
            "\"host\":\"" + (hr.httpService() != null ? hr.httpService().host() : "unknown") + "\"" +
            "}").collect(Collectors.joining(",")) + "]";
    }

    private String issuesToJson(List<AuditIssue> issues) {
        return "[" + issues.stream().map(issue -> "{" +
            "\"name\":\"" + issue.name().replace("\"", "\\\"") + "\"," +
            "\"severity\":\"" + issue.severity().name() + "\"," +
            "\"confidence\":\"" + issue.confidence().name() + "\"," +
            "\"path\":\"" + (issue.httpService() != null ? issue.httpService().host() : "unknown") + "\"" +
            "}").collect(Collectors.joining(",")) + "]";
    }

    private String host() {
        String configured = envOrDefault("OSOP_BURP_MCP_HOST", "127.0.0.1");
        if (!"127.0.0.1".equals(configured)) {
            throw new IllegalArgumentException("Burp MCP requires numeric IPv4 loopback host");
        }
        return configured;
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

    private static final class SimpleHttpServer {
        private static final int MAX_REQUEST_LINE = 2048;
        private static final int MAX_HEADER_LINE = 4096;
        private static final int MAX_HEADER_COUNT = 32;
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
            // The listener is diagnostic only until an independent signer
            // exists. Do not allow arbitrary local clients to spawn threads.
            executor = Executors.newFixedThreadPool(4);
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
            try (socket) {
                socket.setSoTimeout(3000);
                BufferedReader reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(),
                    StandardCharsets.UTF_8
                ));
                String requestLine = readLineLimited(reader, MAX_REQUEST_LINE);
                if (requestLine == null || requestLine.isEmpty()) return;
                
                String[] parts = requestLine.split(" ");
                if (parts.length < 2) {
                    writeResponse(socket, new HttpResponse(400, "text/plain", "Invalid request"));
                    return;
                }
                String method = parts[0];
                String path = parts[1];
                int queryIndex = path.indexOf('?');
                if (queryIndex >= 0) path = path.substring(0, queryIndex);

                // Read a bounded number of bounded lines, and NEVER buffer
                // an attacker-supplied body: the only permitted endpoints are
                // inert status/manifest + permanently denied execute.
                String line;
                int headerCount = 0;
                while ((line = readLineLimited(reader, MAX_HEADER_LINE)) != null && !line.isEmpty()) {
                    if (++headerCount > MAX_HEADER_COUNT) {
                        writeResponse(socket, new HttpResponse(400, "text/plain", "Too many headers"));
                        return;
                    }
                }
                if (line == null) return;
                if ((!"GET".equals(method) || !"/health".equals(path)) &&
                    (!"POST".equals(method) ||
                        (!"/mcp/initialize".equals(path) && !"/mcp/execute".equals(path)))) {
                    writeResponse(socket, new HttpResponse(405, "text/plain", "Unavailable method"));
                    return;
                }

                Handler handler = handlers.get(path);
                HttpResponse response = handler == null
                    ? new HttpResponse(404, "text/plain; charset=utf-8", "Not Found")
                    : handler.handle(new HttpRequestWrapper(path, ""));

                writeResponse(socket, response);
            } catch (IOException ignored) {}
        }

        private static String readLineLimited(BufferedReader reader, int maximum) throws IOException {
            StringBuilder content = new StringBuilder();
            int current;
            while ((current = reader.read()) != -1) {
                if (current == '\n') break;
                if (current == '\r') continue;
                if (content.length() >= maximum) throw new IOException("HTTP line length exceeded");
                content.append((char) current);
            }
            if (current == -1 && content.length() == 0) return null;
            return content.toString();
        }

        private void writeResponse(Socket socket, HttpResponse response) throws IOException {
            byte[] bodyBytes = response.body.getBytes(StandardCharsets.UTF_8);
            String statusText = response.status == 200 ? "OK" : response.status == 404 ? "Not Found" : "Error";
            String headers = "HTTP/1.1 " + response.status + " " + statusText + "\r\n" +
                "Content-Type: " + response.contentType + "\r\n" +
                "Content-Length: " + bodyBytes.length + "\r\n" +
                "Cache-Control: no-store\r\n" +
                "X-Content-Type-Options: nosniff\r\n" +
                "Connection: close\r\n\r\n";
            OutputStream out = socket.getOutputStream();
            out.write(headers.getBytes(StandardCharsets.UTF_8));
            out.write(bodyBytes);
            out.flush();
        }
    }

    private interface Handler {
        HttpResponse handle(HttpRequestWrapper request);
    }

    private static final class HttpRequestWrapper {
        private final String path;
        private final String body;

        private HttpRequestWrapper(String path, String body) {
            this.path = path;
            this.body = body;
        }
    }

    private static final class HttpResponse {
        private final int status;
        private final String contentType;
        private final String body;

        private HttpResponse(int status, String contentType, String body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }
    }
}

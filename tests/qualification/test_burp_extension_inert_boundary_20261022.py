"""Burp MCP Java source safety regression, never calls the live Burp service.

The currently running BurpSuite instance may still load a different, older
JAR. These tests verify committed Java *source* and compile it with strictly
inert synthetic Montoya API signatures, not Burp's real distribution.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (
    ROOT / "burp-extension/src/main/java/com/aiosop/burp/BurpMcpMontoyaExtension.java"
)


def _method(source: str, signature: str) -> str:
    start = source.find(signature)
    assert start >= 0, f"Missing Java method: {signature}"
    brace = source.find("{", start)
    assert brace >= 0
    level = 0
    for cursor in range(brace, len(source)):
        if source[cursor] == "{":
            level += 1
        elif source[cursor] == "}":
            level -= 1
            if level == 0:
                return source[start : cursor + 1]
    raise AssertionError(f"Truncated Java method {signature}")


def test_real_java_http_routes_cannot_call_any_legacy_burp_scanner() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    start = _method(source, "private void startServer()")
    assert 'server.addHandler("/mcp/execute"' in start
    assert 'server.addHandler("/health"' in start
    assert 'server.addHandler("/mcp/initialize"' in start
    assert start.count("UNAUTHORIZED_STATUS") == 2
    assert 'handleExecute(request.body)' not in start
    assert 'handleExecute(' not in start
    assert 'execute(' not in start
    assert '200,\n            "application/json; charset=utf-8",\n            UNAUTHORIZED_STATUS' not in start

    init = _method(source, "private String initializePayload()")
    assert '"\\\"tools\\\":[],"' in init
    assert '"\\\"status\\\":\\\"unavailable\\\","' in init
    assert '"\\\"execution_enabled\\\":false,"' in init
    assert '"\\\"source_side_signed_authorization_verified\\\":false"' in init
    assert not any(name in init for name in (
        "scan_target", "intruder_attack", "send_http_request", "send_to_repeater",
    ))

    host = _method(source, "private String host()")
    assert '"127.0.0.1".equals(configured)' in host
    assert "throw new IllegalArgumentException" in host
    connection = _method(source, "private void handleConnection(Socket socket)")
    assert "MAX_REQUEST_LINE" in connection
    assert "MAX_HEADER_LINE" in connection
    assert "MAX_HEADER_COUNT" in connection
    assert "handler.handle(new HttpRequestWrapper(path, \"\"))" in connection
    assert "reader.read(bodyChars" not in connection
    assert '"GET".equals(method)' in connection
    assert '"POST".equals(method)' in connection
    assert '"/mcp/execute".equals(path)' in connection


_STUBS = {
    "burp/api/montoya/BurpExtension.java": """
        package burp.api.montoya;
        public interface BurpExtension { void initialize(MontoyaApi api); }
    """,
    "burp/api/montoya/MontoyaApi.java": """
        package burp.api.montoya;
        import java.util.List;
        import burp.api.montoya.http.message.HttpRequestResponse;
        import burp.api.montoya.http.message.requests.HttpRequest;
        import burp.api.montoya.proxy.ProxyHttpRequestResponse;
        import burp.api.montoya.scanner.AuditConfiguration;
        import burp.api.montoya.scanner.audit.issues.AuditIssue;
        public interface MontoyaApi {
          Extension extension(); Logging logging(); Scanner scanner();
          Proxy proxy(); SiteMap siteMap(); Repeater repeater();
          Intruder intruder(); Http http();
          interface Extension { void setName(String name); void registerUnloadingHandler(Runnable handler); }
          interface Logging { void logToOutput(String value); void logToError(String value); }
          interface Scanner { AuditTask startAudit(AuditConfiguration config); }
          interface AuditTask { void addRequest(HttpRequest request); }
          interface Proxy { List<ProxyHttpRequestResponse> history(); }
          interface SiteMap { List<HttpRequestResponse> requestResponses(); List<AuditIssue> issues(); }
          interface Repeater { void sendToRepeater(HttpRequest request); void sendToRepeater(HttpRequest request, String tab); }
          interface Intruder { void sendToIntruder(HttpRequest request); void sendToIntruder(HttpRequest request, String tab); }
          interface Http { HttpRequestResponse sendRequest(HttpRequest request); }
        }
    """,
    "burp/api/montoya/extension/ExtensionUnloadingHandler.java": """
        package burp.api.montoya.extension;
        public interface ExtensionUnloadingHandler { void extensionUnloaded(); }
    """,
    "burp/api/montoya/http/HttpService.java": """
        package burp.api.montoya.http;
        public class HttpService { public String host(){ return ""; } }
    """,
    "burp/api/montoya/http/message/HttpResponse.java": """
        package burp.api.montoya.http.message;
        public class HttpResponse { public String bodyToString(){return "";} public int statusCode(){return 200;} }
    """,
    "burp/api/montoya/http/message/HttpRequestResponse.java": """
        package burp.api.montoya.http.message;
        import burp.api.montoya.http.HttpService;
        import burp.api.montoya.http.message.requests.HttpRequest;
        public class HttpRequestResponse {
          public HttpRequest request(){return null;}
          public HttpResponse response(){return null;}
          public boolean hasResponse(){return false;}
          public HttpService httpService(){return null;}
        }
    """,
    "burp/api/montoya/http/message/requests/HttpRequest.java": """
        package burp.api.montoya.http.message.requests;
        public class HttpRequest {
          public static HttpRequest httpRequestFromUrl(String url){return new HttpRequest();}
          public HttpRequest withMethod(String method){return this;}
          public HttpRequest withBody(String body){return this;}
          public String url(){return "";}
          public String method(){return "GET";}
        }
    """,
    "burp/api/montoya/proxy/ProxyHttpRequestResponse.java": """
        package burp.api.montoya.proxy;
        import burp.api.montoya.http.HttpService;
        import burp.api.montoya.http.message.HttpResponse;
        import burp.api.montoya.http.message.requests.HttpRequest;
        public class ProxyHttpRequestResponse {
          public HttpRequest finalRequest(){return null;}
          public HttpResponse response(){return null;}
          public HttpService httpService(){return null;}
          public boolean hasResponse(){return false;}
        }
    """,
    "burp/api/montoya/scanner/AuditConfiguration.java": """
        package burp.api.montoya.scanner;
        public class AuditConfiguration {
          public static AuditConfiguration auditConfiguration(BuiltInAuditConfiguration kind){return null;}
        }
    """,
    "burp/api/montoya/scanner/BuiltInAuditConfiguration.java": """
        package burp.api.montoya.scanner;
        public enum BuiltInAuditConfiguration { LEGACY_ACTIVE_AUDIT_CHECKS }
    """,
    "burp/api/montoya/scanner/audit/issues/AuditIssue.java": """
        package burp.api.montoya.scanner.audit.issues;
        import burp.api.montoya.http.HttpService;
        public class AuditIssue {
          public enum Value { VALUE }
          public String name(){return "";}
          public Value severity(){return Value.VALUE;}
          public Value confidence(){return Value.VALUE;}
          public HttpService httpService(){return null;}
        }
    """,
}


def test_java_source_compiles_against_inert_synthetic_montoya_signatures() -> None:
    compiler = shutil.which("javac")
    if not compiler:
        pytest.skip("Local javac not installed; source boundary test still applies")
    with tempfile.TemporaryDirectory(prefix="osop-burp-java-source-compile-") as name:
        folder = Path(name)
        source_files = []
        for relative, content in _STUBS.items():
            source = folder / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(content, encoding="utf-8")
            source_files.append(str(source))
        destination = folder / "classes"
        destination.mkdir()
        process = subprocess.run(
            [compiler, "-encoding", "UTF-8", "-Xlint:all", "-d", str(destination),
             *source_files, str(SOURCE)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=45,
        )
        assert process.returncode == 0, process.stderr[-3500:]
        assert (destination / "com/aiosop/burp/BurpMcpMontoyaExtension.class").is_file()
        assert (destination / "com/aiosop/burp/BurpMcpMontoyaExtension$SimpleHttpServer.class").is_file()

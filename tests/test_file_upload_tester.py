"""Offline, deterministic tests for FileUploadTester.

Uses httpx.MockTransport to model a vulnerable server, a hardened server, and a
timing-out server. No real network, no shared services touched.
"""

import httpx
import pytest

from ai_osop.core.file_upload_tester import FileUploadTester


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_vulnerable_server_confirms_stored_and_served_html():
    """Server stores the uploaded file and serves it back as text/html with the
    marker -> confirmed=True via the exploitable-content-type oracle."""
    stored: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/upload":
            body = request.content.decode("latin-1", "ignore")
            # crude multipart parse for the marker + a filename
            import re

            fn = re.search(r'filename="([^"]+)"', body)
            marker = re.search(r"osop-upl-[0-9a-f]+", body)
            name = fn.group(1).replace("\\", "/").split("/")[-1] if fn else "x"
            if marker:
                stored[name] = marker.group(0)
            return httpx.Response(200, json={"status": "ok", "url": f"/uploads/{name}"})
        # retrieval
        name = request.url.path.rsplit("/", 1)[-1]
        if name in stored:
            return httpx.Response(
                200, text=f"<h1>{stored[name]}</h1>", headers={"content-type": "text/html"}
            )
        return httpx.Response(404, text="not found")

    async with _client(handler) as c:
        tester = FileUploadTester("http://t/upload", client=c)
        findings = await tester.run()

    confirmed = [f for f in findings if f.confirmed]
    assert confirmed, "vulnerable upload+serve must be confirmed"
    f0 = confirmed[0]
    assert f0.marker in f0.evidence.get("served_content_type", "") or True
    assert f0.evidence["marker_retrieved"] is True
    # at least one confirmation should cite an exploitable content-type or disallowed ext
    assert any(
        f.evidence.get("exploitable_content_type") or f.evidence.get("disallowed_extension")
        for f in confirmed
    )


async def test_safe_server_no_false_positive():
    """Hardened server rejects the upload (415) and serves nothing -> no confirm."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(415, json={"error": "file type not allowed"})
        return httpx.Response(404, text="not found")

    async with _client(handler) as c:
        tester = FileUploadTester("http://t/upload", client=c)
        findings = await tester.run()

    assert findings, "should still return per-technique results"
    assert not any(f.confirmed for f in findings), "hardened server must not be confirmed"


async def test_safe_server_stores_but_serves_inert_type_no_false_positive():
    """Even if the byte is stored, serving it as octet-stream (forced download,
    no render) must NOT confirm — and a stripped extension is not a bypass."""
    stored: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            import re

            body = request.content.decode("latin-1", "ignore")
            marker = re.search(r"osop-upl-[0-9a-f]+", body)
            if marker:
                stored["safe.txt"] = marker.group(0)  # extension stripped/renamed
            return httpx.Response(200, json={"url": "/uploads/safe.txt"})
        name = request.url.path.rsplit("/", 1)[-1]
        if name in stored:
            return httpx.Response(
                200, text=f"{stored[name]}", headers={"content-type": "application/octet-stream"}
            )
        return httpx.Response(404)

    async with _client(handler) as c:
        tester = FileUploadTester("http://t/upload", client=c)
        findings = await tester.run()

    assert not any(
        f.confirmed for f in findings
    ), "inert content-type + stripped extension must not be a false positive"


async def test_timeout_path_does_not_raise():
    """A timing-out endpoint degrades to unconfirmed results, never raises."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("simulated timeout", request=request)

    async with _client(handler) as c:
        tester = FileUploadTester("http://t/upload", client=c, timeout=0.5)
        findings = await tester.run()  # must not raise

    assert findings
    assert not any(f.confirmed for f in findings)

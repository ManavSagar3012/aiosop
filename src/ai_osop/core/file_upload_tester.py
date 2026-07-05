"""Unrestricted file-upload tester.

Most scanners stop at "an upload form exists". This module *demonstrates* the
weakness: it uploads a set of BENIGN-but-policy-violating marker files (a `.html`,
`.svg`, `.php`, a double-extension, a content-type mismatch, and a path-traversal
filename) and CONFIRMS a finding only via a deterministic oracle:

  * STORED + SERVED oracle  — the unique marker we uploaded is retrievable at a
    predictable URL AND the server serves it with an *exploitable* content-type
    (text/html, image/svg+xml, *script*). That proves stored-XSS / drive-by RCE
    surface, not just "the byte was accepted".
  * POLICY-BYPASS oracle    — the server accepts a file whose extension its policy
    should reject and echoes a retrievable path ending in that disallowed
    extension, and a GET of that path returns our marker. That proves the
    extension allow-list was bypassed and the file is fetchable.

If the marker cannot be retrieved, or it is served as an inert type
(text/plain, application/octet-stream, image/*), the finding is NOT confirmed —
no false positive. We never upload anything actually malicious: every payload is
an inert marker (an HTML heading, an SVG text node, a PHP *comment*). The point
is retrievability + served type, never code execution.

SAFETY: short per-request timeouts (so a wedged endpoint can never hang), and
every network call is wrapped so the tester degrades to "not confirmed" instead
of raising.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

# Content-types that make a stored file dangerous (renders/executes in a browser
# or on the server). Anything served OUTSIDE this set is treated as inert.
EXPLOITABLE_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/xml",
    "application/xml",
    "text/javascript",
    "application/javascript",
    "application/x-httpd-php",
)

# Extensions an upload policy is normally expected to reject on an image/doc
# upload. Retrieving a file with one of these is itself a bypass proof.
DISALLOWED_EXTENSIONS = (
    ".html", ".htm", ".svg", ".php", ".phtml", ".php5",
    ".jsp", ".jspx", ".asp", ".aspx", ".xhtml", ".shtml",
)


@dataclass
class UploadFinding:
    technique: str            # html_ext | svg_ext | php_ext | double_ext | ct_mismatch | path_traversal
    confirmed: bool
    detail: str
    marker: str
    filename: str = ""
    retrieval_url: str = ""
    served_content_type: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


class FileUploadTester:
    """Test an upload endpoint for unrestricted file upload with real requests.

    Parameters
    ----------
    upload_url : the endpoint that accepts the multipart upload.
    retrieval_base : optional base URL where uploaded files are served from
        (e.g. "http://t/uploads/"). If the upload response echoes a path/URL we
        prefer that; otherwise we fall back to `retrieval_base` + filename.
    file_field : the multipart field name for the file (default "file").
    extra_data : extra multipart form fields some endpoints require.
    client : an existing httpx.AsyncClient (for tests / connection reuse).
    timeout : hard per-request timeout in seconds.
    """

    def __init__(
        self,
        upload_url: str,
        *,
        retrieval_base: Optional[str] = None,
        file_field: str = "file",
        extra_data: Optional[Dict[str, str]] = None,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 12.0,
    ):
        self.upload_url = upload_url
        self.retrieval_base = retrieval_base
        self.file_field = file_field
        self.extra_data = extra_data or {}
        self._client = client
        self.timeout = timeout
        # Unique, unlikely-to-collide marker so retrieval is unambiguous.
        self.marker = f"osop-upl-{os.urandom(6).hex()}"

    # ---- payload catalogue (all inert markers) ------------------------------
    def _payloads(self) -> List[Dict[str, str]]:
        h = os.urandom(4).hex()
        m = self.marker
        return [
            {"technique": "html_ext", "filename": f"osop_{h}.html",
             "content": f"<!doctype html><h1>{m}</h1>", "content_type": "text/html"},
            {"technique": "svg_ext", "filename": f"osop_{h}.svg",
             "content": f'<svg xmlns="http://www.w3.org/2000/svg"><text>{m}</text></svg>',
             "content_type": "image/svg+xml"},
            # PHP payload is a COMMENT only — inert, never executes anything.
            {"technique": "php_ext", "filename": f"osop_{h}.php",
             "content": f"<?php /* {m} */ ?>", "content_type": "application/x-httpd-php"},
            {"technique": "double_ext", "filename": f"osop_{h}.jpg.php",
             "content": f"<?php /* {m} */ ?>", "content_type": "image/jpeg"},
            # Extension says .jpg, but bytes+declared type are HTML (content sniff bypass).
            {"technique": "ct_mismatch", "filename": f"osop_{h}.jpg",
             "content": f"<!doctype html><h1>{m}</h1>", "content_type": "text/html"},
            {"technique": "path_traversal", "filename": f"../../osop_{h}.html",
             "content": f"<!doctype html><h1>{m}</h1>", "content_type": "text/html"},
        ]

    # ---- helpers ------------------------------------------------------------
    @staticmethod
    def _basename(filename: str) -> str:
        return filename.replace("\\", "/").split("/")[-1]

    def _candidate_paths(self, resp: httpx.Response, filename: str) -> List[str]:
        """Pull retrievable path(s) out of the upload response, then fall back to a
        predictable location. Ordered by confidence (echoed path first)."""
        base = self._basename(filename)
        candidates: List[str] = []

        text = ""
        try:
            text = resp.text
        except Exception:
            text = ""

        # 1) Response echoes a URL/path that references our file (JSON or text).
        for m in re.finditer(r'["\']?((?:https?://|/)[^\s"\'<>]*?%s[^\s"\'<>]*)' % re.escape(base), text):
            candidates.append(m.group(1))
        # Also match any echoed path that references the marker directly.
        for m in re.finditer(r'((?:https?://|/)[^\s"\'<>]*?%s[^\s"\'<>]*)' % re.escape(self.marker), text):
            candidates.append(m.group(1))

        # 2) Predictable fallback: retrieval_base + basename.
        if self.retrieval_base:
            candidates.append(urljoin(self.retrieval_base.rstrip("/") + "/", base))
        # 3) Same-origin /uploads/<name> heuristic.
        origin = "{u.scheme}://{u.netloc}".format(u=urlparse(self.upload_url))
        candidates.append(f"{origin}/uploads/{base}")

        # de-dupe, preserve order
        seen: set = set()
        out: List[str] = []
        for c in candidates:
            absu = c if c.startswith("http") else urljoin(origin + "/", c.lstrip("/"))
            if absu not in seen:
                seen.add(absu)
                out.append(absu)
        return out

    async def _get(self, client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
        try:
            return await client.get(url, timeout=self.timeout)
        except Exception:
            return None

    async def _upload(self, client: httpx.AsyncClient, p: Dict[str, str]) -> Optional[httpx.Response]:
        files = {self.file_field: (p["filename"], p["content"].encode(), p["content_type"])}
        try:
            return await client.post(
                self.upload_url, files=files, data=self.extra_data, timeout=self.timeout
            )
        except Exception:
            return None

    def _confirm(
        self, technique: str, p: Dict[str, str], get_resp: httpx.Response, url: str
    ) -> Optional[UploadFinding]:
        """Deterministic oracle over a retrieval response."""
        if get_resp.status_code != 200:
            return None
        body = ""
        try:
            body = get_resp.text
        except Exception:
            body = ""
        if self.marker not in body:
            return None  # not our file / not stored -> not confirmed

        served_ct = (get_resp.headers.get("content-type") or "").split(";")[0].strip().lower()
        path_lower = urlparse(url).path.lower()
        disallowed_ext = next((e for e in DISALLOWED_EXTENSIONS if path_lower.endswith(e)), None)
        exploitable_ct = any(served_ct == t for t in EXPLOITABLE_CONTENT_TYPES)

        # Oracle A: stored AND served with an exploitable content-type.
        # Oracle B: stored AND retrievable at a disallowed extension (policy bypass).
        if exploitable_ct or disallowed_ext:
            reason = []
            if exploitable_ct:
                reason.append(f"served as exploitable content-type '{served_ct}'")
            if disallowed_ext:
                reason.append(f"retrievable at disallowed extension '{disallowed_ext}'")
            return UploadFinding(
                technique=technique, confirmed=True,
                detail=("Uploaded marker file is retrievable and " + " and ".join(reason) + "."),
                marker=self.marker, filename=p["filename"], retrieval_url=url,
                served_content_type=served_ct,
                evidence={
                    "retrieval_status": 200,
                    "served_content_type": served_ct,
                    "disallowed_extension": disallowed_ext,
                    "exploitable_content_type": exploitable_ct,
                    "declared_content_type": p["content_type"],
                    "marker_retrieved": True,
                },
            )
        return None

    async def run(self) -> List[UploadFinding]:
        findings: List[UploadFinding] = []
        own = self._client is None
        client = self._client or httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout
        )
        try:
            for p in self._payloads():
                up = await self._upload(client, p)
                if up is None:
                    findings.append(UploadFinding(
                        technique=p["technique"], confirmed=False,
                        detail="upload request failed or timed out", marker=self.marker,
                        filename=p["filename"], evidence={"upload_error": True}))
                    continue

                confirmed_here = False
                tried: List[Dict[str, Any]] = []
                for url in self._candidate_paths(up, p["filename"]):
                    get_resp = await self._get(client, url)
                    if get_resp is None:
                        tried.append({"url": url, "status": None})
                        continue
                    tried.append({"url": url, "status": get_resp.status_code})
                    finding = self._confirm(p["technique"], p, get_resp, url)
                    if finding is not None:
                        finding.evidence["upload_status"] = up.status_code
                        finding.evidence["retrieval_attempts"] = tried
                        findings.append(finding)
                        confirmed_here = True
                        break

                if not confirmed_here:
                    findings.append(UploadFinding(
                        technique=p["technique"], confirmed=False,
                        detail="marker not retrievable with an exploitable type; not confirmed",
                        marker=self.marker, filename=p["filename"],
                        evidence={"upload_status": up.status_code, "retrieval_attempts": tried}))
        finally:
            if own:
                await client.aclose()
        return findings

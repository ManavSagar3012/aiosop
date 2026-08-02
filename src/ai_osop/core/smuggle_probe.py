"""HTTP request-smuggling (desync) detection via SAFE timing probes.

We do NOT poison other users' requests. We use the standard PortSwigger timing
technique: a CL.TE / TE.CL probe crafted so that, IF the back-end disagrees with the
front-end on message length, the back-end blocks waiting for chunk data that never
arrives — producing a large response delay versus a fast baseline. A timing
differential is the signal; nothing is smuggled into another connection.
"""

import socket
import ssl
import time
from typing import Any, Dict


def build_cl_te_probe(host: str, path: str = "/") -> bytes:
    """CL.TE: front-end honors Content-Length, back-end honors Transfer-Encoding.
    Content-Length truncates the body so a TE back-end is left awaiting the next
    chunk and hangs."""
    body = "1\r\nA\r\nX"  # incomplete from a TE perspective once CL truncates it
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: 4\r\n"
        f"Connection: close\r\n"
        f"\r\n{body}"
    ).encode()


def build_te_cl_probe(host: str, path: str = "/") -> bytes:
    """TE.CL: front-end honors Transfer-Encoding, back-end honors Content-Length.
    The oversized declared chunk leaves a CL back-end waiting for more bytes."""
    body = "0\r\n\r\nX"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: 6\r\n"
        f"Connection: close\r\n"
        f"\r\n{body}"
    ).encode()


def _build_baseline(host: str, path: str = "/") -> bytes:
    return (f"GET {path} HTTP/1.1\r\n" f"Host: {host}\r\n" f"Connection: close\r\n\r\n").encode()


def classify_timing(baseline_ms: float, probe_ms: float, threshold_ms: float = 4000.0) -> bool:
    """Desync indicated when the probe response is delayed far beyond the baseline."""
    return (probe_ms - baseline_ms) >= threshold_ms


def _send_and_time(host: str, port: int, use_tls: bool, raw: bytes, recv_timeout: float) -> float:
    """Send raw bytes; return ms until the first response byte (or recv_timeout*1000)."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=8)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(recv_timeout)
        t0 = time.perf_counter()
        sock.sendall(raw)
        try:
            sock.recv(1)  # time to first byte
        except socket.timeout:
            return recv_timeout * 1000.0
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return -1.0
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def probe_desync(
    host: str,
    port: int,
    *,
    path: str = "/",
    technique: str = "cl.te",
    use_tls: bool = False,
    recv_timeout: float = 8.0,
    threshold_ms: float = 4000.0,
) -> Dict[str, Any]:
    """Run a baseline + desync timing probe. Returns {technique, vulnerable,
    baseline_ms, probe_ms}."""
    baseline_ms = _send_and_time(host, port, use_tls, _build_baseline(host, path), recv_timeout)
    builder = build_te_cl_probe if technique == "te.cl" else build_cl_te_probe
    probe_ms = _send_and_time(host, port, use_tls, builder(host, path), recv_timeout)
    vulnerable = (
        baseline_ms >= 0 and probe_ms >= 0 and classify_timing(baseline_ms, probe_ms, threshold_ms)
    )
    return {
        "technique": technique,
        "vulnerable": vulnerable,
        "baseline_ms": round(baseline_ms, 1),
        "probe_ms": round(probe_ms, 1),
    }

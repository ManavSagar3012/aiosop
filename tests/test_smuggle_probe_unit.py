from ai_osop.core.smuggle_probe import build_cl_te_probe, build_te_cl_probe, classify_timing


def test_cl_te_probe_has_conflicting_headers():
    raw = build_cl_te_probe("example.com", "/")
    assert b"Transfer-Encoding: chunked" in raw
    assert b"Content-Length:" in raw
    assert raw.startswith(b"POST / HTTP/1.1")


def test_te_cl_probe_has_conflicting_headers():
    raw = build_te_cl_probe("example.com", "/")
    assert b"Transfer-Encoding: chunked" in raw
    assert b"Content-Length:" in raw


def test_classify_timing_flags_desync_delay():
    # Probe hangs ~7s vs a fast baseline => desync indicated.
    assert classify_timing(baseline_ms=120, probe_ms=7000, threshold_ms=4000) is True


def test_classify_timing_clean_when_similar():
    assert classify_timing(baseline_ms=120, probe_ms=180, threshold_ms=4000) is False

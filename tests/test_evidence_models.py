from ai_osop.evidence.models import ExploitReceipt, ReceiptArtifact


def _artifact() -> ReceiptArtifact:
    return ReceiptArtifact(
        artifact_id="art-deadbeefcafe",
        kind="http_response",
        sha256="deadbeefcafe",
        blob_path="eng-1/art-deadbeefcafe",
    )


def test_receipt_round_trips_with_artifacts() -> None:
    r = ExploitReceipt(
        receipt_id="rcpt-1",
        engagement_id="eng-1",
        vuln_id="vuln-1",
        approval_id="apr-1",
        hop_idx=None,
        chain_id=None,
        verdict="confirmed",
        confidence=0.97,
        confirmation_note="OAST canary hit",
        oracle_signals={"oast_hit": True},
        artifacts=[_artifact()],
        request_summary={"method": "GET", "url": "https://x/?t=1"},
        response_summary={"http_code": 200},
        scope_hash="abc123",
        timestamp=__import__("datetime").datetime(2026, 8, 1),
        prev_receipt_hash="",
        integrity_sig="",
        simulated=False,
    )
    dumped = r.model_dump()
    assert dumped["receipt_id"] == "rcpt-1"
    assert dumped["artifacts"][0]["artifact_id"] == "art-deadbeefcafe"
    assert dumped["simulated"] is False

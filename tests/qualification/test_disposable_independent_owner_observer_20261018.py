"""Real separate local signer process; production HTTPS fetch is injected only.

No real external VERIFIED claim, signed ROE, target effect or database release.
"""

import asyncio
import base64
import json
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_osop.core import independent_target_effect_observer as observer
from tests.test_independent_target_effect_observer_20261018 import witness, NONCE  # noqa: F401
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@pytest.mark.asyncio
async def test_separate_process_signatures_privacy_and_replay(witness, monkeypatch):
    server_path = Path(__file__).with_name("disposable_owner_observer_server_20261018.py")
    proc = subprocess.Popen(
        [sys.executable, "-u", str(server_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        setup = json.loads(
            await asyncio.wait_for(asyncio.to_thread(proc.stdout.readline), timeout=6)
        )
        assert setup["owner_public"] != setup["observer_public"]
        url = f"http://127.0.0.1:{setup['port']}/audit/{NONCE}"

        def fetch():
            with urlopen(url, timeout=3) as response:
                return json.loads(response.read())

        envelope = await asyncio.to_thread(fetch)
        raw, signature = decode(envelope["observer_claims_b64url"]), decode(
            envelope["observer_signature_b64url"]
        )
        Ed25519PublicKey.from_public_bytes(base64.b64decode(setup["observer_public"])).verify(
            signature, b"observer-local-fixture:" + raw
        )
        claims = json.loads(raw)
        record = decode(claims["owner_claims"])
        Ed25519PublicKey.from_public_bytes(base64.b64decode(setup["owner_public"])).verify(
            decode(claims["owner_signature"]), b"owner-local-fixture:" + record
        )
        assert claims["access"] == {"source": 200, "target": 200, "anonymous": 403}
        assert claims["private_body_included"] is False
        assert b"confidential-lab-record" not in raw and b"confidential-lab-record" not in record
        with pytest.raises(HTTPError) as replay:
            await asyncio.to_thread(fetch)
        assert replay.value.code == 409

        # Production high-level trust fence is exercised with an injected
        # transport: loopback plain HTTP is NEVER passed to its HTTPS socket.
        async def signed_transport(*, origin, pinned_ip, nonce):
            assert origin == witness.config["origin"]
            assert pinned_ip == witness.config["pinned_public_ipv4"]
            assert nonce == NONCE
            return witness.seal()

        monkeypatch.setattr(observer, "_fetch_pinned_audit", signed_transport)
        fetched = await observer.fetch_independent_target_effect_signed_receipt(
            engagement_id=witness.proof.flow.engagement_id,
            flow=witness.proof.flow,
            expected_nonce=NONCE,
        )
        assert fetched == witness.seal()

        witness.config["generation"] += 1
        witness.set_config()

        async def rotate_while_fetching(**_):
            witness.config["generation"] += 1
            witness.set_config()
            return witness.seal()

        monkeypatch.setattr(observer, "_fetch_pinned_audit", rotate_while_fetching)
        with pytest.raises(observer.IndependentEffectUnavailable, match="trust changed"):
            await observer.fetch_independent_target_effect_signed_receipt(
                engagement_id=witness.proof.flow.engagement_id,
                flow=witness.proof.flow,
                expected_nonce=NONCE,
            )
    finally:
        proc.kill()
        await asyncio.to_thread(proc.wait, 5)
        proc.stdout.close()
        proc.stderr.close()

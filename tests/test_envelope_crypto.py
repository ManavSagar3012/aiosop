"""Envelope encryption round-trip + tamper detection (no external KMS)."""

import pytest

from ai_osop.core.envelope_crypto import EnvelopeCipher, LocalKMSProvider


@pytest.mark.asyncio
async def test_envelope_round_trip_same_tenant():
    cipher = EnvelopeCipher(LocalKMSProvider())
    blob = await cipher.encrypt(b"sensitive-payload", tenant_id="org-blue")
    out = await cipher.decrypt(blob)
    assert out == b"sensitive-payload"


@pytest.mark.asyncio
async def test_envelope_tamper_detected():
    import base64

    cipher = EnvelopeCipher(LocalKMSProvider())
    blob = await cipher.encrypt(b"data", tenant_id="org-blue")
    # Flip a bit inside the ciphertext
    raw = bytearray(base64.b64decode(blob["ciphertext"]))
    raw[0] ^= 0x01
    blob["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(Exception):
        await cipher.decrypt(blob)


@pytest.mark.asyncio
async def test_envelope_wrong_tenant_rejected():
    cipher = EnvelopeCipher(LocalKMSProvider())
    blob = await cipher.encrypt(b"data", tenant_id="org-blue")
    blob["tenant_id"] = "org-red"
    with pytest.raises(Exception):
        await cipher.decrypt(blob)

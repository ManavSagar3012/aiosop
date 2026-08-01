"""AIOSOP-SESSION-KDF: session-field encryption must use a stretched KDF.

The old derivation was Fernet(b64(sha256(operator_key))) — a single SHA-256 with
no salt and no stretching, so a low-entropy operator key produced a low-entropy
data key that is cheap to brute-force. The fix derives the key with scrypt while
keeping the legacy sha256 key as a MultiFernet fallback so existing ciphertext
still decrypts. These tests pin all three properties (no DB required).
"""

import base64
import hashlib

import pytest
from cryptography.fernet import Fernet, InvalidToken

from ai_osop.auth.session_store import SessionEncryption

_RAW = "operator-secret-key"


def _legacy_fernet(raw: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw.encode("utf-8")).digest()))


def test_roundtrip_encrypt_decrypt():
    enc = SessionEncryption(key=_RAW)
    ct = enc.encrypt("hunter2")
    assert ct != "hunter2"
    assert enc.decrypt(ct) == "hunter2"


def test_legacy_sha256_ciphertext_still_decrypts():
    # Data written before this change (encrypted with the bare sha256 key) must
    # still be readable via the MultiFernet legacy fallback — no data loss.
    legacy_ct = _legacy_fernet(_RAW).encrypt(b"hunter2").decode("utf-8")
    enc = SessionEncryption(key=_RAW)
    assert enc.decrypt(legacy_ct) == "hunter2"


def test_new_ciphertext_is_not_legacy_key_decryptable():
    # New ciphertext must be under the stronger scrypt key: the legacy key alone
    # must NOT be able to decrypt it, proving the stretch actually took effect.
    enc = SessionEncryption(key=_RAW)
    ct = enc.encrypt("hunter2")
    with pytest.raises(InvalidToken):
        _legacy_fernet(_RAW).decrypt(ct.encode("utf-8"))

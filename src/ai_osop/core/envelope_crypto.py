"""Envelope encryption abstraction with pluggable KMS.

Step F seam: data at rest encryption with AES-256-GCM. The "envelope" is:
  plaintext + AAD -> encrypted with a random data key (DEK)
  DEK itself is encrypted by a master key (KEK) from a KMS provider.

The KMS provider interface is async and injectable so:
  - LocalKMSProvider: in-memory KEK for tests/dev (NOT for production).
  - AWSKMSProvider: real AWS KMS CMK via boto3; only imported when called,
    so this module stays loadable without boto3 installed.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KMSProvider(ABC):
    """Pluggable KMS interface: resolve a tenant-scoped KEK on demand."""

    @abstractmethod
    async def data_key(self, tenant_id: str, key_len: int = 32) -> Dict[str, bytes]:
        """Return a fresh DEK (plaintext) + encrypted DEK (edek) for the tenant."""

    @abstractmethod
    async def decrypt_data_key(self, tenant_id: str, edek: str) -> bytes:
        """Decrypt an encrypted DEK back to plaintext bytes."""


class LocalKMSProvider(KMSProvider):
    """Dev/test KMS: a fixed KEK in memory. NOT safe for production use."""

    def __init__(self, kek: Optional[bytes] = None) -> None:
        self._kek = kek or secrets.token_bytes(32)

    async def data_key(self, tenant_id: str, key_len: int = 32) -> Dict[str, bytes]:
        dek = secrets.token_bytes(key_len)
        nonce = secrets.token_bytes(12)
        edek = AESGCM(self._kek).encrypt(nonce, dek, tenant_id.encode())
        return {
            "dek": dek,
            "edek": base64.b64encode(nonce + edek).decode(),
            "nonce": nonce,  # also returned raw for the DEK -> AES step
        }

    async def decrypt_data_key(self, tenant_id: str, edek: str) -> bytes:
        raw = base64.b64decode(edek)
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(self._kek).decrypt(nonce, ct, tenant_id.encode())


class AWSKMSProvider(KMSProvider):
    """AWS KMS backend. boto3 is imported lazily so the module loads without it."""

    def __init__(self, key_id: str, region: Optional[str] = None):
        self.key_id = key_id
        self.region = region
        self._client = None  # lazy boto3 client

    def _ensure_client(self) -> Any:
        if self._client is None:
            try:
                import boto3
            except ImportError as e:  # pragma: no cover - opt-in path
                raise RuntimeError(
                    "AWSKMSProvider requires boto3; install with `pip install boto3`"
                ) from e
            self._client = boto3.client("kms", region_name=self.region)
        return self._client

    async def data_key(self, tenant_id: str, key_len: int = 32) -> Dict[str, bytes]:
        client = self._ensure_client()
        resp = client.generate_data_key(
            KeyId=self.key_id,
            KeySpec="AES_256",
            EncryptionContext={"tenant_id": tenant_id},
        )
        return {
            "dek": resp["Plaintext"],
            "edek": base64.b64encode(resp["CiphertextBlob"]).decode(),
            "nonce": b"",
        }

    async def decrypt_data_key(self, tenant_id: str, edek: str) -> bytes:
        client = self._ensure_client()
        resp = client.decrypt(
            CiphertextBlob=base64.b64decode(edek),
            EncryptionContext={"tenant_id": tenant_id},
        )
        return resp["Plaintext"]


class EnvelopeCipher:
    """Per-tenant AES-256-GCM envelope encryption."""

    def __init__(self, kms: KMSProvider):
        self.kms = kms

    async def encrypt(self, plaintext: bytes, tenant_id: str, aad: bytes = b"") -> Dict[str, Any]:
        """Encrypt ``plaintext`` with a fresh DEK wrapped by the tenant's KEK."""
        keys = await self.kms.data_key(tenant_id, key_len=32)
        dek = keys["dek"]
        nonce = secrets.token_bytes(12)
        ct = AESGCM(dek).encrypt(nonce, plaintext, tenant_id.encode() + aad)
        return {
            "edek": keys["edek"],
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "alg": "AES-256-GCM",
            "tenant_id": tenant_id,
        }

    async def decrypt(self, blob: Dict[str, Any], aad: bytes = b"") -> bytes:
        """Decrypt a blob produced by ``encrypt``. Raises on tamper or wrong tenant."""
        tenant_id = blob["tenant_id"]
        dek = await self.kms.decrypt_data_key(tenant_id, blob["edek"])
        nonce = base64.b64decode(blob["nonce"])
        ct = base64.b64decode(blob["ciphertext"])
        return AESGCM(dek).decrypt(nonce, ct, tenant_id.encode() + aad)

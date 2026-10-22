"""Non-Docker contract checks for signed, loopback-only Go supervisor admission.

Source inspection below is a contract guard, NOT proof of live Linux execution.
Only the opt-in joined test can attest real Go/0033/HTTPS/PostgreSQL wiring.
No process, target, DB, provider, HTTP listener or Docker daemon is started.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tests.qualification import native_linux_isolated_go_helper_20261020 as linux
from tests.qualification import test_native_isolated_stage_receipt_joined_20261020 as joined

_ROOT = Path(__file__).resolve().parents[2]
_REDEEM = "https://127.0.0.1:18443/native-grants/redeem"
_ISSUER = Ed25519PrivateKey.generate()
_SUPERVISOR = Ed25519PrivateKey.generate()


def _url64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _fixtures(now: int = 1_761_000_000):
    grant = {
        "version": 1,
        "grant_id": "ngr-" + "1" * 32,
        "request_id": "req-" + "2" * 48,
        "engagement_id": "eng-real",
        "flow_id": "flow-real",
        "task_id": "task-real",
        "subtask_id": "subtask-real",
        "action_id": "action-real",
        "server_id": "recon-mcp",
        "lease_id": "lease-real",
        "authorization_sha256": "a" * 64,
        "resource_sha256": "b" * 64,
        "expires_at": now + 40,
    }
    observed = {
        "grant_id": grant["grant_id"],
        "worker_id": "worker-independent-0033",
        "state": "provisioned",
        "epoch": 91,
        "revision": 1,
    }
    return {"claims": grant}, observed


def _proof(*, now: int = 1_761_000_000, **overrides):
    token, observed = _fixtures(now)
    options = {
        "token": token,
        "observed": observed,
        "container_id": "c" * 64,
        "owner_id": "signed-owner",
        "approval_id": "apr-reviewed",
        "lease_id": "lease-real",
        "supervisor_id": "independent-supervisor",
        "supervisor_kid": "supervisor-test-key",
        "signer": _SUPERVISOR,
        "now": now,
    }
    options.update(overrides)
    return joined._signed_provision_proof(**options)


def _native_env() -> dict[str, str]:
    issuer_public = _url64(_ISSUER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    supervisor_public = _url64(
        _SUPERVISOR.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return {
        "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON": json.dumps({"issuer-kid": issuer_public}),
        "OSOP_NATIVE_MCP_REDEEM_URL": _REDEEM,
        "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM": "-----BEGIN CERTIFICATE-----\nredacted-fixture\n-----END CERTIFICATE-----",
        "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON": json.dumps(
            {"recon-mcp": "standalone-test-private-service-secret"}
        ),
        "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON": json.dumps(
            {
                "independent-supervisor": {
                    "kid": "supervisor-test-key",
                    "public_key": supervisor_public,
                    "secret_sha256": hashlib.sha256(b"unique-supervisor-secret").hexdigest(),
                }
            }
        ),
        "OSOP_NATIVE_MCP_STAGE_ROOT": "/run/osop-native-stage",
    }


def test_supervisor_claims_are_exact_go_23_fields_signed_with_independent_domain():
    go = (_ROOT / "mcp-servers/go/sdk/native_supervisor_provision_20261020.go").read_text(
        encoding="utf-8"
    )
    block = go.split("var nativeSupervisorClaimKeys = map[string]bool{", 1)[1].split("}", 1)[0]
    native_fields = set(re.findall(r'"([a-z0-9_]+)": true', block))
    assert len(native_fields) == 23
    assert native_fields == joined.SUPERVISOR_PROVISION_CLAIMS
    assert 'const nativeSupervisorDomain = "ai-osop/native-grant-worker-redemption/v1\\x00"' in go

    proof = _proof()
    assert set(proof) == {"claims", "kid", "signature"}
    assert set(proof["claims"]) == native_fields
    claims = proof["claims"]
    source, observed = _fixtures()
    assert claims["worker_id"] == observed["worker_id"]
    assert claims["epoch"] == observed["epoch"]
    assert claims["revision"] == observed["revision"]
    assert (
        claims["claims_sha256"]
        == hashlib.sha256(
            json.dumps(
                source["claims"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
        ).hexdigest()
    )
    assert claims["resource_sha256"] == source["claims"]["resource_sha256"]
    assert claims["server_id"] == "recon-mcp"
    assert claims["container_id"] == "c" * 64
    assert claims["issued_at"] < claims["expires_at"] <= claims["issued_at"] + 10
    original = joined.SUPERVISOR_PROVISION_DOMAIN + json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    signature = base64.urlsafe_b64decode(proof["signature"] + "==")
    _SUPERVISOR.public_key().verify(signature, original)
    with pytest.raises(InvalidSignature):
        _ISSUER.public_key().verify(signature, original)
    for changed in (
        {**claims, "worker_id": "worker-unobserved"},
        {**claims, "epoch": claims["epoch"] + 1},
        {**claims, "resource_sha256": "f" * 64},
    ):
        with pytest.raises(InvalidSignature):
            _SUPERVISOR.public_key().verify(
                signature,
                joined.SUPERVISOR_PROVISION_DOMAIN
                + json.dumps(
                    changed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode("ascii"),
            )


@pytest.mark.parametrize("remaining", [1, 5, 9, 40])
def test_proof_ttl_is_bounded_by_go_ten_seconds_and_grant_expiry(remaining):
    token, observed = _fixtures()
    token["claims"]["expires_at"] = 1_761_000_000 + remaining
    claims = _proof(token=token, observed=observed)["claims"]
    assert claims["expires_at"] == 1_761_000_000 + min(remaining, 9)
    assert 0 < claims["expires_at"] - claims["issued_at"] <= 9


@pytest.mark.parametrize(
    "state,epoch,revision", [("unknown", 4, 1), ("provisioned", 0, 1), ("provisioned", 1, 0)]
)
def test_proof_requires_current_0033_provision_record(state, epoch, revision):
    token, observed = _fixtures()
    observed.update(state=state, epoch=epoch, revision=revision)
    with pytest.raises(ValueError, match="independently observed"):
        _proof(token=token, observed=observed)


def test_expired_grant_and_malformed_container_refuse_signature():
    token, observed = _fixtures()
    token["claims"]["expires_at"] = 1_761_000_000
    with pytest.raises(ValueError, match="independently observed"):
        _proof(token=token, observed=observed)
    with pytest.raises(ValueError, match="independently observed"):
        _proof(container_id="not-an-actual-container")


def test_native_environment_requires_valid_separate_supervisor_trust_and_pinned_tunnel():
    base = _native_env()
    accepted = linux._environment(base, 14789)
    assert accepted["OSOP_NATIVE_MCP_REDEEM_URL"] == _REDEEM
    assert set(accepted) <= linux._ALLOWED_ENV
    for removed in linux._TRUST_ENV:
        invalid = {key: value for key, value in base.items() if key != removed}
        with pytest.raises(ValueError):
            linux._environment(invalid, 14789)
    with pytest.raises(ValueError):
        linux._environment(
            {
                "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON": base[
                    "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"
                ]
            },
            None,
        )
    for bad in (
        {"issuer": "private-key"},
        {"independent-supervisor": {"kid": "x", "public_key": "abc", "secret_sha256": "0" * 64}},
        {
            "independent-supervisor": {
                "kid": "x",
                "public_key": "abc",
                "secret_sha256": "0" * 64,
                "private_key": "reject",
            }
        },
    ):
        invalid = {**base, "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON": json.dumps(bad)}
        with pytest.raises(ValueError):
            linux._environment(invalid, 14789)
    issuer_public = json.loads(base["OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON"])["issuer-kid"]
    bad_key = json.loads(base["OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"])
    bad_key["independent-supervisor"]["public_key"] = issuer_public
    with pytest.raises(ValueError):
        linux._environment(
            {**base, "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON": json.dumps(bad_key)}, 14789
        )


def test_go_run_trust_order_loopback_remoteaddr_and_local_provision_path_guard():
    sdk = (_ROOT / "mcp-servers/go/sdk/server.go").read_text(encoding="utf-8")
    go = (_ROOT / "mcp-servers/go/sdk/native_supervisor_provision_20261020.go").read_text(
        encoding="utf-8"
    )
    run = sdk.split("func (s *Server) Run(addr string) error {", 1)[1].split("\n}", 1)[0]
    assert (
        run.index("s.configureNativeGrantFromEnvironment()")
        < run.index("s.configureNativeSupervisorFromEnvironment()")
        < run.index("s.Handler()")
    )
    assert 'mux.HandleFunc("/native-supervisor/provision", s.handleSupervisorProvision)' in sdk
    assert "net.SplitHostPort(r.RemoteAddr)" in go
    assert "!net.ParseIP(address).IsLoopback()" in go
    assert 'len(r.Header.Values("Authorization")) != 0' in go
    assert 'len(r.Header.Values("X-OSOP-Native-Supervisor-Proof")) != 0' in go
    assert "c.IssuedAt <= now && now < c.ExpiresAt && c.ExpiresAt <= c.IssuedAt+10" in go
    assert '"http://127.0.0.1:8082" + item["path"]' in linux._POST_CODE
    assert "/native-supervisor/provision" in linux._POST_CODE
    assert "http://127.0.0.1:8082" in linux._POST_CODE
    assert "urllib.request.ProxyHandler({})" in linux._POST_CODE
    # These are embedded subprocess sources; py_compile of the outer helper
    # would not validate their syntax unless explicitly compiled here.
    compile(linux._POST_CODE, "native-local-http-helper", "exec")
    compile(linux._TUNNEL_CODE, "native-local-tls-tunnel", "exec")


@pytest.mark.asyncio
async def test_provision_local_transport_disallows_headers_and_arbitrary_paths_without_exec(
    monkeypatch,
):
    calls = []

    def fake_exec(container, argv, *, data, timeout):
        calls.append((container, argv, json.loads(data), timeout))
        return json.dumps({"status": 200, "body": {"status": "supervisor_proof_provisioned"}})

    monkeypatch.setattr(linux, "_exec", fake_exec)
    worker = linux.IsolatedLinuxGoWorker(
        container_id="c" * 64,
        network_id="n" * 64,
        validator_url=_REDEEM,
        _container_name="qualification-fixture",
    )
    proof = _proof()
    assert await worker.post("/native-supervisor/provision", proof) == (
        200,
        {"status": "supervisor_proof_provisioned"},
    )
    assert len(calls) == 1
    assert calls[0][2]["headers"] == {}
    assert calls[0][2]["path"] == "/native-supervisor/provision"
    for path in (
        "/native-supervisor/issue",
        "http://outside.invalid",
        "/native-supervisor/provision?key=bad",
    ):
        with pytest.raises(ValueError):
            await worker.post(path, proof)
    with pytest.raises(ValueError, match="cannot use caller-supplied headers"):
        await worker.post(
            "/native-supervisor/provision", proof, {"Authorization": "Bearer untrusted"}
        )
    with pytest.raises(ValueError, match="envelope"):
        await worker.post("/native-supervisor/provision", {"claims": {}}, None)
    assert len(calls) == 1

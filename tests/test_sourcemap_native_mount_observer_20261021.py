"""Linux SourceMap observer tests.

The cryptographic fixture uses independently enrolled Ed25519 signing keys;
tests marked 'simulated' replace the kernel probe and are NOT proof of a real
isolated read-only mount. Real /proc tests below run read-only and confirm
that a self namespace, malformed mount, and caller PID cannot be authorized.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import os
import runpy
import stat
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

_FIXTURES_PATH = Path(__file__).with_name("test_sourcemap_original_host_coordinator_20261021.py")
_FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "sourcemap_host_coordinator_fixture_module", _FIXTURES_PATH
)
assert _FIXTURE_SPEC is not None and _FIXTURE_SPEC.loader is not None
_FIXTURE_MODULE = importlib.util.module_from_spec(_FIXTURE_SPEC)
_FIXTURE_SPEC.loader.exec_module(_FIXTURE_MODULE)
_token = _FIXTURE_MODULE._token
context = _FIXTURE_MODULE.context
modules = _FIXTURE_MODULE.modules


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only source-map observer")
def test_simulated_kernel_proof_is_signed_and_bound_to_supervisor_source(
    context: dict,
) -> None:
    mod = context["native_observer"]
    host = context["stage"].OriginalSourceMapHostStage()
    observer = mod.IndependentSourceMapNativeMountObserver(host)
    source = context["supervisor_source"]
    original, source_sha = mod.verify_supervisor_source(
        source, observer._source_roots, "/run/osop-sourcemap/sourcemap-originals"
    )
    assert original["action_id"] == context["claims"]["action_id"]
    assert original["lease_active"] is True
    signed = observer.observe(source)
    assert signed["kid"] == "native-observer"
    claims = signed["claims"]
    assert set(claims) == mod.MOUNT_FIELDS
    assert claims["pid"] == original["pid"]
    assert claims["container_id"] == original["container_id"]
    assert claims["epoch"] == original["epoch"]
    assert claims["pid_start_ticks"] == original["pid_start_ticks"]
    assert claims["native_fsuid"] == original["native_fsuid"]
    assert claims["lease_id"] == original["lease_id"]
    assert claims["supervisor_source_sha256"] == source_sha
    assert claims["read_only"] is True
    assert claims["root_ino"] == context["root"].stat().st_ino
    assert (
        context["mod"]._native_mount_ready(
            signed,
            host,
            observer._observer_roots,
            source,
            observer._source_roots,
            {
                "request_id": original["request_id"],
                "engagement_id": original["engagement_id"],
                "task_id": original["task_id"],
                "artifact_sha256": original["artifact_sha256"],
            },
        )
        == claims
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only source-map observer")
def test_missing_revoked_or_unsafe_signing_principals_deny(
    context: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = context["native_observer"]
    host = context["stage"].OriginalSourceMapHostStage()
    missing = "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON"
    monkeypatch.delenv(missing)
    with pytest.raises(mod.SourceMapNativeMountDenied):
        mod.IndependentSourceMapNativeMountObserver(host)
    monkeypatch.setenv(
        missing,
        '{"native-supervisor-source": "'
        + base64.b64encode(
            context["supervisor"]
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode()
        + '"}',
    )
    key = Path(os.environ["OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_SIGNING_KEY_FILE"])
    key.chmod(0o644)
    with pytest.raises(mod.SourceMapNativeMountDenied):
        mod.IndependentSourceMapNativeMountObserver(host)
    key.chmod(0o600)
    monkeypatch.setenv("OSOP_SOURCEMAP_NATIVE_READONLY_ROOT", "/tmp/arbitrary")
    with pytest.raises(mod.SourceMapNativeMountDenied):
        mod.IndependentSourceMapNativeMountObserver(host)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only source-map observer")
@pytest.mark.parametrize(
    "change",
    [
        {"source_current": False},
        {"lease_active": False},
        {"approval_current": False},
        {"status": "stopped"},
        {"server_id": "recon-mcp"},
        {"native_stage_root": "/tmp/caller-claimed"},
        {"pid": -1},
        {"epoch": 0},
        {"container_id": "a" * 63},
        {"signed_roe_sha256": "untrusted"},
    ],
)
def test_independently_signed_bad_supervisor_source_denied_before_kernel(
    context: dict,
    change: dict,
) -> None:
    mod = context["native_observer"]
    host = context["stage"].OriginalSourceMapHostStage()
    observer = mod.IndependentSourceMapNativeMountObserver(host)
    token = copy.deepcopy(context["supervisor_source"])
    token["claims"].update(change)
    token = _token(
        context["stage"],
        token["claims"],
        context["supervisor"],
        mod.SUPERVISOR_SOURCE_DOMAIN,
        "native-supervisor-source",
    )
    with pytest.raises(mod.SourceMapNativeMountDenied):
        observer.observe(token)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only source-map observer")
def test_forged_cross_process_source_and_expired_lease_denied(
    context: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = context["native_observer"]
    observer = mod.IndependentSourceMapNativeMountObserver(
        context["stage"].OriginalSourceMapHostStage()
    )
    invalid = copy.deepcopy(context["supervisor_source"])
    invalid["claims"]["pid"] += 1  # unchanged signature
    with pytest.raises(mod.SourceMapNativeMountDenied):
        observer.observe(invalid)
    invalid = copy.deepcopy(context["supervisor_source"])
    invalid["signature"] = "A" * 86
    with pytest.raises(mod.SourceMapNativeMountDenied):
        observer.observe(invalid)
    monkeypatch.setattr(
        mod.time,
        "time",
        lambda: context["supervisor_source"]["claims"]["expires_at"] + 1,
    )
    with pytest.raises(mod.SourceMapNativeMountDenied):
        observer.observe(context["supervisor_source"])


def test_mountinfo_exact_ro_vfs_options_and_denials(
    modules: tuple,
) -> None:
    _stage, _coordinator = modules
    from ai_osop.orchestrator import sourcemap_native_mount_observer as mod

    name = "/run/osop-sourcemap/sourcemap-originals"
    ro = f"40 31 0:52 / {name} ro,nosuid,nodev,noexec,relatime - ext4 /dev/vda rw,relatime"
    assert mod._mount_options(ro, name) >= {"ro", "nosuid", "nodev", "noexec"}
    for entry in (
        ro.replace("ro,nosuid", "rw,nosuid"),
        ro.replace("ro,nosuid", "ro,rw,nosuid"),
        ro.replace("ro,nosuid", "ro,nosuid").replace(",noexec", ""),
        ro + "\n" + ro,
        ro.replace(name, "/run/osop-sourcemap/unrelated"),
        "missing fields",
    ):
        with pytest.raises(mod.SourceMapNativeMountDenied):
            mod._mount_options(entry, name)
    escaped = ro.replace("sourcemap-originals", "sourcemap\\055originals")
    assert mod._mount_options(escaped, name) >= {"ro", "nosuid", "nodev", "noexec"}


@pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc only")
def test_real_kernel_process_start_and_self_namespace_fail_closed(
    context: dict,
) -> None:
    """Genuine kernel reads: self PID cannot masquerade as isolated native."""
    mod = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "src/ai_osop/orchestrator/sourcemap_native_mount_observer.py"
        )
    )
    # Avoid the simulated fixture's _observe_proc monkeypatch for this test.
    pid = os.getpid()
    raw = Path(f"/proc/{pid}/stat").read_text()
    start = mod["_process_start_ticks"](raw, pid)
    assert start > 0
    ns = os.stat("/proc/self/ns/mnt").st_ino
    cgroup_sha = hashlib.sha256(Path(f"/proc/{pid}/cgroup").read_bytes()).hexdigest()
    original = context["supervisor_source"]["claims"]
    claims = {
        **original,
        "pid": pid,
        "pid_start_ticks": start,
        "mount_namespace_inode": ns,
        "cgroup_sha256": cgroup_sha,
    }
    with pytest.raises(mod["SourceMapNativeMountDenied"]):
        mod["_observe_proc"](claims, context["stage"].OriginalSourceMapHostStage())
    with pytest.raises(mod["SourceMapNativeMountDenied"]):
        mod["_native_dir_stat"](pid, "/tmp/../unsafe", os.getuid())


@pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc DAC only")
def test_real_native_proc_path_requires_reader_fsuid_and_mode(
    context: dict,
) -> None:
    """O_PATH alone isn't permission evidence; explicit fsuid/mode must agree."""
    native = context["native_observer"]
    probe = context["root"]
    probe.chmod(0o700)
    observed = native._native_dir_stat(os.getpid(), str(probe), os.getuid())
    assert observed.st_uid == os.getuid()
    assert stat.S_IMODE(observed.st_mode) == 0o700
    with pytest.raises(native.SourceMapNativeMountDenied):
        native._native_dir_stat(os.getpid(), str(probe), os.getuid() + 1)
    probe.chmod(0o500)
    with pytest.raises(native.SourceMapNativeMountDenied):
        native._native_dir_stat(os.getpid(), str(probe), os.getuid())
    probe.chmod(0o755)
    with pytest.raises(native.SourceMapNativeMountDenied):
        native._native_dir_stat(os.getpid(), str(probe), os.getuid())
    fs_uid = native._process_fsuid(Path("/proc/self/status").read_text())
    assert fs_uid == os.getuid()
    with pytest.raises(native.SourceMapNativeMountDenied):
        native._process_fsuid("Uid:\t1000\t1000\t1000\tmalformed")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc only")
def test_real_mountinfo_no_assumed_ro_mount(
    modules: tuple,
) -> None:
    _stage, _coordinator = modules
    from ai_osop.orchestrator import sourcemap_native_mount_observer as mod

    actual_mountinfo = Path("/proc/self/mountinfo").read_text()
    assert actual_mountinfo
    # Never treat a generic RW root filesystem or merely a directory inode as
    # SourceMap read-only bind evidence.
    with pytest.raises(mod.SourceMapNativeMountDenied):
        mod._mount_options(actual_mountinfo, "/definitely/not/a/native/sourcemap/mount")

"""Authenticated HAR/manifest reader TOCTOU and engagement provenance regressions.

Tests use disposable real local files only: no app DB, browser, MCP provider,
target, or live mount. Adversarial races are injected at narrow read boundaries
to check fail-closed decisions deterministically on Windows and POSIX.
"""

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from ai_osop.memory import authenticated_resource_paths as paths

ENGAGEMENT = "eng-provenance-a"
FOREIGN = "eng-provenance-b"
RESOURCE = "captures/browser.har"
IMAGE_SHA = "4" * 64


@pytest.fixture
def tenant_files(tmp_path, monkeypatch):
    root = tmp_path / "operator-mounted"
    manual = tmp_path / "manual-imports"
    for directory in (root, manual):
        for tenant in (ENGAGEMENT, FOREIGN):
            (directory / tenant / "captures").mkdir(parents=True)
            (directory / tenant / RESOURCE).write_text(
                json.dumps({
                    "log": {"entries": [{
                        "request": {"method": "GET", "url": "https://example.test/api"},
                    }]}
                }),
                encoding="utf-8",
            )
    descriptor = root / ENGAGEMENT / ".osop-har-mount.json"
    manifest = {
        "engagement_id": ENGAGEMENT,
        "mount_id": "browser-storage-v1",
        "container_image_sha256": IMAGE_SHA,
    }
    descriptor.write_bytes(json.dumps(manifest, separators=(",", ":")).encode())
    pin = hashlib.sha256(descriptor.read_bytes()).hexdigest()
    monkeypatch.setenv("OSOP_AUTHENTICATED_HAR_ROOT", str(root))
    monkeypatch.setenv("OSOP_MANUAL_HAR_ROOT", str(manual))
    monkeypatch.setenv(
        "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
        json.dumps({ENGAGEMENT: pin}),
    )
    return {
        "root": root, "manual": manual, "descriptor": descriptor,
        "har": root / ENGAGEMENT / RESOURCE, "pin": pin,
    }


def test_pinned_mount_and_scoped_resource_read_still_work(tenant_files):
    assert paths.signed_har_mount_attestation(ENGAGEMENT) == (
        tenant_files["pin"], IMAGE_SHA,
    )
    document, digest = paths.snapshot_local_har(ENGAGEMENT, RESOURCE, signed=True)
    assert document["log"]["entries"][0]["request"]["url"] == "https://example.test/api"
    assert digest == hashlib.sha256(tenant_files["har"].read_bytes()).hexdigest()
    assert paths.snapshot_local_har(FOREIGN, RESOURCE, signed=False)[0]["log"]["entries"]


def test_signed_har_snapshot_rejects_mount_descriptor_replaced_mid_read(
    tenant_files, monkeypatch,
):
    original = paths._read_scoped_regular_file
    modified = False
    def inject_mount_swap(root, tenant, pieces, limit):
        nonlocal modified
        content = original(root, tenant, pieces, limit)
        if not modified and pieces[-1].endswith(".har"):
            modified = True
            descriptor = tenant_files["descriptor"]
            descriptor.write_bytes(
                json.dumps({
                    "engagement_id": ENGAGEMENT,
                    "mount_id": "substituted-mount",
                    "container_image_sha256": IMAGE_SHA,
                }).encode()
            )
        return content
    monkeypatch.setattr(paths, "_read_scoped_regular_file", inject_mount_swap)
    with pytest.raises(paths.ResourcePathDenied):
        paths.snapshot_local_har(ENGAGEMENT, RESOURCE, signed=True)
    assert modified


def test_signed_har_snapshot_denies_operator_pin_replaced_during_read(
    tenant_files, monkeypatch,
):
    original = paths._read_scoped_regular_file
    count = 0
    def inject_new_pin(root, tenant, pieces, limit):
        nonlocal count
        content = original(root, tenant, pieces, limit)
        if pieces[-1].endswith(".har"):
            count += 1
            monkeypatch.setenv(
                "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
                json.dumps({ENGAGEMENT: "0" * 64}),
            )
        return content
    monkeypatch.setattr(paths, "_read_scoped_regular_file", inject_new_pin)
    with pytest.raises(paths.ResourcePathDenied):
        paths.snapshot_local_har(ENGAGEMENT, RESOURCE, signed=True)
    assert count == 1


@pytest.mark.parametrize("kind", ["har", "descriptor"])
def test_hard_link_alias_cannot_masquerade_as_tenant_private_resource(
    tenant_files, kind,
):
    source = tenant_files["har"] if kind == "har" else tenant_files["descriptor"]
    foreign_dir = tenant_files["root"] / FOREIGN
    alias = foreign_dir / ("foreign.har" if kind == "har" else "alias.json")
    try:
        os.link(source, alias)
    except (OSError, NotImplementedError):
        pytest.skip("Host filesystem cannot create hard links")
    if kind == "har":
        with pytest.raises(paths.ResourcePathDenied):
            paths.snapshot_local_har(ENGAGEMENT, RESOURCE, signed=True)
    else:
        with pytest.raises(paths.ResourcePathDenied):
            paths.signed_har_mount_attestation(ENGAGEMENT)


@pytest.mark.parametrize("component", ["captures", "browser.har"])
def test_ancestor_or_leaf_rebind_during_resource_read_is_rejected(
    tenant_files, monkeypatch, component,
):
    """Inject a swap as seen in a final lstat, without relying on Windows rename rights."""
    chosen = (
        tenant_files["har"].parent if component == "captures"
        else tenant_files["har"]
    )
    real_lstat = Path.lstat
    observed = 0
    def replaced_identity(path, *args, **kwargs):
        nonlocal observed
        info = real_lstat(path, *args, **kwargs)
        if path == chosen:
            observed += 1
            # For directories and files, the reader must reject a post-open
            # inode replacement even if the document bytes are still valid.
            if observed >= 2:
                values = list(info)
                values[stat.ST_INO] = values[stat.ST_INO] + 121
                return os.stat_result(values)
        return info
    monkeypatch.setattr(Path, "lstat", replaced_identity)
    with pytest.raises(paths.ResourcePathDenied):
        paths.snapshot_local_har(ENGAGEMENT, RESOURCE, signed=True)
    assert observed >= 2


def test_same_size_in_place_rewrite_during_read_is_rejected(tenant_files, monkeypatch):
    """A stable inode/size does not prove stable bytes across the read."""
    original = os.fdopen
    path = tenant_files["har"]
    once = False

    class RewritingReader:
        def __init__(self, underlying):
            self.underlying = underlying

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.underlying.__exit__(*args)

        def fileno(self):
            return self.underlying.fileno()

        def read(self, count):
            nonlocal once
            data = self.underlying.read(count)
            if not once:
                once = True
                old = path.read_bytes()
                replacement = old.replace(b"/api", b"/xyz")
                assert len(replacement) == len(old)
                path.write_bytes(replacement)
                # Force a distinct timestamp even on coarse timestamp FS.
                before = path.stat().st_mtime_ns
                os.utime(path, ns=(before + 2_000_000_000, before + 2_000_000_000))
            return data

    def intercept(fd, mode="r", *args, **kwargs):
        reader = original(fd, mode, *args, **kwargs)
        return RewritingReader(reader) if path.exists() else reader

    monkeypatch.delenv("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS", raising=False)
    monkeypatch.setattr(os, "fdopen", intercept)
    with pytest.raises(paths.ResourcePathDenied):
        paths.snapshot_local_har(ENGAGEMENT, RESOURCE, signed=True)
    assert once


def test_explicit_operator_pin_cannot_authorize_foreign_tenant(tenant_files):
    with pytest.raises(paths.ResourcePathDenied):
        paths.signed_har_mount_attestation(FOREIGN)
    with pytest.raises(paths.ResourcePathDenied):
        paths.snapshot_local_har(
            ENGAGEMENT, f"../{FOREIGN}/{RESOURCE}", signed=True,
        )

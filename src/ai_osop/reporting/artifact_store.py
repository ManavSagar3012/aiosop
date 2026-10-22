"""Create-only report publication; a manifest is published after its artifacts."""

from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Dict

from ai_osop.reporting.attested_storage import validated_report_id

_IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,160}\Z")


def _check_directory(path: Path) -> None:
    for current in (path, *path.parents):
        metadata = current.lstat()
        if current.is_symlink() or bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise OSError("Report directory cannot contain links or reparse points")


def publish_report_bundle(
    root: Path, engagement_id: str, report_id: str, contents: Dict[str, str]
) -> Dict[str, str]:
    """Never replace original bytes, including when reusing an explicit version.

    A crashed publisher can leave an incomplete generation or owned lock.
    Readers require the manifest and exact digests; recovery must select a new
    generation rather than break a live/stale lock and overwrite evidence.
    """
    if not _IDENTIFIER.fullmatch(engagement_id) or not validated_report_id(
        engagement_id, report_id
    ):
        raise ValueError("Invalid report storage identifier")
    directory = root.absolute() / engagement_id
    directory.mkdir(parents=True, exist_ok=True)
    _check_directory(directory)
    lock = directory / f".{report_id}.publish.lock"
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    artifacts: Dict[str, str] = {}
    try:
        for extension in sorted(contents, key=lambda name: (name == "manifest", name)):
            if extension not in {"md", "html", "graph.html", "json", "attestation", "manifest"}:
                raise ValueError("Unexpected report artifact extension")
            path = directory / f"{report_id}.{extension}"
            data = contents[extension].encode("utf-8")
            if path.exists() or path.is_symlink():
                metadata = path.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or path.is_symlink()
                    or metadata.st_size != len(data)
                    or path.read_bytes() != data
                ):
                    raise FileExistsError("Report identity already has different immutable bytes")
            else:
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(
                        dir=directory, prefix=".report-", delete=False
                    ) as stream:
                        temporary = Path(stream.name)
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    # Unlike replace(), link() fails if another writer owns the name.
                    os.link(temporary, path)
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
            artifacts[extension] = str(path)
        return artifacts
    finally:
        lock.unlink()

import os
import tempfile
from unittest.mock import patch

import pytest

from scripts.ops.supervisor import PID_FILE, _check_pidfile, _write_pidfile, _remove_pidfile


def test_check_pidfile_raises_on_live_pid():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pid") as tf:
        tf.write(str(os.getpid()))
        tmp_pid = tf.name
    try:
        with patch("scripts.ops.supervisor.PID_FILE", tmp_pid):
            with pytest.raises(SystemExit) as exc:
                _check_pidfile()
            assert exc.value.code == 1
    finally:
        os.unlink(tmp_pid)


def test_check_pidfile_cleans_up_stale_pid():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pid") as tf:
        tf.write("999999999")
        tmp_pid = tf.name
    try:
        with patch("scripts.ops.supervisor.PID_FILE", tmp_pid):
            _check_pidfile()
        assert not os.path.exists(tmp_pid)
    finally:
        if os.path.exists(tmp_pid):
            os.unlink(tmp_pid)


def test_check_pidfile_noop_when_missing():
    with tempfile.TemporaryDirectory() as tmpdir:
        missing = os.path.join(tmpdir, "nonexistent.pid")
        with patch("scripts.ops.supervisor.PID_FILE", missing):
            _check_pidfile()


def test_write_and_remove_pidfile_round_trip():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_pid = os.path.join(tmpdir, "supervisor.pid")
        with patch("scripts.ops.supervisor.PID_FILE", tmp_pid):
            _write_pidfile()
            assert os.path.exists(tmp_pid)
            with open(tmp_pid) as f:
                assert f.read().strip() == str(os.getpid())
            _remove_pidfile()
            assert not os.path.exists(tmp_pid)


def test_remove_pidfile_noop_when_missing():
    with tempfile.TemporaryDirectory() as tmpdir:
        missing = os.path.join(tmpdir, "nonexistent.pid")
        with patch("scripts.ops.supervisor.PID_FILE", missing):
            _remove_pidfile()

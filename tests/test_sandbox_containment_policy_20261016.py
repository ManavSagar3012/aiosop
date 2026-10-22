"""Docker worker containment without starting containers or changing host rules."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import docker
import pytest

from ai_osop.core.config import settings
from ai_osop.core.exceptions import SandboxException
from ai_osop.safety.scope import SandboxManager


@pytest.fixture
def launch(monkeypatch):
    import subprocess

    actions = []
    client = MagicMock()
    network = MagicMock()
    network.id = "network-disposable"
    network.remove.side_effect = lambda: actions.append(("network.remove",))
    container = MagicMock()
    container.id = "container-disposable"
    container.stop.side_effect = lambda **kw: actions.append(("container.stop", kw))
    container.remove.side_effect = lambda **kw: actions.append(("container.remove", kw))

    def create(name, **kwargs):
        actions.append(("network.create", name, kwargs))
        return network

    def run(image, **kwargs):
        actions.append(("container.run", image, kwargs))
        return container

    def iptables(command, **kwargs):
        actions.append(("iptables", list(command)))
        return SimpleNamespace(returncode=0, stderr=b"")

    client.networks.create.side_effect = create
    client.networks.get.return_value = network
    client.containers.run.side_effect = run
    client.containers.get.return_value = container
    api = MagicMock(return_value=client)
    monkeypatch.setattr(docker, "from_env", api)
    monkeypatch.setattr(subprocess, "run", iptables)
    monkeypatch.setattr(settings, "sandbox_runtime", "docker")
    monkeypatch.setattr(settings, "sandbox_network_mode", "isolated")
    return SimpleNamespace(
        actions=actions,
        api=api,
        client=client,
        network=network,
        container=container,
        manager=SandboxManager(),
    )


def _run_kwargs(launch):
    return next(action[2] for action in launch.actions if action[0] == "container.run")


@pytest.mark.asyncio
async def test_no_egress_default_sealed_before_any_worker_launch(launch):
    result = await launch.manager.create_sandbox(
        "sandbox-15", {"egress": {}, "ingress": {"allowed": False}}
    )
    assert result["network_egress"] == "disabled"
    network = next(a for a in launch.actions if a[0] == "network.create")
    assert network[2]["internal"] is True
    assert network[2]["attachable"] is False
    assert network[2]["enable_ipv6"] is False
    assert not any(a[0] == "iptables" for a in launch.actions)
    opts = _run_kwargs(launch)
    assert opts["privileged"] is False
    assert opts["read_only"] is True
    assert opts["user"] == "65534:65534"
    assert opts["cap_drop"] == ["ALL"]
    assert opts["cap_add"] == []
    assert opts["pid_mode"] == opts["ipc_mode"] == "private"
    assert opts["pids_limit"] == 128
    assert opts["volumes"] == {}
    assert opts["mounts"] == []
    assert opts["devices"] == []
    assert opts["device_requests"] == []
    assert opts["publish_all_ports"] is False
    assert opts["memswap_limit"] == opts["mem_limit"]
    assert opts["mem_limit"] == 4 * 1024**3
    assert "no-new-privileges:true" in opts["security_opt"]
    assert all("unconfined" not in opt for opt in opts["security_opt"])
    assert "/var/run/docker.sock" not in str(opts)
    assert opts["tmpfs"]["/tmp"].count("noexec") == 1


@pytest.mark.asyncio
async def test_scoped_egress_preinstalls_terminal_drop_before_container_run(launch):
    sandbox = await launch.manager.create_sandbox(
        "sandbox-egress", {"egress": {"allowed_ips": ["192.0.2.50/32"]}}
    )
    assert sandbox["network_egress"] == "scoped"
    network_create = next(a for a in launch.actions if a[0] == "network.create")
    assert network_create[2]["internal"] is False
    iptables = [a[1] for a in launch.actions if a[0] == "iptables"]
    assert iptables[0][:2] == ["iptables", "-N"]
    assert any("-d" in cmd and "192.0.2.50/32" in cmd and "ACCEPT" in cmd for cmd in iptables)
    assert any(cmd[-1] == "DROP" and "-A" in cmd for cmd in iptables)
    assert any("DOCKER-USER" in cmd and "-I" in cmd for cmd in iptables)
    assert any("INPUT" in cmd and "-I" in cmd for cmd in iptables)
    assert not any("FORWARD" in cmd for cmd in iptables)
    assert max(i for i, action in enumerate(launch.actions) if action[0] == "iptables") < next(
        i for i, action in enumerate(launch.actions) if action[0] == "container.run"
    )
    assert sandbox["network"]["forward_hook"] is True
    assert sandbox["network"]["input_hook"] is True


@pytest.mark.asyncio
async def test_failure_after_forward_hook_rolls_back_only_created_rules(launch, monkeypatch):
    import subprocess

    def fail_host_input(cmd, **kwargs):
        launch.actions.append(("iptables", list(cmd)))
        return SimpleNamespace(
            returncode=1 if "-I" in cmd and "INPUT" in cmd else 0, stderr=b"denied"
        )

    monkeypatch.setattr(subprocess, "run", fail_host_input)
    with pytest.raises(SandboxException):
        await launch.manager.create_sandbox(
            "rollback-12", {"egress": {"allowed_cidrs": ["198.51.100.0/24"]}}
        )
    assert not any(a[0] == "container.run" for a in launch.actions)
    assert launch.network.remove.call_count == 1
    cmds = [a[1] for a in launch.actions if a[0] == "iptables"]
    assert any(cmd[1:3] == ["-D", "DOCKER-USER"] for cmd in cmds)
    assert not any(cmd[1:3] == ["-D", "INPUT"] for cmd in cmds)
    assert any(cmd[1] == "-F" and cmd[2].startswith("AIOSOP-") for cmd in cmds)
    assert not any(cmd[1] == "-F" and cmd[2] == "FORWARD" for cmd in cmds)
    assert launch.manager._active_sandboxes == {}


@pytest.mark.asyncio
async def test_container_launch_error_removes_own_network_and_firewall(launch):
    launch.client.containers.run.side_effect = RuntimeError("blocked image")
    with pytest.raises(SandboxException):
        await launch.manager.create_sandbox(
            "sandbox-failed", {"egress": {"allowed_ips": ["203.0.113.5"]}}
        )
    assert launch.network.remove.call_count == 1
    cmds = [a[1] for a in launch.actions if a[0] == "iptables"]
    assert any(cmd[1:3] == ["-D", "DOCKER-USER"] for cmd in cmds)
    assert any(cmd[1:3] == ["-D", "INPUT"] for cmd in cmds)
    assert launch.manager._active_sandboxes == {}


@pytest.mark.asyncio
async def test_destroy_removes_container_before_loosening_firewall(launch):
    await launch.manager.create_sandbox(
        "sandbox-destroy", {"egress": {"allowed_ips": ["192.0.2.1"]}}
    )
    launch.actions.clear()
    await launch.manager.destroy_sandbox("sandbox-destroy")
    names = [a[0] for a in launch.actions]
    assert names[:2] == ["container.stop", "container.remove"]
    assert "iptables" in names
    assert names[-1] == "network.remove"


@pytest.mark.asyncio
async def test_destroy_error_keeps_firewall_and_retry_state(launch):
    await launch.manager.create_sandbox(
        "sandbox-stopfails", {"egress": {"allowed_ips": ["192.0.2.7"]}}
    )
    launch.actions.clear()
    launch.container.stop.side_effect = RuntimeError("daemon refused to stop")
    with pytest.raises(SandboxException):
        await launch.manager.destroy_sandbox("sandbox-stopfails")
    assert not any(a[0] == "iptables" for a in launch.actions)
    assert launch.network.remove.call_count == 0
    assert "sandbox-stopfails" in launch.manager._active_sandboxes


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "identifier, policy, resources",
    [
        ("../traversal", {}, None),
        ("", {}, None),
        ("x" * 60, {}, None),
        ("okay", {"ingress": {"allowed": True}}, None),
        ("okay", {"egress": {"allowed_ips": "0.0.0.0/0"}}, None),
        ("okay", {"privileged": True}, None),
        ("okay", {}, {"cpu": "nan", "memory": "4Gi"}),
        ("okay", {}, {"cpu": "1000", "memory": "4Gi"}),
        ("okay", {}, {"cpu": "2", "memory": "9000Gi"}),
        ("okay", {}, {"cpu": "2", "memory": "0Gi"}),
        ("okay", {}, {"cpu": "2", "memory": "4Gi", "volumes": "/:/host"}),
    ],
)
async def test_invalid_policy_or_resources_denied_before_privileged_client(
    launch,
    identifier,
    policy,
    resources,
):
    with pytest.raises(SandboxException):
        await launch.manager.create_sandbox(identifier, policy, resources)
    launch.api.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("forbidden", ["0.0.0.0/0", "::/0", "garbage"])
async def test_unscoped_network_does_not_launch_worker(launch, forbidden):
    with pytest.raises(SandboxException):
        await launch.manager.create_sandbox(
            "sandbox-invalid-network", {"egress": {"allowed_cidrs": [forbidden]}}
        )
    assert not any(a[0] == "container.run" for a in launch.actions)
    # The rejected CIDR never even reached the privileged Docker API.
    launch.api.assert_not_called()
    assert launch.network.remove.call_count == 0


@pytest.mark.asyncio
async def test_host_iptables_missing_fails_before_container_start(launch, monkeypatch):
    import subprocess

    def unavailable(*args, **kwargs):
        raise FileNotFoundError("iptables unsupported")

    monkeypatch.setattr(subprocess, "run", unavailable)
    with pytest.raises(SandboxException):
        await launch.manager.create_sandbox(
            "sandbox-firewall-absent", {"egress": {"allowed_ips": ["198.51.100.3"]}}
        )
    assert not any(a[0] == "container.run" for a in launch.actions)
    assert launch.network.remove.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "daemon", ["tcp://127.0.0.1:2375", "ssh://other-worker", "npipe:////./pipe/docker_engine"]
)
async def test_remote_or_unverifiable_daemon_denied_before_scoped_bridge(
    launch,
    monkeypatch,
    daemon,
):
    monkeypatch.setenv("DOCKER_HOST", daemon)
    with pytest.raises(SandboxException, match="local Docker daemon"):
        await launch.manager.create_sandbox(
            "remote-daemon", {"egress": {"allowed_ips": ["192.0.2.3"]}}
        )
    launch.api.assert_not_called()

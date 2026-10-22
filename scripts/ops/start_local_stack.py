"""Start actual local providers and API; never substitute a stub for Burp.

Uses the separate 20261021 lab database, leaving the older database untouched.
Local credentials and logs remain in .runtime/local-stack, outside Git.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / ".runtime" / "local-stack"
GO_SERVERS = {
    "recon-mcp": 8082,
    "payload-mcp": 8083,
    "nuclei-mcp": 8084,
    "shodan-mcp": 8085,
    "security-bridge": 8087,
}
PY_SERVERS = {
    "browser_mcp": 8091,
    "source_map_mcp": 8096,
    "cloud_mcp": 8097,
    "turbo_intruder_mcp": 8098,
}


def _open(port: int) -> bool:
    with socket.socket() as connection:
        connection.settimeout(0.3)
        return connection.connect_ex(("127.0.0.1", port)) == 0


def _container_env(name: str) -> Dict[str, str]:
    raw = subprocess.check_output(["docker", "inspect", name], text=True)
    return dict(item.split("=", 1) for item in json.loads(raw)[0]["Config"]["Env"] if "=" in item)


def _launch(name: str, port: int, command: list[str], environment: Dict[str, str]) -> None:
    if _open(port):
        print(f"{name}: existing listener on {port}; ownership unverified", flush=True)
        return
    with (RUNTIME / f"{name}.log").open("ab") as output:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        )
    (RUNTIME / f"{name}.pid").write_text(str(process.pid), encoding="ascii")
    for _ in range(80):
        if _open(port):
            print(f"{name}: listening on {port}; execution unverified", flush=True)
            return
        if process.poll() is not None:
            raise RuntimeError(f"{name} exited; inspect its local log")
        time.sleep(0.25)
    print(f"{name}: starting; inspect its local log", flush=True)


def main() -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    names = [
        "ai-osop-codex-pg-20261021",
        "ai-osop-codex-redis-20261021",
        "ai-osop-neo4j",
        "ai-osop-threat-intel-mcp",
    ]
    subprocess.run(["docker", "start", *names], check=True, stdout=subprocess.DEVNULL)
    environment = dict(os.environ)
    for filename in (".env", ".env.opensource"):
        environment.update(
            {
                key: value
                for key, value in dotenv_values(ROOT / filename).items()
                if value is not None
            }
        )
    pg = _container_env(names[0])
    graph_password_file = RUNTIME / "graph-password"
    if not graph_password_file.exists():
        graph_password_file.write_text(secrets.token_urlsafe(36), encoding="ascii")
    graph_password = graph_password_file.read_text(encoding="ascii")
    graph_name = "ai-osop-local-stack-neo4j"
    existing = subprocess.run(
        ["docker", "inspect", graph_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if existing.returncode != 0:
        graph_environment = dict(os.environ, NEO4J_AUTH="neo4j/" + graph_password)
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                graph_name,
                "-p",
                "127.0.0.1:17687:7687",
                "-p",
                "127.0.0.1:17474:7474",
                "-e",
                "NEO4J_AUTH",
                "neo4j:5.18-community",
            ],
            env=graph_environment,
            check=True,
            stdout=subprocess.DEVNULL,
        )
    else:
        subprocess.run(["docker", "start", graph_name], check=True, stdout=subprocess.DEVNULL)
    from urllib.parse import quote

    environment.update(
        {
            "OSOP_ENV": "development",
            "OSOP_MOCK_LLM": "false",
            "OSOP_LLM_API_BASE": "http://127.0.0.1:11434",
            "OSOP_POSTGRES_URI": f"postgresql+asyncpg://{quote(pg['POSTGRES_USER'], safe='')}:{quote(pg['POSTGRES_PASSWORD'], safe='')}@127.0.0.1:55435/{pg['POSTGRES_DB']}",
            "OSOP_REDIS_URI": "redis://127.0.0.1:6380/0",
            "OSOP_NEO4J_URI": "bolt://127.0.0.1:17687",
            "OSOP_NEO4J_PASSWORD": graph_password,
            "OSOP_TEMPORAL_ENABLED": "false",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONPATH": str(ROOT / "src"),
        }
    )
    token_file = RUNTIME / "cloud-bearer"
    if not token_file.exists():
        token_file.write_text(secrets.token_urlsafe(48), encoding="ascii")
    environment.update(
        {
            "OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED": "1",
            "OSOP_CLOUD_MCP_IAC_ROOT": str(ROOT / "tests/fixtures/local_iac"),
            "OSOP_CLOUD_MCP_CHECKOV_PYTHON": str(
                ROOT
                / ".runtime/checkov-venv"
                / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            ),
            "OSOP_CLOUD_MCP_BEARER_TOKEN": token_file.read_text(encoding="ascii"),
            "OSOP_CLOUD_MCP_HOST": "127.0.0.1",
        }
    )
    for name, port in GO_SERVERS.items():
        binary = RUNTIME / (name + (".exe" if os.name == "nt" else ""))
        if not _open(port):
            subprocess.run(
                ["go", "build", "-o", str(binary), f"./cmd/{name}"],
                cwd=ROOT / "mcp-servers/go",
                check=True,
            )
        _launch(name, port, [str(binary)], environment)
    for name, port in PY_SERVERS.items():
        _launch(
            name,
            port,
            [sys.executable, str(ROOT / f"mcp-servers/python/{name}.py"), "--port", str(port)],
            environment,
        )
    _launch(
        "lab-target",
        8080,
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app:app",
            "--app-dir",
            str(ROOT / "docker/lab-target"),
            "--host",
            "127.0.0.1",
            "--port",
            "8080",
        ],
        environment,
    )
    _launch(
        "api",
        8200,
        [
            sys.executable,
            "-m",
            "uvicorn",
            "ai_osop.api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8200",
        ],
        environment,
    )
    node = shutil.which("node")
    if node:
        _launch(
            "ui",
            5173,
            [
                node,
                str(ROOT / "ui/node_modules/vite/bin/vite.js"),
                str(ROOT / "ui"),
                "--host",
                "127.0.0.1",
                "--port",
                "5173",
            ],
            environment,
        )
    if not _open(8081):
        print(
            "burp-mcp: unavailable; an actual Burp extension/backend must be installed", flush=True
        )


if __name__ == "__main__":
    main()

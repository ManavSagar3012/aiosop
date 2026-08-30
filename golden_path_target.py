"""Deliberately-vulnerable web application for the AIOSOP golden path.

A minimal HTTP server with a known SQL injection vulnerability in the login
form's username parameter. Uses stdlib http.server + sqlite3 (in-memory).

Vulnerability: username is concatenated directly into a simulated SQL query.
A payload like ' OR 1=1 -- authenticates without a valid password.
"""

import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

PORT = 9199

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.executescript("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    );
    INSERT INTO users (username, password, role) VALUES ('admin', 'supersecret', 'admin');
    INSERT INTO users (username, password, role) VALUES ('user1', 'password1', 'user');
    INSERT INTO users (username, password, role) VALUES ('user2', 'password2', 'user');
""")

HTML_LOGIN = """<!DOCTYPE html>
<html><head><title>Golden Path Login</title></head><body>
<h1>Golden Path Test App</h1>
<form method="POST" action="/login">
  <label>Username: <input type="text" name="username"></label><br>
  <label>Password: <input type="password" name="password"></label><br>
  <input type="submit" value="Login">
</form>
<p>Hint: try <code>admin</code> / <code>supersecret</code></p>
</body></html>"""

HTML_DASHBOARD = """<!DOCTYPE html>
<html><head><title>Dashboard</title></head><body>
<h1>Welcome, {username}</h1>
<p>Your role: {role}</p>
<p>Account balance: ${balance}</p>
<a href="/logout">Logout</a>
</body></html>"""


class GoldenPathHandler(BaseHTTPRequestHandler):
    """HTTP handler serving a deliberately-vulnerable login app."""

    def _send_html(self, body: str, status: int = 200) -> None:
        body_bytes = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Server", "GoldenPath/1.0")
        self.end_headers()
        self.wfile.write(body_bytes)

    def _send_json(self, data: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_post_body(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:                       return {}
        raw = self.rfile.read(length).decode("utf-8")
        return {k: v[0] if len(v) == 1 else v for k, v in parse_qs(raw).items()}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("", "/login"):
            self._send_html(HTML_LOGIN)
        elif path == "/health":
            self._send_json({"status": "healthy", "app": "golden-path"})
        else:
            self._send_html("<h1>404</h1>", 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/login":
            body = self._read_post_body()
            username = body.get("username", "")
            password = body.get("password", "")

            # VULNERABILITY: SQL injection — username concatenated directly.
            query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
            try:
                cursor = _DB.execute(query)
                row = cursor.fetchone()
                if row:
                    self._send_html(
                        HTML_DASHBOARD.format(
                            username=row[1], role=row[3], balance=50000
                        )
                    )
                else:
                    self._send_html("<h1>Login failed</h1>", 401)
            except Exception as exc:
                self._send_html(f"<h1>Error</h1><pre>{exc}</pre>", 500)
        else:
            self._send_html("<h1>404</h1>", 404)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_golden_path_server(port: int = PORT) -> HTTPServer:
    """Start the golden-path vulnerable server."""
    return HTTPServer(("0.0.0.0", port), GoldenPathHandler)


if __name__ == "__main__":
    server = run_golden_path_server()
    print(f"Golden Path running on http://localhost:{PORT}")
    server.serve_forever()
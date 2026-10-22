"""Isolated loopback test PROCESS with two distinct ephemeral signing roles.

Never an external owner of record. The process holds keys only in memory and
exposes synthetic privacy decisions, not genuine observed target evidence.
"""

import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def main():
    owner, observer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()

    def public(key):
        return base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

    seen = set()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = urlsplit(self.path)
            nonce = parts.path.removeprefix("/audit/")
            if not parts.path.startswith("/audit/") or len(nonce) != 32:
                self.send_error(404)
                return
            if nonce in seen:
                self.send_error(409)
                return
            seen.add(nonce)
            # Each simulated principal has separately logged access outcome.
            decisions = {"source": 200, "target": 200, "anonymous": 403}
            owner_record = json.dumps(
                {
                    "resource": "private-lab",
                    "visibility": "private",
                    "access": decisions,
                    "nonce": nonce,
                },
                sort_keys=True,
            ).encode()
            owner_signature = b64(owner.sign(b"owner-local-fixture:" + owner_record))
            observation = json.dumps(
                {
                    "nonce": nonce,
                    "owner_claims": b64(owner_record),
                    "owner_signature": owner_signature,
                    "access": decisions,
                    "private_body_included": False,
                },
                sort_keys=True,
            ).encode()
            signature = b64(observer.sign(b"observer-local-fixture:" + observation))
            body = json.dumps(
                {"observer_claims_b64url": b64(observation), "observer_signature_b64url": signature}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print(
        json.dumps(
            {
                "port": server.server_port,
                "owner_public": public(owner),
                "observer_public": public(observer),
            }
        ),
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())

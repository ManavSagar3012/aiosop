"""Process-local private record simulator, never an external assessment target.

Its observed events are explicitly synthetic and must never be submitted as
independently verified external target evidence or a PostgreSQL promotion.
"""

from dataclasses import dataclass
import hashlib


@dataclass
class LocalPrivateRecord:
    owner: str = "account_a"
    resource_id: str = "123"
    private_text: bytes = b"confidential-lab-record"
    active: bool = True

    def request(self, role: str) -> tuple[int, bytes]:
        if not self.active:
            return 404, b""
        if role == self.owner:
            return 200, self.private_text
        if role == "account_b":
            # Intentionally vulnerable controlled fixture only.
            return 200, self.private_text
        return 403, b""

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.private_text).hexdigest()

    def revoke(self) -> None:
        self.active = False

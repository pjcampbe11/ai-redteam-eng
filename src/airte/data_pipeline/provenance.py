"""Data provenance and integrity for AI pipelines.

Sign records/chunks on ingest and verify before they enter a prompt or index, so
tampered or injected content (poisoning, OWASP LLM04/LLM08) is detected. Uses
HMAC-SHA256 with a key held in a vault (see airte.cloud.secrets).
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


class IntegrityError(Exception):
    pass


def sign_record(data: str, key: bytes, source: str) -> str:
    """Return a hex HMAC tag binding the data to its declared source."""
    msg = source.encode() + b"\x00" + data.encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_record(data: str, key: bytes, source: str, tag: str) -> None:
    """Raise IntegrityError if the data/source does not match the signed tag."""
    expected = sign_record(data, key, source)
    if not hmac.compare_digest(expected, tag):   # constant-time compare
        raise IntegrityError(
            f"integrity check failed for record from '{source}'")


@dataclass(frozen=True)
class SignedRecord:
    data: str
    source: str
    tag: str

    @classmethod
    def create(cls, data: str, source: str, key: bytes) -> "SignedRecord":
        return cls(data, source, sign_record(data, key, source))

    def verify(self, key: bytes) -> "SignedRecord":
        verify_record(self.data, key, self.source, self.tag)
        return self

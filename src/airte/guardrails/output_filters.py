"""Output-side guardrails: secret/PII redaction before returning model output.

Prevents the model from leaking credentials it may have ingested via context,
tools, or memorization (defense against OWASP LLM02 Sensitive Info Disclosure).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# High-precision secret formats. Order matters (specific before generic).
_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9-]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
]


@dataclass
class SecretRedactor:
    placeholder: str = "[REDACTED:{kind}]"
    found: list[str] = field(default_factory=list)

    def __call__(self, text: str) -> str:
        if not isinstance(text, str):
            return text
        out = text
        for kind, pat in _SECRET_PATTERNS:
            def _sub(m, kind=kind):
                self.found.append(kind)
                return self.placeholder.format(kind=kind)
            out = pat.sub(_sub, out)
        return out


def redact_secrets(text: str) -> str:
    """Convenience: redact secrets/PII from a string and return the result."""
    return SecretRedactor()(text)

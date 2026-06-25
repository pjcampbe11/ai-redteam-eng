"""Least-privilege access patterns for LLM data access.

Enforces that an LLM (or the agent acting on a user's behalf) can only retrieve
data the *end user* is entitled to — preventing the classic RAG confused-deputy
bug where the model has broader read access than the requester.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .dlp import Classification


class LeastPrivilegeError(Exception):
    pass


@dataclass(frozen=True)
class DataScope:
    """What a principal is entitled to read."""
    tenants: frozenset[str]
    max_classification: Classification
    purposes: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class AccessRequest:
    tenant: str
    classification: Classification
    purpose: str


def evaluate_access(scope: DataScope, request: AccessRequest) -> None:
    """Raise LeastPrivilegeError unless the request is within scope.

    Enforces tenant isolation, classification ceiling, and purpose limitation
    (the data-protection principle that data is used only for stated purposes).
    """
    if request.tenant not in scope.tenants:
        raise LeastPrivilegeError(
            f"cross-tenant access blocked: '{request.tenant}'")
    if request.classification > scope.max_classification:
        raise LeastPrivilegeError(
            f"classification {request.classification} exceeds ceiling "
            f"{scope.max_classification}")
    if scope.purposes and request.purpose not in scope.purposes:
        raise LeastPrivilegeError(
            f"purpose '{request.purpose}' not permitted for this principal")

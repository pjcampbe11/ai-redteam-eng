"""Guardrails for tool-using / autonomous agents.

Implements the controls from docs/agentic-security.md that contain a runaway or
adversarially-manipulated agent:

* scoped permissions   - allow-list of (tool, resource) the agent may touch
* step / cost budget   - hard cap on reasoning steps and tool calls (loop guard)
* human-in-the-loop    - high-risk actions require explicit approval
* irreversibility gate - destructive actions are flagged for review
* per-tool rate limits

The ``AgentGuard`` is transport-agnostic: call ``check()`` before executing any
tool the agent requests, and ``record()`` after, regardless of which agent
framework (LangChain, custom, MCP client) you use.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class GuardDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class StepBudgetExceeded(Exception):
    pass


class HumanApprovalRequired(Exception):
    def __init__(self, request: "ToolCallRequest"):
        super().__init__(f"approval required for {request.tool}")
        self.request = request


@dataclass(frozen=True)
class Permission:
    """An allow-list entry. ``resources`` empty means 'any resource for this tool'."""
    tool: str
    resources: frozenset[str] = field(default_factory=frozenset)
    destructive: bool = False


@dataclass(frozen=True)
class ToolCallRequest:
    tool: str
    resource: str | None = None
    args: tuple = ()


@dataclass
class AgentGuard:
    permissions: list[Permission]
    max_steps: int = 25
    max_tool_calls: int = 50
    # tools whose effects cannot be undone -> require human approval
    require_approval_for: frozenset[str] = field(default_factory=frozenset)
    _steps: int = 0
    _calls: int = 0
    _per_tool: dict[str, int] = field(default_factory=dict)
    rate_limit_per_tool: int = 20

    def tick(self) -> None:
        """Count one reasoning step; raise if the budget is exhausted (loop guard)."""
        self._steps += 1
        if self._steps > self.max_steps:
            raise StepBudgetExceeded(
                f"agent exceeded max_steps={self.max_steps} (possible runaway loop)")

    def check(self, request: ToolCallRequest) -> GuardDecision:
        """Decide whether a requested tool call is permitted."""
        if self._calls >= self.max_tool_calls:
            raise StepBudgetExceeded(
                f"agent exceeded max_tool_calls={self.max_tool_calls}")
        if self._per_tool.get(request.tool, 0) >= self.rate_limit_per_tool:
            return GuardDecision.DENY

        perm = self._matching_permission(request)
        if perm is None:
            return GuardDecision.DENY        # default deny (least privilege)
        if request.tool in self.require_approval_for or perm.destructive:
            return GuardDecision.REQUIRE_APPROVAL
        return GuardDecision.ALLOW

    def authorize(self, request: ToolCallRequest, human_approved: bool = False):
        """Enforce the decision. Raises on deny / unapproved high-risk action."""
        decision = self.check(request)
        if decision is GuardDecision.DENY:
            raise PermissionError(
                f"agent not permitted to call {request.tool} on {request.resource}")
        if decision is GuardDecision.REQUIRE_APPROVAL and not human_approved:
            raise HumanApprovalRequired(request)
        return decision

    def record(self, request: ToolCallRequest) -> None:
        self._calls += 1
        self._per_tool[request.tool] = self._per_tool.get(request.tool, 0) + 1

    def _matching_permission(self, request: ToolCallRequest) -> Permission | None:
        for perm in self.permissions:
            if perm.tool != request.tool:
                continue
            if not perm.resources:
                return perm
            if request.resource in perm.resources:
                return perm
        return None

"""Server-enforced, in-memory approval for desktop tool calls.

The owner control panel is deliberately separate from MCP. These controls are
not a security boundary against a process running as the same Windows user.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import secrets
import threading
import time
from typing import Any, Callable

import anyio

MODES = frozenset({"ask", "low_risk", "full"})
# This is an explicit rule, not an AI assessment of GUI contents.
LOW_RISK_TOOLS = frozenset({
    'reach_get_screen_info', 'reach_screenshot', 'reach_list_windows',
    'reach_get_cursor_position', 'reach_wait',
})


class ApprovalError(RuntimeError):
    """The tool has not been authorized to execute."""


@dataclass(frozen=True)
class _Grant:
    token: str


@dataclass
class _Request:
    id: str
    tool: str
    arguments: dict[str, Any]
    client: str
    fingerprint: str
    generation: int
    deadline: float
    created_at: float
    expires_at: float
    decision: bool | None = None
    error: str | None = None


def _normalized(tool: str, arguments: dict, client: str) -> tuple[dict, str]:
    """Snapshot actual validated arguments, including applied defaults."""
    if not isinstance(tool, str) or not isinstance(client, str) or not isinstance(arguments, dict):
        raise ApprovalError("Invalid approval request.")
    try:
        encoded = json.dumps(
            {"tool": tool, "arguments": arguments, "client": client},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ApprovalError("Approval arguments must be finite JSON values.") from exc
    if len(encoded) > 262144:
        raise ApprovalError("Approval request is too large.")
    return json.loads(encoded)["arguments"], hashlib.sha256(encoded.encode("ascii")).hexdigest()


class ApprovalGate:
    """Thread-safe owner decisions with asynchronous, bounded tool waiting.

    Every instance starts in Ask. Temporary automatic modes expire back to Ask.
    authorize() never reads the desktop. consume() is the dispatch boundary:
    a grant is consumed once immediately before the native operation starts.
    Mode changes invalidate waiting requests and grants not yet dispatched.
    Operations already dispatched cannot be undone by changing a mode.
    """

    def __init__(
        self, *, timeout: float = 60.0, max_pending: int = 32,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("Approval timeout must be greater than 0 and at most 60 seconds.")
        if isinstance(max_pending, bool) or not isinstance(max_pending, int) or not 1 <= max_pending <= 32:
            raise ValueError("Approval queue limit must be between 1 and 32.")
        self._timeout = timeout
        self._max_pending = max_pending
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = threading.RLock()
        self._mode = "ask"
        self._mode_deadline: float | None = None
        self._expires_at: float | None = None
        self._generation = 0
        self._closed = False
        self._pending: dict[str, _Request] = {}
        self._grants: dict[str, tuple[str, int, float]] = {}

    def _invalidate_locked(self, reason: str) -> None:
        self._generation += 1
        for request in self._pending.values():
            request.error = reason
        self._pending.clear()
        self._grants.clear()

    def _refresh_locked(self) -> None:
        now = self._clock()
        if self._mode_deadline is not None and now >= self._mode_deadline:
            self._mode = "ask"
            self._mode_deadline = self._expires_at = None
            self._invalidate_locked("Approval mode expired; request approval again.")
        for request_id, request in list(self._pending.items()):
            if now >= request.deadline:
                request.error = "Approval timed out; the tool was not executed."
                del self._pending[request_id]
        for token, (_, _, deadline) in list(self._grants.items()):
            if now >= deadline:
                del self._grants[token]

    def _grant_locked(self, fingerprint: str, deadline: float, request_id: str | None = None) -> _Grant:
        replacing = int(request_id is not None and request_id in self._pending)
        if len(self._pending) + len(self._grants) - replacing >= self._max_pending:
            raise ApprovalError("Approval queue is full; retry after an existing request completes.")
        if self._mode_deadline is not None:
            deadline = min(deadline, self._mode_deadline)
        if request_id is not None:
            self._pending.pop(request_id, None)
        token = secrets.token_urlsafe(32)
        self._grants[token] = (fingerprint, self._generation, deadline)
        return _Grant(token)

    async def authorize(self, tool: str, arguments: dict, client: str = "") -> _Grant:
        arguments, fingerprint = _normalized(tool, arguments, client)
        with self._lock:
            self._refresh_locked()
            if self._closed:
                raise ApprovalError("Approval controller is closed.")
            if self._mode == "full" or (self._mode == "low_risk" and tool in LOW_RISK_TOOLS):
                return self._grant_locked(fingerprint, self._clock() + self._timeout)
            if len(self._pending) + len(self._grants) >= self._max_pending:
                raise ApprovalError("Approval queue is full; retry after an existing request completes.")
            now, wall = self._clock(), self._wall_clock()
            request = _Request(
                id=secrets.token_urlsafe(32), tool=tool, arguments=arguments, client=client,
                fingerprint=fingerprint, generation=self._generation,
                deadline=now + self._timeout, created_at=wall, expires_at=wall + self._timeout,
            )
            self._pending[request.id] = request
        try:
            while True:
                with self._lock:
                    self._refresh_locked()
                    if request.error:
                        raise ApprovalError(request.error)
                    if self._closed or request.generation != self._generation:
                        raise ApprovalError("Approval changed; request approval again.")
                    if request.decision is False:
                        raise ApprovalError("The owner denied this tool call.")
                    if request.decision is True:
                        return self._grant_locked(fingerprint, request.deadline, request.id)
                # No worker thread is occupied while an owner reviews a request.
                await anyio.sleep(0.05)
        finally:
            with self._lock:
                self._pending.pop(request.id, None)

    def consume(self, grant: _Grant, tool: str, arguments: dict, client: str = "") -> None:
        """Atomically claim one matching grant just before desktop dispatch."""
        _, fingerprint = _normalized(tool, arguments, client)
        with self._lock:
            self._refresh_locked()
            token = grant.token if isinstance(grant, _Grant) else None
            issued = self._grants.pop(token, None)
            if (
                self._closed or issued is None or issued[0] != fingerprint
                or issued[1] != self._generation or self._clock() >= issued[2]
            ):
                raise ApprovalError("Approval is missing, expired, changed, or already used.")

    def revoke(self, grant: _Grant | None) -> None:
        """Discard an unused grant when a waiting request is cancelled or fails."""
        with self._lock:
            if isinstance(grant, _Grant):
                self._grants.pop(grant.token, None)

    def snapshot(self) -> dict:
        with self._lock:
            self._refresh_locked()
            return {
                "mode": self._mode,
                "expires_at": self._expires_at,
                "closed": self._closed,
                "pending": [
                    {
                        "id": r.id, "tool": r.tool,
                        "arguments": json.loads(json.dumps(r.arguments)),
                        "client": r.client, "created_at": r.created_at,
                        "expires_at": r.expires_at,
                    }
                    for r in self._pending.values()
                    if r.error is None and r.decision is None
                ],
            }

    def decide(self, request_id: str, allow: bool) -> bool:
        if not isinstance(request_id, str) or not isinstance(allow, bool):
            return False
        with self._lock:
            self._refresh_locked()
            request = self._pending.get(request_id)
            if self._closed or request is None or request.decision is not None or request.error:
                return False
            request.decision = allow
            return True

    def set_mode(self, mode: str, duration: float = 900) -> None:
        if not isinstance(mode, str) or mode not in MODES:
            raise ValueError("Mode must be ask, low_risk, or full.")
        if (
            isinstance(duration, bool) or not isinstance(duration, (int, float))
            or not math.isfinite(duration) or not 0 < duration <= 3600
        ):
            raise ValueError("Mode duration must be greater than 0 and at most 3600 seconds.")
        with self._lock:
            if self._closed:
                raise ApprovalError("Approval controller is closed.")
            self._invalidate_locked("Approval mode changed; request approval again.")
            self._mode = mode
            self._mode_deadline = None if mode == "ask" else self._clock() + duration
            self._expires_at = None if mode == "ask" else self._wall_clock() + duration

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._mode = "ask"
            self._mode_deadline = self._expires_at = None
            self._invalidate_locked("Approval controller closed; the tool was not executed.")

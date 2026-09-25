"""Lifecycle hook registry (CC-02).

Hooks are the extension seam around the harness — the equivalent of Claude Code's
pre/post tool hooks. Four events:

  * ``pre_phase``  / ``post_phase``  — around every orchestrator phase transition
  * ``pre_tool``   / ``post_tool``   — around every check execution by a specialist agent

A ``pre_tool`` hook may **veto** the tool call by returning ``HookVeto(reason)``; the
agent then records a ``vetoed`` decision instead of running the check and the reason
lands in the audit trail. Hooks never widen scope — they can only observe or refuse.
Hook failures are contained: an exception in a hook is logged and treated as "no
opinion", so an observer hook cannot crash an assessment.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("sentrik.hooks")

EVENTS = ("pre_phase", "post_phase", "pre_tool", "post_tool")

HookFn = Callable[[dict], Any | Awaitable[Any]]


@dataclass(frozen=True)
class HookVeto:
    reason: str


@dataclass
class HookOutcome:
    vetoed: bool = False
    reason: str = ""
    ran: int = 0
    errors: list[str] = field(default_factory=list)


class HookRegistry:
    def __init__(self) -> None:
        self._hooks: dict[str, list[tuple[str, HookFn]]] = {e: [] for e in EVENTS}

    def register(self, event: str, fn: HookFn, *, name: str = "") -> None:
        if event not in self._hooks:
            raise ValueError(f"unknown hook event {event!r}; expected one of {EVENTS}")
        self._hooks[event].append((name or getattr(fn, "__name__", "hook"), fn))

    def unregister(self, event: str, fn: HookFn) -> None:
        self._hooks[event] = [(n, f) for n, f in self._hooks.get(event, []) if f is not fn]

    def clear(self) -> None:
        for e in EVENTS:
            self._hooks[e] = []

    def registered(self, event: str) -> list[str]:
        return [n for n, _ in self._hooks.get(event, [])]

    async def run(self, event: str, payload: dict) -> HookOutcome:
        """Run every hook for ``event``. The first ``HookVeto`` wins (pre_* events only)."""
        outcome = HookOutcome()
        for name, fn in list(self._hooks.get(event, [])):
            try:
                res = fn(dict(payload))
                if inspect.isawaitable(res):
                    res = await res
            except Exception as exc:  # observer failure must not propagate
                log.warning("hook %s/%s failed: %s", event, name, exc)
                outcome.errors.append(f"{name}: {type(exc).__name__}: {exc}")
                continue
            outcome.ran += 1
            if isinstance(res, HookVeto) and event.startswith("pre_"):
                outcome.vetoed = True
                outcome.reason = f"{name}: {res.reason}"
                break
        return outcome


# process-wide registry (tests call ``hooks.clear()``)
hooks = HookRegistry()

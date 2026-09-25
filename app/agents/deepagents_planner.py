"""Optional Deep Agents-backed planning re-ranker.

Deep Agents (``deepagents``, built on LangChain + LangGraph) is integrated here **only**
as a re-ranker over an already-authorized, deterministic plan. Per the prior evaluation
(``docs/DEEPAGENTS_EVAL.md``), Deep Agents' builtin shell/filesystem tools are
safety-negative for this product, so the re-ranker agent is constructed so those tools
**cannot act**:

* ``create_deep_agent`` registers builtin file tools (``ls/read_file/write_file/
  edit_file/delete/glob/grep``) and a shell ``execute`` tool by default. Passing
  ``tools=[]`` only means "no *extra* tools" — it does NOT remove the builtins. So we
  additionally pass a catch-all :func:`filesystem_deny_rules` (``FilesystemPermission``
  with ``mode="deny"`` over all paths and read+write ops), which makes every filesystem
  tool call return a permission-denied error, and we pass **no** ``SandboxBackendProtocol``
  backend, so the ``execute`` shell tool is inert (it errors without a sandbox backend).
* Structured output is obtained via LangChain's ``response_format`` (a Pydantic schema),
  not by scraping free text.

The integration is strictly optional and safety-preserving:

* If ``use_deepagents_planner`` is off, ``deepagents`` is not importable, or no Anthropic
  API key is set, :func:`rerank_plan` returns the input plan unchanged.
* :func:`rerank_plan` is *reorder-only*: it never adds, drops, mutates, or duplicates
  steps. Unknown check names keep their original relative order. Any error falls back to
  the unchanged plan.
"""

from __future__ import annotations

import importlib.util
import json
from typing import Any

from pydantic import BaseModel, Field

from app.core.config import get_settings

_SYSTEM_PROMPT = (
    "You are a security-test PLAN RE-RANKER. You receive an already-authorized list of "
    "security-test steps identified by their check names. Your ONLY job is to propose a "
    "better EXECUTION ORDER over those exact check names — highest priority first. You "
    "must NOT add, remove, invent, or rename any step, and you must NOT execute anything, "
    "touch the filesystem, or run shell commands. Return the reordered check names."
)


class ReorderedPlan(BaseModel):
    """Structured response schema for the re-ranker (LangChain ``response_format``)."""

    order: list[str] = Field(
        default_factory=list,
        description="A permutation/subset of the provided check names, highest priority first.",
    )


def deepagents_available() -> bool:
    """True iff the ``deepagents`` package is installed."""
    return importlib.util.find_spec("deepagents") is not None


def planner_tools() -> list:
    """The list of *extra* tools handed to the re-ranker agent — always empty.

    The re-ranker is granted no additional tools; the builtin filesystem/shell tools that
    ``create_deep_agent`` registers are neutralized separately (see
    :func:`filesystem_deny_rules` and the module docstring).
    """
    return []


def filesystem_deny_rules() -> list:
    """A catch-all ``FilesystemPermission`` deny rule set (empty if deepagents absent).

    Denies read+write filesystem operations on all paths, so every builtin file tool
    (``ls/read_file/write_file/edit_file/delete/glob/grep``) returns permission-denied.
    """
    try:
        from deepagents import FilesystemPermission
    except Exception:
        return []
    # Paths must be absolute globs; "/**" (plus "/") matches every filesystem path.
    return [
        FilesystemPermission(operations=["read", "write"], paths=["/**", "/"], mode="deny")
    ]


def _build_chat_model(model: Any, api_key: str) -> Any:
    """Return a LangChain chat model. A non-str ``model`` is assumed to be an instance."""
    if model is None:
        return None
    if not isinstance(model, str):
        return model
    from langchain.chat_models import init_chat_model

    return init_chat_model(model, model_provider="anthropic", api_key=api_key)


def build_reranker_agent(model: Any, api_key: str) -> Any:
    """Construct the Deep Agent re-ranker with builtin tools neutralized, or ``None``.

    Uses ``create_deep_agent`` with an empty extra-tool list, a catch-all filesystem deny
    rule set, structured ``response_format``, and no sandbox backend (so ``execute`` is
    inert). Returns ``None`` on any construction error.
    """
    try:
        from deepagents import create_deep_agent

        chat_model = _build_chat_model(model, api_key)
        if chat_model is None:
            return None
        return create_deep_agent(
            model=chat_model,
            tools=planner_tools(),  # no extra tools
            system_prompt=_SYSTEM_PROMPT,
            permissions=filesystem_deny_rules(),  # deny all builtin filesystem tools
            response_format=ReorderedPlan,  # structured output
        )
    except Exception:
        return None


async def rerank_plan(planned: list, context: dict) -> list:
    """Optionally reorder an authorized plan via the Deep Agent re-ranker; safe fallback.

    Returns ``planned`` unchanged when disabled, ``deepagents`` is unavailable, no API key
    is set, the plan is empty, or on any error. When active it applies a REORDER ONLY over
    the step ``check_name`` values.
    """
    settings = get_settings()
    if (
        not settings.use_deepagents_planner
        or not deepagents_available()
        or not settings.anthropic_api_key
        or not planned
    ):
        return planned
    try:
        agent = build_reranker_agent(settings.planner_model, settings.anthropic_api_key)
        if agent is None:
            return planned
        check_names = [step.check_name for step in planned]
        prompt = json.dumps(
            {
                "instruction": "Reorder these security-test check names, best first.",
                "check_names": check_names,
                "context": _safe_context(context),
            }
        )
        result = await agent.ainvoke({"messages": [{"role": "user", "content": prompt}]})
        order = _extract_order(result)
        if not order:
            return planned
        reordered = _apply_reorder(planned, order)
        # Safety invariant: identical multiset of steps, only reordered.
        if len(reordered) != len(planned):
            return planned
        return reordered
    except Exception:
        return planned


def _extract_order(result: Any) -> list[str]:
    """Pull the ordered check names from the agent result.

    Prefers LangChain's structured ``structured_response`` (a :class:`ReorderedPlan` or
    dict); falls back to parsing a JSON object out of the final message text.
    """
    structured = result.get("structured_response") if isinstance(result, dict) else None
    if isinstance(structured, ReorderedPlan):
        return [str(n) for n in structured.order]
    if isinstance(structured, dict) and isinstance(structured.get("order"), list):
        return [str(n) for n in structured["order"]]
    payload = _first_json_object(_last_message_text(result))
    if isinstance(payload, dict) and isinstance(payload.get("order"), list):
        return [str(n) for n in payload["order"]]
    return []


def _last_message_text(result: Any) -> str:
    messages = result.get("messages") if isinstance(result, dict) else getattr(result, "messages", None)
    if not messages:
        return ""
    last = messages[-1]
    content = getattr(last, "content", None)
    if content is None and isinstance(last, dict):
        content = last.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            b if isinstance(b, str) else b.get("text", "")
            for b in content
            if isinstance(b, (str, dict))
        ]
        return "".join(parts)
    return str(content or "")


def _first_json_object(text: str) -> Any:
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except Exception:
                        break
        start = text.find("{", start + 1)
    return None


def _apply_reorder(planned: list, order: list[str]) -> list:
    """Pure reorder of ``planned`` by first appearance of each ``check_name`` in ``order``;
    steps not named keep their original relative position at the end."""
    rank: dict[str, int] = {}
    for i, name in enumerate(order):
        rank.setdefault(name, i)
    default = len(order)
    indexed = list(enumerate(planned))
    indexed.sort(key=lambda pair: (rank.get(pair[1].check_name, default), pair[0]))
    return [step for _, step in indexed]


def _safe_context(context: dict) -> dict:
    if not isinstance(context, dict):
        return {}
    return {
        str(k): v
        for k, v in context.items()
        if isinstance(v, (str, int, float, bool)) or v is None
    }

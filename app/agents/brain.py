"""Agent brains.

`Brain` is the reasoning interface every agent uses. Two implementations:

  * LLMBrain          — calls the Anthropic Messages API and parses a JSON decision.
  * DeterministicBrain — a rule-based brain implementing the identical interface,
                         used automatically when no API key is set (keeps the platform
                         runnable and end-to-end testable without external calls).

`get_brain()` returns an LLMBrain when an Anthropic key is configured, else a
DeterministicBrain. Both are bounded: token/step budgets are enforced by callers.
Brains only ever RANK, SELECT-AMONG-ALLOWED, or HYPOTHESIZE. They never receive the
authorization record or secrets, and their output is treated as untrusted: callers
validate every field against the deterministic policy before acting on it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.agents.budget import get_current_budget
from app.core.config import get_settings

log = logging.getLogger("sentrik.brain")

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


@dataclass
class BrainTask:
    role: str  # agent role, e.g. "sqli-specialist"
    instruction: str  # what to decide
    context: dict = field(default_factory=dict)  # untrusted facts (endpoint, signals)
    allowed_actions: list[str] = field(
        default_factory=list
    )  # closed set the brain may pick from
    max_tokens: int = 512


@dataclass
class BrainDecision:
    action: str  # chosen action (validated by caller against allowed_actions)
    reasoning: str  # short rationale (for audit trail)
    params: dict = field(default_factory=dict)
    # "llm" | "deterministic" | "llm_fallback" | "budget_exceeded" | "local_llm"…
    source: str = "deterministic"
    confidence: float = 0.6
    input_tokens: int = 0  # LLM usage for this decision (0 for deterministic)
    output_tokens: int = 0


class Brain:
    kind = "base"

    async def decide(self, task: BrainTask) -> BrainDecision:  # pragma: no cover
        raise NotImplementedError


class DeterministicBrain(Brain):
    """Rule-based brain. Deterministic, offline, and safe by construction."""

    kind = "deterministic"

    async def decide(self, task: BrainTask) -> BrainDecision:
        action = task.allowed_actions[0] if task.allowed_actions else "proceed"
        # Simple, explainable heuristics keyed by role.
        ctx = task.context
        params: dict[str, Any] = {}
        reasoning = f"deterministic policy for {task.role}: default to '{action}'"

        if task.role.endswith("specialist"):
            # prioritize parameters that look injectable
            params["param_order"] = _rank_params(ctx.get("parameters", []))
            reasoning = "ranked parameters by injectability heuristic"
        elif task.role == "planner":
            params["strategy"] = "coverage-first"
        elif task.role == "coordinator":
            # choose whether to continue based on remaining budget/signal
            if ctx.get("budget_remaining", 1) <= 0:
                action = "stop" if "stop" in task.allowed_actions else action
                reasoning = "budget exhausted"
        elif task.role == "validator":
            params["independent"] = True
        return BrainDecision(
            action=action,
            reasoning=reasoning,
            params=params,
            source="deterministic",
            confidence=0.6,
        )


_SYSTEM_PROMPT = (
    "You are a bounded reasoning module inside an AUTHORIZED security-testing "
    "platform. You only choose among the explicitly allowed actions and propose "
    "parameters. You never invent targets, never request out-of-scope hosts, and "
    "never attempt to change authorization. Respond ONLY with compact JSON: "
    '{"action": <one of allowed_actions>, "reasoning": <=280 chars, '
    '"params": {..}, "confidence": 0..1}.'
)


def _langchain_client(model: str, api_key: str):
    """Return a LangChain ChatAnthropic client if langchain-anthropic is available."""
    try:
        from langchain_anthropic import ChatAnthropic
    except Exception:  # noqa: BLE001
        return None
    try:
        return ChatAnthropic(model=model, api_key=api_key, max_tokens=512, timeout=30)
    except Exception:  # noqa: BLE001
        return None


class LLMBrain(Brain):
    """Anthropic-backed brain. Uses LangChain's ChatAnthropic when available (framework
    integration), else the raw Messages API. Falls back to DeterministicBrain on any error."""

    kind = "llm"

    def __init__(self, api_key: str, model: str, *, prefer_langchain: bool = True):
        self._api_key = api_key
        self._model = model
        self._fallback = DeterministicBrain()
        self._lc = _langchain_client(model, api_key) if prefer_langchain else None
        self.transport = "langchain" if self._lc is not None else "httpx"

    async def decide(self, task: BrainTask) -> BrainDecision:
        # F-09: if the assessment's token/cost budget is already spent, do not make the
        # network call — degrade to the deterministic brain and mark the source so the
        # audit trail shows *why* this decision was not LLM-reasoned.
        budget = get_current_budget()
        if budget is not None and budget.exceeded():
            d = await self._fallback.decide(task)
            d.source = "budget_exceeded"
            return d

        user = json.dumps(
            {
                "role": task.role,
                "instruction": task.instruction,
                "allowed_actions": task.allowed_actions,
                "context": _truncate_context(task.context),
            }
        )
        try:
            if self._lc is not None:
                text, usage = await self._decide_langchain(user)
            else:
                text, usage = await self._decide_httpx(user, task.max_tokens)
            decision = _parse_decision(text)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.warning("LLM brain error (%s); falling back", exc)
            return await self._fallback_with_source(task)
        except Exception as exc:  # noqa: BLE001  langchain raises varied types
            log.warning("LLM brain (langchain) error (%s); falling back", exc)
            return await self._fallback_with_source(task)

        # Record token usage against the active per-assessment ledger (F-09).
        in_tok, out_tok = usage
        decision.input_tokens, decision.output_tokens = in_tok, out_tok
        if budget is not None:
            budget.record(in_tok, out_tok)
        # Validate the LLM's chosen action against the closed allowed set.
        if task.allowed_actions and decision.action not in task.allowed_actions:
            decision.action = task.allowed_actions[0]
            decision.reasoning = "[coerced to allowed] " + decision.reasoning
        decision.source = "llm"
        return decision

    async def _decide_langchain(self, user: str) -> tuple[str, tuple[int, int]]:
        from langchain_core.messages import HumanMessage, SystemMessage

        resp = await self._lc.ainvoke(
            [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=user)]
        )
        content = resp.content
        if isinstance(content, list):  # some providers return content blocks
            content = "".join(
                b.get("text", "") if isinstance(b, dict) else str(b) for b in content
            )
        return str(content), _langchain_usage(resp)

    async def _decide_httpx(
        self, user: str, max_tokens: int
    ) -> tuple[str, tuple[int, int]]:
        payload = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": _SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user}],
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(ANTHROPIC_URL, headers=headers, json=payload)
        if resp.status_code >= 400:
            raise httpx.HTTPError(f"LLM brain HTTP {resp.status_code}")
        data = resp.json()
        usage = data.get("usage") or {}
        return _extract_text(data), (
            int(usage.get("input_tokens", 0) or 0),
            int(usage.get("output_tokens", 0) or 0),
        )

    async def _fallback_with_source(self, task: BrainTask) -> BrainDecision:
        d = await self._fallback.decide(task)
        d.source = "llm_fallback"
        return d


class LocalLLMBrain(Brain):
    """Private-deployment brain: an OpenAI-compatible local endpoint (vLLM/Ollama/LM Studio).

    Keeps inference on-prem (no data leaves the network). Falls back to DeterministicBrain
    on any error. Selected when SENTINEL_LOCAL_LLM_BASE_URL is set.
    """

    kind = "local_llm"

    def __init__(self, base_url: str, model: str, api_key: str = "local"):
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._api_key = api_key
        self._fallback = DeterministicBrain()
        self.transport = "openai_compatible"

    async def decide(self, task: BrainTask) -> BrainDecision:
        budget = get_current_budget()
        if budget is not None and budget.exceeded():
            d = await self._fallback.decide(task)
            d.source = "budget_exceeded"
            return d

        user = json.dumps(
            {
                "role": task.role,
                "instruction": task.instruction,
                "allowed_actions": task.allowed_actions,
                "context": _truncate_context(task.context),
            }
        )
        payload = {
            "model": self._model,
            "max_tokens": task.max_tokens,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    self._url,
                    json=payload,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
            if resp.status_code >= 400:
                raise httpx.HTTPError(f"local LLM HTTP {resp.status_code}")
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
            decision = _parse_decision(text)
        except Exception as exc:  # noqa: BLE001
            log.warning("local LLM brain error (%s); falling back", exc)
            d = await self._fallback.decide(task)
            d.source = "local_llm_fallback"
            return d
        usage = data.get("usage") or {}
        in_tok = int(usage.get("prompt_tokens", 0) or 0)
        out_tok = int(usage.get("completion_tokens", 0) or 0)
        decision.input_tokens, decision.output_tokens = in_tok, out_tok
        if budget is not None:
            budget.record(in_tok, out_tok)
        if task.allowed_actions and decision.action not in task.allowed_actions:
            decision.action = task.allowed_actions[0]
        decision.source = "local_llm"
        return decision


_singleton: Brain | None = None


def get_brain() -> Brain:
    """Return the configured brain.

    Priority: local self-hosted endpoint (private deployment) → Anthropic (LangChain/raw)
    → deterministic fallback (offline, always available).
    """
    global _singleton
    if _singleton is not None:
        return _singleton
    s = get_settings()
    if s.local_llm_base_url and s.local_llm_model:
        _singleton = LocalLLMBrain(
            s.local_llm_base_url, s.local_llm_model, s.local_llm_api_key
        )
    elif s.anthropic_api_key:
        _singleton = LLMBrain(
            s.anthropic_api_key, s.planner_model, prefer_langchain=s.use_langchain_brain
        )
    else:
        _singleton = DeterministicBrain()
    return _singleton


def reset_brain() -> None:
    global _singleton
    _singleton = None


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _rank_params(params: list[dict]) -> list[str]:
    def score(p: dict) -> int:
        name = p.get("name", "").lower()
        s = 0
        if any(
            h in name for h in ("id", "user", "search", "q", "query", "name", "email")
        ):
            s += 3
        if p.get("in") in ("query", "body"):
            s += 1
        return s

    return [
        p.get("name", "")
        for p in sorted(params, key=score, reverse=True)
        if p.get("name")
    ]


def _truncate_context(ctx: dict, limit: int = 4000) -> dict:
    """Backward-compatible alias — see ``_compact_context`` (G-04)."""
    return _compact_context(ctx, limit)


def _compact_context(ctx: dict, limit: int = 4000, *, max_str: int = 200) -> dict:
    """Deterministic context compaction (G-04 / CC-03).

    The brain's context must fit a character budget *and* stay valid, meaningful JSON
    (the old behaviour cut the serialized text mid-token). Strategy, applied only as far
    as needed: (1) shorten long strings, (2) trim the longest list from its tail — lists
    are pre-ranked so the head is the most useful part — (3) drop the largest remaining
    key. A ``_compacted`` marker records what was removed so the decision trail is honest.
    """

    def size(obj) -> int:
        return len(json.dumps(obj, default=str))

    if size(ctx) <= limit:
        return ctx
    out: dict = json.loads(json.dumps(ctx, default=str))
    note: dict = {"strings_shortened": 0, "lists_trimmed": {}, "keys_dropped": []}

    def shorten(obj):
        if isinstance(obj, str) and len(obj) > max_str:
            note["strings_shortened"] += 1
            return obj[:max_str] + "…"
        if isinstance(obj, list):
            return [shorten(x) for x in obj]
        if isinstance(obj, dict):
            return {k: shorten(v) for k, v in obj.items()}
        return obj

    out = shorten(out)
    # (2) trim the longest top-level list, one element at a time from the tail
    while size(out) + size(note) > limit:
        lists = [(k, v) for k, v in out.items() if isinstance(v, list) and len(v) > 1]
        if not lists:
            break
        k, v = max(lists, key=lambda kv: size(kv[1]))
        out[k] = v[:-1]
        note["lists_trimmed"][k] = note["lists_trimmed"].get(k, 0) + 1
    # (3) drop the largest remaining key
    while size(out) + size(note) > limit and out:
        k = max(out, key=lambda key: size(out[key]))
        del out[k]
        note["keys_dropped"].append(k)
    out["_compacted"] = note
    return out


def _langchain_usage(resp) -> tuple[int, int]:
    """Extract (input_tokens, output_tokens) from a LangChain AIMessage.

    LangChain surfaces token counts in ``usage_metadata`` (preferred) or, for older
    providers, in ``response_metadata['usage']`` / ``['token_usage']``. Missing counts
    degrade to 0 so budgeting never crashes on a provider that omits usage.
    """
    meta = getattr(resp, "usage_metadata", None)
    if isinstance(meta, dict):
        return (
            int(meta.get("input_tokens", 0) or 0),
            int(meta.get("output_tokens", 0) or 0),
        )
    rmeta = getattr(resp, "response_metadata", None) or {}
    usage = rmeta.get("usage") or rmeta.get("token_usage") or {}
    if isinstance(usage, dict):
        return (
            int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0),
            int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0),
        )
    return (0, 0)


def _extract_text(data: dict) -> str:
    blocks = data.get("content", [])
    parts = [
        b.get("text", "")
        for b in blocks
        if isinstance(b, dict) and b.get("type") == "text"
    ]
    return "\n".join(parts).strip()


def _parse_decision(text: str) -> BrainDecision:
    # tolerate code fences / surrounding prose
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in LLM output")
    obj = json.loads(text[start : end + 1])
    return BrainDecision(
        action=str(obj.get("action", "proceed")),
        reasoning=str(obj.get("reasoning", ""))[:280],
        params=obj.get("params", {}) if isinstance(obj.get("params"), dict) else {},
        confidence=float(obj.get("confidence", 0.6))
        if _is_num(obj.get("confidence"))
        else 0.6,
    )


def _is_num(v) -> bool:
    return isinstance(v, (int, float))

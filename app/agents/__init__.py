"""Framework-first agent layer.

Every agent carries an LLM *brain* (Anthropic Messages API) that drives its
inspect→hypothesize→plan→act→observe→verify→revise reasoning loop. When no API key
is configured the brain transparently falls back to a deterministic policy so the
whole platform still runs and is testable offline. The deterministic security/scope
layer always sits BENEATH the brain — an agent's reasoning can never widen scope,
bypass policy, or reach secrets it was not handed.
"""

from app.agents.base import Agent, AgentContext, AgentResult
from app.agents.brain import Brain, BrainDecision, BrainTask, get_brain

__all__ = [
    "Brain",
    "BrainDecision",
    "BrainTask",
    "get_brain",
    "Agent",
    "AgentContext",
    "AgentResult",
]

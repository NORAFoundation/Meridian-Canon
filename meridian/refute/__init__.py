"""Refutation harness (Phase D).

Five challenge modules per paper §6.6.1, plus a harness that orchestrates
them into a Refutation block. The Tri-Model Consensus mechanism (paper
§6.6, fig. 4) aggregates three architecturally-distinct adversary models'
verdicts via majority rule, with the all-disagree case producing a
'contested' outcome and a detailed-disagreement gap.

Public surface:
    LMAdapter            — protocol for language-model backends
    EchoAdapter          — deterministic test backend
    OllamaAdapter        — local Ollama (qwen, llama, mistral, gemma)
    OpenAIAdapter        — frontier API (custodian-authorized only)
    run_harness(att, *, models, ...) -> Refutation block dict
"""

from .lm import EchoAdapter, LMAdapter, OllamaAdapter, OpenAIAdapter
from .harness import run_harness

__all__ = [
    "EchoAdapter",
    "LMAdapter",
    "OllamaAdapter",
    "OpenAIAdapter",
    "run_harness",
]

"""Pluggable LLM layer.

The pipeline runs fully offline and deterministically with `DeterministicLLM`
(the default). Swap in `ClaudeLLM` to have `claude-sonnet-5` write the advisory
summaries, correlation narrative, and executive summary. The rest of the system
does not change: rules and scanners produce the findings, the LLM only explains,
correlates, and drafts prose.
"""

from .base import LLMClient
from .deterministic import DeterministicLLM
from .factory import get_llm

__all__ = ["LLMClient", "DeterministicLLM", "get_llm"]

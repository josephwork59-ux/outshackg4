"""Common base class for agents."""

from __future__ import annotations

import os
import traceback
from typing import Any

from contracts import AgentResult, ScanTarget

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


class Agent:
    #: Short stable identifier used as the key in ScanReport.agent_status.
    name: str = "agent"

    #: One-line description of the agent's single responsibility.
    role: str = ""

    #: The system prompt an LLM-backed implementation of this agent would use.
    system_prompt: str = ""

    def run(self, target: ScanTarget, context: dict[str, Any] | None = None) -> AgentResult:
        """Execute the agent, never raising. Subclasses override `_run`."""
        context = context or {}
        try:
            return self._run(target, context)
        except Exception as exc:  # noqa: BLE001 - fail safe: report, don't crash the pipeline
            return AgentResult(
                agent=self.name,
                findings=[],
                status="failed",
                notes=[f"{type(exc).__name__}: {exc}", traceback.format_exc(limit=3)],
            )

    def _run(self, target: ScanTarget, context: dict[str, Any]) -> AgentResult:  # pragma: no cover
        raise NotImplementedError

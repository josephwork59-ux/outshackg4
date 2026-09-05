"""The five specialized agents plus a common base class.

Each agent owns exactly one job, consumes a `ScanTarget` (plus context from the
orchestrator), and returns an `AgentResult` carrying a list of `Finding`s and a
status of ok | partial | failed. An agent never raises out to the orchestrator;
it catches its own errors and reports `failed` so the run can still finish.
"""

from .base import Agent
from .log_monitor import LogMonitorAgent
from .threat_intel import ThreatIntelAgent
from .vuln_scanner import VulnerabilityScannerAgent
from .incident_response import IncidentResponseAgent
from .policy_checker import PolicyCheckerAgent

__all__ = [
    "Agent",
    "LogMonitorAgent",
    "ThreatIntelAgent",
    "VulnerabilityScannerAgent",
    "IncidentResponseAgent",
    "PolicyCheckerAgent",
]

"""Orchestrator / Supervisor Agent, built as a LangGraph StateGraph.

Flow (per spec §7):
  1. validate scope/allowlist
  2. run Log Monitor + Vulnerability Scanner in parallel
  3. feed IOCs/CVEs to Threat Intelligence; wait for enrichment
  4. dedupe, correlate, finalize severity (supervisor.py)
  5. Incident Response for findings at high+ or confidence >= 0.7
  6. Policy Checker over the full findings set
  7. Report Builder emits ScanReport (JSON + Markdown + console)
  8. requires_human_approval actions are queued, never executed (enforced by
     every agent — nothing in this graph ever calls a mutating action)

Never executes remediation; only proposes. If any node raises, its agent is
marked "failed" in agent_status and the graph still produces a partial
report (fail-safe guardrail).
"""
from __future__ import annotations

import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from agents.incident_response import IncidentResponseAgent
from agents.log_monitor import LogMonitorAgent
from agents.policy_checker import PolicyCheckerAgent
from agents.threat_intel import ThreatIntelAgent
from agents.vuln_scanner import VulnScannerAgent
from contracts import Finding, IncidentPlan, ScanReport, ScanTarget
from tools.audit import RunAuditLog
from tools.llm_client import get_llm_client
from tools.store import get_store

from . import report_builder, supervisor


def _merge_status(a: dict[str, str] | None, b: dict[str, str] | None) -> dict[str, str]:
    """Reducer for `agent_status`: log_monitor and vuln_scanner run as
    parallel branches in the same LangGraph superstep and each write this
    key, so a plain overwrite would raise an InvalidUpdateError — merge the
    two partial dicts instead."""
    merged = dict(a or {})
    merged.update(b or {})
    return merged


class GraphState(TypedDict, total=False):
    run_id: str
    scan_target: ScanTarget
    log_findings: list[Finding]
    vuln_findings: list[Finding]
    merged_findings: list[Finding]
    incident_plans: list[IncidentPlan]
    compliance: object
    agent_status: Annotated[dict[str, str], _merge_status]
    scope_error: Optional[str]


class Orchestrator:
    def __init__(self):
        self.llm = get_llm_client()
        self.store = get_store()

    # ---- scope validation -------------------------------------------------
    @staticmethod
    def _validate_scope(target: ScanTarget) -> Optional[str]:
        if target.allow_active and target.api_base_url:
            from urllib.parse import urlparse
            host = urlparse(target.api_base_url).netloc
            if host not in target.target_allowlist and target.api_base_url not in target.target_allowlist:
                return (f"Active scanning requested for {target.api_base_url} but it is not in "
                        f"target_allowlist={target.target_allowlist}. Refusing active scan.")
        return None

    def _build_graph(self, audit: RunAuditLog):
        log_agent = LogMonitorAgent(llm=self.llm, audit=audit)
        vuln_agent = VulnScannerAgent(llm=self.llm, audit=audit)
        ti_agent = ThreatIntelAgent(llm=self.llm, audit=audit)
        ir_agent = IncidentResponseAgent(llm=self.llm, audit=audit)
        pc_agent = PolicyCheckerAgent(llm=self.llm, audit=audit)

        def node_validate(state: GraphState) -> GraphState:
            err = self._validate_scope(state["scan_target"])
            status = dict(state.get("agent_status", {}))
            if err:
                audit.log_event("scope_validation_failed", error=err)
                status["orchestrator"] = "partial"
                return {"scope_error": err, "agent_status": status}
            status["orchestrator"] = "ok"
            return {"agent_status": status}

        def node_log_monitor(state: GraphState) -> GraphState:
            status = dict(state.get("agent_status", {}))
            try:
                findings = log_agent.run(state["scan_target"].log_sources)
                status["log_monitor"] = "ok" if state["scan_target"].log_sources else "skipped"
            except Exception:
                audit.log_event("agent_error", agent="log_monitor", trace=traceback.format_exc())
                findings, status["log_monitor"] = [], "failed"
            return {"log_findings": findings, "agent_status": status}

        def node_vuln_scanner(state: GraphState) -> GraphState:
            status = dict(state.get("agent_status", {}))
            try:
                findings = vuln_agent.run(state["scan_target"])
                status["vuln_scanner"] = "ok"
            except Exception:
                audit.log_event("agent_error", agent="vuln_scanner", trace=traceback.format_exc())
                findings, status["vuln_scanner"] = [], "failed"
            return {"vuln_findings": findings, "agent_status": status}

        def node_threat_intel(state: GraphState) -> GraphState:
            status = dict(state.get("agent_status", {}))
            all_findings = list(state.get("log_findings", [])) + list(state.get("vuln_findings", []))
            try:
                ti_agent.enrich(all_findings)
                status["threat_intel"] = "ok"
            except Exception:
                audit.log_event("agent_error", agent="threat_intel", trace=traceback.format_exc())
                status["threat_intel"] = "failed"
            return {"log_findings": state.get("log_findings", []),
                    "vuln_findings": state.get("vuln_findings", []),
                    "agent_status": status}

        def node_supervisor_merge(state: GraphState) -> GraphState:
            merged = supervisor.merge_and_prioritize(
                state.get("log_findings", []), state.get("vuln_findings", [])
            )
            audit.log_event("merged_findings", n=len(merged))
            return {"merged_findings": merged}

        def node_incident_response(state: GraphState) -> GraphState:
            status = dict(state.get("agent_status", {}))
            try:
                plans = ir_agent.run(state["merged_findings"], min_severity="high", min_confidence=0.7)
                status["incident_response"] = "ok" if plans else "skipped"
            except Exception:
                audit.log_event("agent_error", agent="incident_response", trace=traceback.format_exc())
                plans, status["incident_response"] = [], "failed"
            return {"incident_plans": plans, "agent_status": status}

        def node_policy_checker(state: GraphState) -> GraphState:
            status = dict(state.get("agent_status", {}))
            try:
                compliance = pc_agent.run(
                    state["merged_findings"], state.get("incident_plans", []),
                    framework=state["scan_target"].compliance_framework,
                )
                status["policy_checker"] = "ok"
            except Exception:
                audit.log_event("agent_error", agent="policy_checker", trace=traceback.format_exc())
                compliance, status["policy_checker"] = None, "failed"
            return {"compliance": compliance, "agent_status": status}

        graph = StateGraph(GraphState)
        graph.add_node("validate", node_validate)
        graph.add_node("log_monitor", node_log_monitor)
        graph.add_node("vuln_scanner", node_vuln_scanner)
        graph.add_node("threat_intel", node_threat_intel)
        graph.add_node("supervisor_merge", node_supervisor_merge)
        graph.add_node("incident_response", node_incident_response)
        graph.add_node("policy_checker", node_policy_checker)

        graph.add_edge(START, "validate")
        # fan-out: log_monitor + vuln_scanner run as parallel branches
        graph.add_edge("validate", "log_monitor")
        graph.add_edge("validate", "vuln_scanner")
        # fan-in: threat_intel waits for both
        graph.add_edge("log_monitor", "threat_intel")
        graph.add_edge("vuln_scanner", "threat_intel")
        graph.add_edge("threat_intel", "supervisor_merge")
        graph.add_edge("supervisor_merge", "incident_response")
        graph.add_edge("incident_response", "policy_checker")
        graph.add_edge("policy_checker", END)

        return graph.compile()

    def run_scan(self, target: ScanTarget) -> ScanReport:
        run_id = uuid.uuid4().hex[:12]
        audit = RunAuditLog(run_id)
        audit.log_input(target.model_dump())
        started_at = datetime.now(timezone.utc)

        app = self._build_graph(audit)
        final_state: GraphState = app.invoke({"run_id": run_id, "scan_target": target, "agent_status": {}})

        findings = final_state.get("merged_findings", [])
        plans = final_state.get("incident_plans", [])
        compliance = final_state.get("compliance")
        agent_status = final_state.get("agent_status", {})

        target_parts = []
        if target.log_sources:
            target_parts.append(f"{len(target.log_sources)} log source(s)")
        if target.repo_path:
            target_parts.append(f"repo:{target.repo_path}")
        if target.image_names:
            target_parts.append(f"{len(target.image_names)} image(s)")
        target_summary = ", ".join(target_parts) or "(empty target)"

        report = ScanReport(
            run_id=run_id, started_at=started_at, finished_at=datetime.now(timezone.utc),
            target_summary=target_summary, findings=findings, incident_plans=plans,
            compliance=compliance, agent_status=agent_status,
        )
        report.executive_summary = report_builder.build_executive_summary(report, llm=self.llm)

        self.store.save_report(report)
        audit.log_event("run_complete", n_findings=len(findings), n_plans=len(plans))
        return report

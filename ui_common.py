"""Shared display helpers for the Streamlit security-agent workspaces."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import streamlit as st

ROOT = Path(__file__).resolve().parent
REPORT_PATH = ROOT / "reports" / "sample_scan_report.json"

AGENTS = [
    {"key": "vuln_scanner", "label": "Vulnerability Scanner", "icon": "🔎", "description": "Identifies vulnerable dependencies, exposed secrets, and insecure code patterns.", "page": "pages/1_Vulnerability_Scanner.py"},
    {"key": "log_monitor", "label": "Log Monitor", "icon": "📡", "description": "Detects suspicious activity, brute-force attempts, and application attack probes.", "page": "pages/2_Log_Monitor.py"},
    {"key": "threat_intel", "label": "Threat Intelligence", "icon": "🌐", "description": "Enriches indicators and vulnerabilities with known-threat context.", "page": "pages/3_Threat_Intelligence.py"},
    {"key": "policy_checker", "label": "Policy Checker", "icon": "🛡️", "description": "Maps security observations to NIST CSF controls and compliance gaps.", "page": "pages/4_Policy_Checker.py"},
    {"key": "incident_response", "label": "Incident Response", "icon": "🚨", "description": "Turns confirmed risks into actionable containment and recovery guidance.", "page": "pages/5_Incident_Response.py"},
]


def configure_page(title: str) -> None:
    st.set_page_config(page_title=title, page_icon="🛡️", layout="wide")
    st.markdown(
        """<style>
        .stApp { background: #f7f9fc; }
        [data-testid="stMetric"] { background: white; border: 1px solid #e5e7eb;
          border-radius: 10px; padding: 12px; }
        </style>""",
        unsafe_allow_html=True,
    )


@st.cache_data(show_spinner=False)
def load_report() -> dict[str, Any]:
    """Load the latest bundled demo report; return an empty report if unavailable."""
    if not REPORT_PATH.exists():
        return {"findings": []}
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def render_orchestration_summary(report: dict[str, Any]) -> None:
    findings = report.get("findings", [])
    severity = Counter(f.get("severity", "unknown").lower() for f in findings)
    participating = {f.get("agent") for f in findings}

    st.subheader("Orchestration summary")
    st.caption("The supervisor merges outputs, removes duplicates, correlates related evidence, and prioritizes findings by severity and confidence.")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Findings prioritized", len(findings))
    c2.metric("Critical findings", severity["critical"])
    c3.metric("Agents reporting", f"{len(participating)}/5")
    c4.metric("Correlated findings", sum(bool(f.get("correlated_ids")) for f in findings))

    if report.get("target_summary"):
        st.info(f"**Current demo scope:** {report['target_summary']}")


def render_agent_page(agent_key: str) -> None:
    agent = next(item for item in AGENTS if item["key"] == agent_key)
    report = load_report()
    findings = [f for f in report.get("findings", []) if f.get("agent") == agent_key]

    left, right = st.columns([5, 1])
    with left:
        st.title(f"{agent['icon']} {agent['label']}")
        st.caption(agent["description"])
    with right:
        if st.button("← Home", use_container_width=True):
            st.switch_page("streamlit_app.py")

    if not findings:
        st.info("No standalone findings were produced by this agent in the bundled demo run. Its analysis may still enrich or guide findings reported by other agents.")
        st.markdown("#### Agent role")
        st.write(agent["description"])
        return

    severity = Counter(f.get("severity", "unknown").lower() for f in findings)
    c1, c2, c3 = st.columns(3)
    c1.metric("Findings", len(findings))
    c2.metric("Critical", severity["critical"])
    c3.metric("Human review required", sum(f.get("requires_human_approval", False) for f in findings))

    st.subheader("Findings")
    for finding in findings:
        label = f"{finding.get('severity', 'unknown').upper()} · {finding.get('title', 'Untitled finding')}"
        with st.expander(label):
            st.write(finding.get("description", "No description available."))
            a, b = st.columns(2)
            a.markdown(f"**Confidence:** {finding.get('confidence', '—')}")
            b.markdown(f"**Category:** {finding.get('category', '—')}")
            st.markdown(f"**Target:** `{finding.get('target', '—')}`")
            if finding.get("recommended_fix"):
                st.success(f"Recommended action: {finding['recommended_fix']}")
            if finding.get("evidence"):
                st.markdown("**Evidence**")
                for item in finding["evidence"]:
                    st.code(item, language=None)
            if finding.get("references"):
                st.markdown("**References:** " + " · ".join(finding["references"]))

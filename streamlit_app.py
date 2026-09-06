"""Streamlit dashboard for the Cybersecurity AI Agent System.

Run with: streamlit run streamlit_app.py
"""
from __future__ import annotations

import streamlit as st

from ui_common import AGENTS, configure_page, load_report, render_orchestration_summary


configure_page("CyberGuard | Command Center")
report = load_report()

st.title("CyberGuard Command Center")
st.caption("Multi-agent security findings, prioritized for analyst review.")

st.markdown(
    """
    CyberGuard coordinates five focused security agents to inspect application code,
    activity logs, threat intelligence, compliance controls, and incident response.
    Their observations are merged into one prioritized view so security teams can
    focus on the most urgent risks first.
    """
)

st.subheader("Agent workspaces")
st.write("Open an agent workspace to explore the findings and evidence it contributed.")

for row in range(0, len(AGENTS), 2):
    columns = st.columns(2)
    for column, agent in zip(columns, AGENTS[row : row + 2]):
        with column:
            st.markdown(f"#### {agent['icon']} {agent['label']}")
            st.caption(agent["description"])
            if st.button("View findings", key=agent["key"], use_container_width=True):
                st.switch_page(agent["page"])

st.divider()
render_orchestration_summary(report)

"""Threat intelligence findings and approval-gated alert handoff."""
from __future__ import annotations

import os

import httpx
import streamlit as st
from dotenv import load_dotenv

from ui_common import configure_page, load_report, render_agent_page

configure_page("CyberGuard | Threat Intelligence")
load_dotenv()
render_agent_page("threat_intel")

st.divider()
st.subheader("Approve threat alert")
st.caption(
    "Approval sends the alert payload to the configured webhook. The webhook can then "
    "deliver the email through your preferred provider."
)

recipient = st.text_input(
    "Alert recipient",
    value="ar.selvakumar03@gmail.com",
    help="This address is included in the webhook payload after approval.",
)

if st.button("Approve & send alert", type="primary", use_container_width=True):
    webhook_url = os.getenv("THREAT_INTEL_WEBHOOK_URL")
    if not webhook_url:
        st.warning(
            "Alert approved, but no alert was sent because `THREAT_INTEL_WEBHOOK_URL` "
            "has not been configured yet. Add it to `.env` when your webhook is ready."
        )
    else:
        report = load_report()
        critical_findings = [
            finding
            for finding in report.get("findings", [])
            if finding.get("severity", "").lower() == "critical"
        ]
        payload = {
            "event": "threat_intelligence_alert_approved",
            "recipient": recipient,
            "summary": {
                "total_findings": len(report.get("findings", [])),
                "critical_findings": len(critical_findings),
                "target": report.get("target_summary", "CyberGuard scan"),
            },
            "critical_findings": critical_findings,
        }
        try:
            response = httpx.post(webhook_url, json=payload, timeout=10.0)
            response.raise_for_status()
            st.success(f"Threat alert approved and delivered to the webhook for {recipient}.")
        except httpx.HTTPError as error:
            st.error(f"The webhook did not accept the alert: {error}")

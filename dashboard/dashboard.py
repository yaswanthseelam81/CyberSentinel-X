import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from app.pipeline import run_pipeline
from app.incident_enricher import enrich_incident
from app.collectors.log_reader import read_log_file
from app.normalizer.log_parser import parse_log_line
from app.detection.rule_manager import load_all_rules
from app.detection.rule_engine import evaluate_rule
from app.evaluation.scenario_runner import run_all_scenarios
from app.investigation.actions import add_action
from app.storage.incident_store import (
    save_incident,
    save_action,
    get_actions,
    get_incident,
    get_all_incidents,
)
from app.storage.database import initialize_database



# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------

st.set_page_config(
    page_title="CyberSentinel X",
    page_icon="🛡️",
    layout="wide",
)

initialize_database()


# --------------------------------------------------
# STYLE
# --------------------------------------------------

st.markdown(
    """
    <style>
    .main {
        padding-top: 1rem;
    }

    .title {
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 0;
    }

    .subtitle {
        color: #8b949e;
        margin-bottom: 20px;
    }

    .card {
        padding: 20px;
        border-radius: 14px;
        border: 1px solid rgba(128,128,128,0.25);
        background: rgba(128,128,128,0.05);
        margin-bottom: 15px;
    }

    .danger {
        border-left: 6px solid #ff4b4b;
    }

    .metric-title {
        font-size: 14px;
        color: #8b949e;
    }

    .metric-value {
        font-size: 30px;
        font-weight: 800;
    }

    .timeline-item {
        padding: 10px 15px;
        border-left: 3px solid #ff4b4b;
        margin-bottom: 8px;
        background: rgba(128,128,128,0.05);
        border-radius: 6px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.markdown(
    '<div class="title">🛡️ CyberSentinel X</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">'
    "Explainable Security Operations & Threat Detection Platform"
    "</div>",
    unsafe_allow_html=True,
)

st.success("● SYSTEM ONLINE")


# --------------------------------------------------
# RUN MAIN PIPELINE
# --------------------------------------------------

result = run_pipeline()

if not result.incidents:
    st.warning("No security incidents detected.")
    st.stop()


# --------------------------------------------------
# LOAD ALL EVENTS + ALERTS
# --------------------------------------------------

scenario_files = [
    "data/simulated_attack.log",
    "data/privilege_escalation.log",
    "data/suspicious_process.log",
    "data/suspicious_dns.log",
    "data/unusual_network.log",
]

all_events = []
all_alerts = []

rules = load_all_rules("rules")

for log_file in scenario_files:

    logs = read_log_file(log_file)

    scenario_events = [
        parse_log_line(log)
        for log in logs
    ]

    all_events.extend(scenario_events)

    for rule in rules:

        all_alerts.extend(
            evaluate_rule(
                scenario_events,
                rule,
            )
        )


# --------------------------------------------------
# INCIDENT SELECTOR
# --------------------------------------------------

incident_options = {
    incident["incident_id"]: incident
    for incident in result.incidents
}

selected_incident_id = st.selectbox(
    "Select Incident",
    list(incident_options.keys()),
)

incident = incident_options[selected_incident_id]
saved_incident = get_incident(
    incident["incident_id"]
)

if saved_incident:
    incident["status"] = saved_incident["status"]

# --------------------------------------------------
# EVENTS + ALERTS FOR SELECTED INCIDENT
# --------------------------------------------------

incident_source_ip = incident["source_ip"]

incident_events = [
    event
    for event in all_events
    if event.source_ip == incident_source_ip
]

incident_alerts = [
    alert
    for alert in all_alerts
    if alert.get("source_ip") == incident_source_ip
]


# --------------------------------------------------
# ENRICH INCIDENT
# --------------------------------------------------

enriched = enrich_incident(
    incident_events,
    incident_alerts,
    incident,
)
save_incident(
    {
        **incident,
        "status": incident.get("status", "OPEN"),
        "risk_score": enriched["risk_score"],
        "risk_level": enriched["risk_level"],
        "confidence": enriched["confidence"],
    }
)

# --------------------------------------------------
# SECURITY OVERVIEW
# --------------------------------------------------

st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.markdown(
        f"""
        <div class="card danger">
            <div class="metric-title">CRITICAL INCIDENTS</div>
            <div class="metric-value">
                {result.incident_count}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with col2:

    st.markdown(
        f"""
        <div class="card">
            <div class="metric-title">ALERTS</div>
            <div class="metric-value">
                {result.alert_count}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with col3:

    st.markdown(
        f"""
        <div class="card">
            <div class="metric-title">EVENTS ANALYZED</div>
            <div class="metric-value">
                {result.event_count}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with col4:

    st.markdown(
        f"""
        <div class="card danger">
            <div class="metric-title">SELECTED RISK</div>
            <div class="metric-value">
                {enriched['risk_score']}/100
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


st.divider()


# --------------------------------------------------
# INCIDENT SUMMARY
# --------------------------------------------------

st.subheader("🚨 Selected Security Incident")

left, right = st.columns([1.5, 1])


with left:

    st.markdown("### Incident Details")

    st.write(
        f"**Incident ID:** {enriched['incident_id']}"
    )

    st.write(
        f"**Source IP:** {enriched['source_ip']}"
    )

    st.write(
        f"**Username:** "
        f"{incident_events[0].username if incident_events else 'UNKNOWN'}"
    )

    st.write(
        f"**Host:** "
        f"{incident_events[0].host if incident_events else 'UNKNOWN'}"
    )

    st.write(
        f"**Severity:** {enriched['severity']}"
    )

    st.write(
        f"**Status:** {enriched['status']}"
    )

    st.write(
        f"**Confidence:** "
        f"{enriched['confidence'] * 100:.0f}%"
    )


with right:

    st.markdown("### Risk Assessment")

    st.progress(
        enriched["risk_score"] / 100
    )

    st.write(
        f"**{enriched['risk_score']}/100 — "
        f"{enriched['risk_level']}**"
    )


# --------------------------------------------------
# MITRE ATT&CK
# --------------------------------------------------

st.subheader("🎯 MITRE ATT&CK")

if enriched["mitre"]:

    mitre = enriched["mitre"]

    st.markdown(
        f"""
        <div class="card">
            <h3>
                {mitre['technique_id']} —
                {mitre['technique_name']}
            </h3>

            <b>Tactic:</b> {mitre['tactic']}
        </div>
        """,
        unsafe_allow_html=True,
    )

else:

    st.info("No MITRE ATT&CK technique mapped.")


# --------------------------------------------------
# INVESTIGATION ACTIONS
# --------------------------------------------------

st.subheader("🛠️ Investigation Actions")

# --------------------------------------------------
# INVESTIGATION CASE STATE
# --------------------------------------------------

if (
    "case_state" not in st.session_state
    or st.session_state.case_state.get("case_id")
    != incident["incident_id"]
):

    saved_actions = get_actions(
        incident["incident_id"]
    )

    st.session_state.case_state = {
        "case_id": incident["incident_id"],
        "status": incident["status"],
        "actions": saved_actions,
    }
# Reset session state when the user selects another incident
if (
    st.session_state.case_state.get("case_id")
    != incident["incident_id"]
):

    st.session_state.case_state = {
        "case_id": incident["incident_id"],
        "status": incident["status"],
        "actions": [],
    }


action = st.selectbox(
    "Update Incident Status",
    [
        "Investigating",
        "Contained",
        "Resolved",
    ],
)

note = st.text_input(
    "Analyst Note",
    placeholder="Describe the action taken...",
)

if st.button("Apply Investigation Action"):

    if not note.strip():

        st.warning(
            "Enter an analyst note first."
        )

    else:

        # Update session state
        st.session_state.case_state = add_action(
            st.session_state.case_state,
            action,
            note,
        )

        # Prepare database record
        incident_to_save = {
            **incident,
            "status": action,
            "risk_score": enriched["risk_score"],
            "risk_level": enriched["risk_level"],
            "confidence": enriched["confidence"],
        }

        # Save incident
        save_incident(
            incident_to_save
        )

        # Save analyst action
        save_action(
            incident["incident_id"],
            action,
            note,
        )

        st.success(
            f"Incident updated to {action} "
            "and saved to database."
        )


# --------------------------------------------------
# ACTION HISTORY
# --------------------------------------------------

if st.session_state.case_state.get("actions"):

    st.markdown("#### Action History")

    for item in st.session_state.case_state["actions"]:

        st.write(
            f"**{item['action']}** — "
            f"{item['note']}"
        )


# --------------------------------------------------
# ATTACK CHAIN
# --------------------------------------------------

st.subheader("⛓️ Attack Chain")

chain = enriched["attack_chain"]

if chain["detected"]:

    chain_col1, chain_col2 = st.columns(2)

    with chain_col1:
        st.metric(
            "Chain Risk",
            f"{chain['total_risk']}/100",
        )

    with chain_col2:
        st.metric(
            "Chain Confidence",
            f"{chain['confidence'] * 100:.1f}%",
        )

    st.success(
        f"Attack chain detected — "
        f"{chain['stage_count']} stages"
    )

    for index, stage in enumerate(
        chain["stages"],
        start=1,
    ):

        st.markdown(
            f"""
            <div class="timeline-item">
                <b>Stage {index}: {stage['stage']}</b><br>
                <small>{stage['timestamp']}</small><br><br>

                <b>Event:</b>
                {stage['event_type']}<br>

                <b>MITRE:</b>
                {stage['mitre_technique']} —
                {stage['mitre_name']}<br>

                <b>Tactic:</b>
                {stage['tactic']}<br>

                <b>Risk Contribution:</b>
                +{stage['risk']}<br>

                <b>Confidence:</b>
                {stage['confidence'] * 100:.0f}%<br><br>

                <b>Explanation:</b>
                {stage['description']}
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.expander(
            f"🔎 Evidence — Stage {index}"
        ):
            st.json(stage["evidence"])

else:

    st.info(
        "No multi-stage attack chain detected."
    )
# --------------------------------------------------
# ATTACK TIMELINE
# --------------------------------------------------

st.subheader("🕐 Attack Timeline")

for item in enriched["timeline"]:

    st.markdown(
        f"""
        <div class="timeline-item">
            <b>{item['timestamp']}</b>
            &nbsp;&nbsp;
            <strong>{item['event_type']}</strong>
            &nbsp;&nbsp;
            {item['source_ip']}
        </div>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------
# DETECTION ALERTS
# --------------------------------------------------

st.subheader("🔔 Detection Alerts")

if incident_alerts:

    for alert in incident_alerts:

        st.markdown(
            f"""
            <div class="card">
                <b>{alert['rule_id']}</b><br>
                {alert['rule_name']}<br><br>

                Severity:
                <b>{alert['severity']}</b><br>

                Confidence:
                <b>{alert['confidence'] * 100:.0f}%</b><br>

                Source:
                <b>{alert['source_ip']}</b>
            </div>
            """,
            unsafe_allow_html=True,
        )

else:

    st.info(
        "No alerts associated with this incident."
    )


# --------------------------------------------------
# EVIDENCE
# --------------------------------------------------

with st.expander("🔎 View Evidence"):

    for evidence in enriched["evidence"]:

        st.json(evidence)


# --------------------------------------------------
# ANALYST NARRATIVE
# --------------------------------------------------

st.subheader("🤖 Analyst Narrative")

st.info(
    enriched["narrative"]
)


# --------------------------------------------------
# SECURITY PERFORMANCE
# --------------------------------------------------

attack_results = run_all_scenarios()

attack_detected = sum(
    1
    for scenario in attack_results
    if scenario["detected"]
)

attack_total = len(
    attack_results
)

detection_rate = (
    attack_detected / attack_total * 100
    if attack_total
    else 0
)


st.divider()

st.subheader("🧪 Security Performance")

m1, m2, m3 = st.columns(3)

m1.metric(
    "Detection Rate",
    f"{detection_rate:.1f}%",
)

m2.metric(
    "Scenarios Tested",
    attack_total,
)

m3.metric(
    "Scenarios Passed",
    attack_detected,
)

# --------------------------------------------------
# INCIDENT HISTORY
# --------------------------------------------------

st.divider()

st.subheader("📋 Incident History")

stored_incidents = get_all_incidents()

if stored_incidents:

    history_options = {
        incident["incident_id"]: incident
        for incident in stored_incidents
    }

    selected_history_id = st.selectbox(
        "Open Stored Incident",
        list(history_options.keys()),
    )

    selected_history = history_options[
        selected_history_id
    ]

    st.markdown("### Selected Stored Incident")

    c1, c2, c3, c4 = st.columns(4)

    c1.write("**Source IP**")
    c1.write(selected_history["source_ip"])

    c2.write("**Severity**")
    c2.write(selected_history["severity"])

    c3.write("**Risk**")
    c3.write(
        f"{selected_history['risk_score']}/100 "
        f"({selected_history['risk_level']})"
    )

    c4.write("**Status**")
    c4.write(selected_history["status"])

    st.caption(
        f"Created: {selected_history['created_at']}"
    )

else:
    st.info("No stored incidents yet.")
# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "CyberSentinel X • Detection → Correlation → "
    "Risk → Investigation"
)
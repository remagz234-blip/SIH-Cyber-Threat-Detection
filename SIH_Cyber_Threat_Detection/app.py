import streamlit as st
from streamlit_autorefresh import st_autorefresh
import pandas as pd
import numpy as np
import plotly.express as px
import subprocess
import sys
import time

from streamlit_autorefresh import st_autorefresh

from sklearn.ensemble import IsolationForest
from datetime import datetime
import random
import os

# -----------------------------------------
# PAGE CONFIGURATION
# -----------------------------------------

st.set_page_config(
    page_title="AI Cyber Threat Detection",
    page_icon="🛡️",
    layout="wide"
)
st_autorefresh(
    interval=3000,
    key="live_traffic_refresh"
)

# -----------------------------------------
# CUSTOM DESIGN
# -----------------------------------------

st.markdown("""
<style>

.main {
    background-color: #0e1117;
}

h1 {
    color: #00d4ff;
}

h2, h3 {
    color: #ffffff;
}

div[data-testid="stMetric"] {
    background-color: #1b2330;
    padding: 15px;
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)

# -----------------------------------------
# HEADER
# -----------------------------------------

st.title("🛡️ AI-Based Cyber Threat Detection")

st.markdown(
    "### Unidirectional IP Traffic Monitoring & Anomaly Detection"
)

st.caption(
    "SIH Prototype | Machine Learning Powered Network Security"
)

st.divider()

# -----------------------------------------
# GENERATE NETWORK TRAFFIC
# -----------------------------------------


# Refresh dashboard every 5 seconds
# -----------------------------------------
# LIVE NETWORK MONITORING
# -----------------------------------------

# Refresh dashboard every 5 seconds
st_autorefresh(
    interval=3000,
    key="network_refresh"
)

st.sidebar.header("⚙️ Control Panel")
st.sidebar.divider()
st.sidebar.subheader("📡 Live Capture Control")

if "capture_process" not in st.session_state:
    st.session_state.capture_process = None

if st.session_state.capture_process is None:

    if st.sidebar.button("▶ Start Monitoring", use_container_width=True):

        st.session_state.capture_process = subprocess.Popen(
            [
                sys.executable,
                "SIH_Cyber_Threat_Detection/traffic_capture.py"
            ]
        )

        st.sidebar.success("Live packet capture started")
        st.rerun()

else:

    st.sidebar.success("Monitoring is currently running")

    if st.sidebar.button("⏹ Stop Monitoring", use_container_width=True):

        st.session_state.capture_process.terminate()
        st.session_state.capture_process = None

        st.sidebar.info("Live packet capture stopped")
        st.rerun()

st.sidebar.subheader("📡 Network Monitoring")

live_file = "SIH_Cyber_Threat_Detection/network_traffic.csv"

if os.path.exists(live_file):

    all_traffic = pd.read_csv(live_file)

    # Simulate incoming traffic from the existing CSV
    if "demo_rows" not in st.session_state:
        st.session_state.demo_rows = 10

    st.session_state.demo_rows += 5

    if st.session_state.demo_rows > len(all_traffic):
        st.session_state.demo_rows = len(all_traffic)

    traffic_data = all_traffic.iloc[
        :st.session_state.demo_rows
    ].copy()

    st.sidebar.success(
        f"Demo traffic loaded: {len(traffic_data):,} packets"
    )

    # Convert captured packet data into model features
    traffic_data["Packet_Count"] = 1

    traffic_data["Bytes_Transferred"] = pd.to_numeric(
        traffic_data.get("Packet_Size", 0),
        errors="coerce"
    ).fillna(0)

    traffic_data["Duration"] = 1.0

    traffic_data["Destination_Port"] = pd.to_numeric(
        traffic_data.get(
            "Destination_Port",
            pd.Series([0] * len(traffic_data))
        ),
        errors="coerce"
    ).fillna(0)

    df = traffic_data.copy()

else:

    st.sidebar.error(
        "network_traffic.csv not found."
    )

    st.error(
        "No network traffic data found. "
        "Please start traffic_capture.py first."
    )

    st.stop()

# -----------------------------------------
# DATA PREPARATION
# -----------------------------------------



required_columns = [
    "Packet_Count",
    "Bytes_Transferred",
    "Duration",
    "Destination_Port"
]

for column in required_columns:

    if column not in df.columns:
        df[column] = 0

    df[column] = pd.to_numeric(
        df[column],
        errors="coerce"
    ).fillna(0)


# -----------------------------------------
# MACHINE LEARNING MODEL
# -----------------------------------------

features = [
    "Packet_Count",
    "Bytes_Transferred",
    "Duration",
    "Destination_Port"
]

X = df[features].replace(
    [np.inf, -np.inf],
    0
)

# Train an unsupervised anomaly detection model
# on the traffic records.

model = IsolationForest(
    n_estimators=150,
    contamination=0.12,
    random_state=42
)

model.fit(X)

df["AI_Prediction"] = model.predict(X)

df["Anomaly_Score"] = model.decision_function(X)

df["Threat_Status"] = np.where(
    df["AI_Prediction"] == -1,
    "Suspicious",
    "Normal"
)

df["Threat_Level"] = np.where(
    df["Threat_Status"] == "Normal",
    "Low",
    np.where(
        df["Anomaly_Score"] < -0.08,
        "High",
        "Medium"
    )
)

# -----------------------------------------
# DASHBOARD METRICS
# -----------------------------------------

total_traffic = len(df)

normal_traffic = len(
    df[df["Threat_Status"] == "Normal"]
)

suspicious_traffic = len(
    df[df["Threat_Status"] == "Suspicious"]
)

high_threats = len(
    df[df["Threat_Level"] == "High"]
)

st.subheader("📊 Network Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Traffic Records",
    f"{total_traffic:,}"
)

col2.metric(
    "Normal Traffic",
    f"{normal_traffic:,}"
)

col3.metric(
    "Suspicious Traffic",
    f"{suspicious_traffic:,}",
    delta=f"{suspicious_traffic / max(total_traffic, 1) * 100:.1f}% flagged"
)

col4.metric(
    "High Threat Alerts",
    f"{high_threats:,}"
)

st.divider()

# -----------------------------------------
# CHARTS
# -----------------------------------------

st.subheader("📈 Traffic Analytics")

chart_col1, chart_col2 = st.columns(2)

with chart_col1:

    status_counts = (
        df["Threat_Status"]
        .value_counts()
        .reset_index()
    )

    status_counts.columns = [
        "Status",
        "Count"
    ]

    fig1 = px.pie(
        status_counts,
        names="Status",
        values="Count",
        title="Normal vs Suspicious Traffic",
        hole=0.45
    )

    st.plotly_chart(
        fig1,
        use_container_width=True
    )

with chart_col2:

    protocol_counts = (
        df["Protocol"]
        .value_counts()
        .reset_index()
    )

    protocol_counts.columns = [
        "Protocol",
        "Count"
    ]

    fig2 = px.bar(
        protocol_counts,
        x="Protocol",
        y="Count",
        title="Protocol Distribution"
    )

    st.plotly_chart(
        fig2,
        use_container_width=True
    )

# -----------------------------------------
# TRAFFIC VOLUME CHART
# -----------------------------------------

st.subheader("📦 Traffic Volume Analysis")

fig3 = px.histogram(
    df,
    x="Bytes_Transferred",
    color="Threat_Status",
    nbins=30,
    title="Distribution of Transferred Bytes"
)

st.plotly_chart(
    fig3,
    use_container_width=True
)

# -----------------------------------------
# ALERTS TABLE
# -----------------------------------------

st.subheader("🚨 AI-Detected Threat Alerts")

alerts = df[
    df["Threat_Status"] == "Suspicious"
].sort_values(
    "Anomaly_Score"
)

if len(alerts) > 0:

    display_columns = [
        "Timestamp",
        "Source_IP",
        "Destination_IP",
        "Protocol",
        "Destination_Port",
        "Packet_Count",
        "Bytes_Transferred",
        "Threat_Level",
        "Anomaly_Score"
    ]

    st.dataframe(
        alerts[display_columns],
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No suspicious traffic detected in this sample."
    )

# -----------------------------------------
# MODEL INFORMATION
# -----------------------------------------

st.divider()

st.subheader("🤖 AI Model Information")

st.info(
    "Isolation Forest is an unsupervised machine learning "
    "algorithm used here to identify unusual traffic patterns "
    "based on packet count, transferred bytes, duration, "
    "and destination port."
)

st.caption(
    "Note: Suspicious classifications are anomaly indicators, "
"not proof of malicious activity. This prototype analyzes "
"captured network traffic using machine learning."
)

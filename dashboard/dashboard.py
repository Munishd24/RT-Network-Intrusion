"""
Streamlit Dashboard — Real-Time IDS Monitoring
-----------------------------------------------
Polls the Flask API every 2 seconds and renders:
  • Summary metric cards (Critical / Medium / Low / Unique IPs)
  • Live threat timeline chart
  • Severity distribution pie chart
  • Scrollable alert feed with color-coded severity

Run:
    streamlit run dashboard.py
"""

import streamlit as st
import requests
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os

_API_KEY = os.environ.get("IDS_API_KEY", "")

# ── Page Config ────────────────────────────────────────────────────
st.set_page_config(
    page_title="IDS Dashboard — Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS for a polished look ─────────────────────────────────
st.markdown("""
<style>
    /* Dark glassmorphism cards */
    [data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(30,30,60,0.85), rgba(20,20,40,0.95));
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 16px;
        padding: 20px 24px;
        backdrop-filter: blur(12px);
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    }
    [data-testid="stMetric"] label {
        color: #a0a0c0 !important;
        font-size: 0.85rem !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    [data-testid="stMetric"] [data-testid="stMetricValue"] {
        font-size: 2.4rem !important;
        font-weight: 700 !important;
    }
    
    /* Alert rows */
    .alert-critical {
        background: linear-gradient(90deg, rgba(255,50,50,0.15), transparent);
        border-left: 4px solid #ff3232;
        padding: 10px 16px;
        border-radius: 0 8px 8px 0;
        margin-bottom: 6px;
    }
    .alert-medium {
        background: linear-gradient(90deg, rgba(255,180,0,0.12), transparent);
        border-left: 4px solid #ffb400;
        padding: 10px 16px;
        border-radius: 0 8px 8px 0;
        margin-bottom: 6px;
    }
    .alert-low {
        background: linear-gradient(90deg, rgba(0,150,255,0.10), transparent);
        border-left: 4px solid #0096ff;
        padding: 10px 16px;
        border-radius: 0 8px 8px 0;
        margin-bottom: 6px;
    }
    
    /* Header styling */
    .main-header {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 24px 32px;
        border-radius: 16px;
        margin-bottom: 24px;
        border: 1px solid rgba(255,255,255,0.05);
    }
    .main-header h1 {
        margin: 0;
        font-size: 1.8rem;
        background: linear-gradient(90deg, #00d2ff, #3a7bd5);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .main-header p {
        color: #8888aa;
        margin: 4px 0 0 0;
        font-size: 0.9rem;
    }
    
    .stApp { background-color: #0a0a1a; }
    
    div[data-testid="stHorizontalBlock"] > div {
        padding: 0 6px;
    }
</style>
""", unsafe_allow_html=True)

# ── Header ─────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🛡️ Real-Time Intrusion Detection System</h1>
    <p>Live network threat monitoring • Port scans • ARP spoofing • Hardware alerts</p>
</div>
""", unsafe_allow_html=True)

FLASK_URL = os.environ.get("IDS_API_URL", "http://localhost:5000")

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "NONE": "⚪",
}

SEVERITY_CSS = {
    "CRITICAL": "alert-critical",
    "MEDIUM": "alert-medium",
    "LOW": "alert-low",
}

# ── Main Loop ──────────────────────────────────────────────────────
placeholder = st.empty()

while True:
    try:
        _headers = {"X-API-Key": _API_KEY} if _API_KEY else {}
        stats_res = requests.get(f"{FLASK_URL}/stats", timeout=3, headers=_headers)
        alerts_res = requests.get(f"{FLASK_URL}/alerts", timeout=3, headers=_headers)

        stats = stats_res.json()
        alerts = alerts_res.json()

        with placeholder.container():
            # ── Metric Cards ───────────────────────────────────────
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("🔴 Critical", stats.get("critical", 0))
            c2.metric("🟡 Medium", stats.get("medium", 0))
            c3.metric("🔵 Low", stats.get("low", 0))
            c4.metric("🌐 Unique Attackers", stats.get("unique_attackers", 0))

            st.markdown("---")

            # ── Charts Row ─────────────────────────────────────────
            chart_col, pie_col = st.columns([2, 1])

            with chart_col:
                st.subheader("📈 Threat Timeline")
                if alerts:
                    df = pd.DataFrame(alerts)
                    # Build a cumulative count per severity over time
                    df["index"] = range(len(df))
                    color_map = {
                        "CRITICAL": "#ff3232",
                        "MEDIUM": "#ffb400",
                        "LOW": "#0096ff",
                    }
                    fig = px.scatter(
                        df, x="time", y="severity",
                        color="severity",
                        color_discrete_map=color_map,
                        hover_data=["type", "src_ip"],
                        height=300,
                    )
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#aaa",
                        showlegend=False,
                        margin=dict(l=0, r=0, t=10, b=0),
                        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                        yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No threats detected yet — network is clear.")

            with pie_col:
                st.subheader("🎯 Severity Split")
                if stats.get("total", 0) > 0:
                    pie_data = {
                        "Severity": ["Critical", "Medium", "Low"],
                        "Count": [
                            stats.get("critical", 0),
                            stats.get("medium", 0),
                            stats.get("low", 0),
                        ],
                    }
                    fig2 = px.pie(
                        pie_data, names="Severity", values="Count",
                        color="Severity",
                        color_discrete_map={
                            "Critical": "#ff3232",
                            "Medium": "#ffb400",
                            "Low": "#0096ff",
                        },
                        hole=0.5,
                        height=300,
                    )
                    fig2.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        font_color="#aaa",
                        margin=dict(l=0, r=0, t=10, b=0),
                        showlegend=True,
                        legend=dict(
                            orientation="h",
                            yanchor="bottom", y=-0.2,
                            xanchor="center", x=0.5,
                        ),
                    )
                    st.plotly_chart(fig2, use_container_width=True)
                else:
                    st.info("Waiting for data…")

            st.markdown("---")

            # ── Live Alert Feed ────────────────────────────────────
            st.subheader("📋 Live Threat Feed")
            if alerts:
                for alert in reversed(alerts[-20:]):
                    sev = alert.get("severity", "LOW")
                    icon = SEVERITY_ICONS.get(sev, "⚪")
                    css_class = SEVERITY_CSS.get(sev, "alert-low")
                    extra = ""
                    if alert["type"] == "PORT_SCAN":
                        extra = f" • {alert.get('ports_per_5s', '?')} ports/5s"
                    elif alert["type"] == "ARP_SPOOF":
                        extra = f" • MAC: {alert.get('src_mac', '?')}"

                    st.markdown(
                        f'<div class="{css_class}">'
                        f'{icon} <code>{alert["time"]}</code> — '
                        f'<b>{alert["type"]}</b> from '
                        f'<code>{alert["src_ip"]}</code> '
                        f'— Severity: <b>{sev}</b>{extra}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.success("✅ No threats detected. Network is secure.")

    except requests.exceptions.ConnectionError:
        with placeholder.container():
            st.error(
                "⚠️ Cannot reach the backend at `localhost:5000`. "
                "Make sure `sniffer.py` is running."
            )
    except Exception as e:
        with placeholder.container():
            st.error(f"Dashboard error: {e}")

    time.sleep(2)
    st.rerun()

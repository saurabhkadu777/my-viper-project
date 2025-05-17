"""
VIPER CTI Dashboard - Main application file
"""
import streamlit as st
import pandas as pd
import sys
import os
from datetime import datetime

# Configure page settings
st.set_page_config(
    page_title="VIPER - CTI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Set up the main page
st.title("🛡️ VIPER - CVE Intelligence and Prioritization Engine")
st.subheader("Cyber Threat Intelligence Dashboard")

# Add main page content
st.markdown("""
Welcome to VIPER, your Cyber Threat Intelligence Dashboard for:
- Tracking and visualizing recent vulnerabilities
- Prioritizing patching based on AI analysis and risk scoring
- Monitoring Microsoft Patch Tuesday updates
- Tracking CISA Known Exploited Vulnerabilities (KEV)
- Identifying critical vulnerabilities through automated risk analysis
""")

# Display metrics from the latest data
st.subheader("Navigation")
st.markdown("""
Use the sidebar to navigate between the dashboard pages:
1. **📊 Dashboard** - Overview and metrics of vulnerabilities
2. **🔍 Detailed Analysis** - In-depth analysis of individual vulnerabilities
3. **📈 Analytics** - Trends and statistical analysis
4. **🔬 Microsoft Analysis** - Focus on Microsoft Patch Tuesday updates
""")

# Add a footer with application information
st.markdown("---")
st.markdown(f"*VIPER - CVE Intelligence and Prioritization Engine | Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*") 
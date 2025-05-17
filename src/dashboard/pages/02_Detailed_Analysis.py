"""
VIPER CTI Dashboard - Detailed Vulnerability Analysis Page
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import sys
import os
import re

# Add the project root directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.utils.database_handler import get_all_cves_with_details, get_filtered_cves

# Set the page title
st.title("🔍 Detailed Vulnerability Analysis")

# Sidebar for filtering
st.sidebar.header("Find Vulnerability")

# Search by CVE ID
cve_search = st.sidebar.text_input("Search by CVE ID", placeholder="e.g., CVE-2023-1234")

# Search by keyword
keyword_search = st.sidebar.text_input("Search by Keyword", placeholder="Search in description...")

# Priority filter
priority_filter = st.sidebar.multiselect(
    "Filter by Priority",
    options=["HIGH", "MEDIUM", "LOW"],
    default=[]
)

# KEV filter
kev_filter = st.sidebar.checkbox("Only show CISA KEV entries", value=False)

# Apply search/filters
search_button = st.sidebar.button("Search", type="primary")

# Load all CVEs with details
@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_cve_data():
    return get_all_cves_with_details()

# Get filtered data based on search criteria
def get_search_results(cve_id=None, keyword=None, priorities=None, is_in_kev=None):
    if cve_id and re.match(r'^CVE-\d{4}-\d+$', cve_id):
        # If specific CVE ID is provided, get just that one
        results = get_filtered_cves(keyword=cve_id)
    else:
        # Otherwise apply filters
        results = get_filtered_cves(
            keyword=keyword if keyword else None,
            priorities=priorities if priorities else None,
            is_in_kev=is_in_kev
        )
    return results

# Get the CVE data
if search_button or 'detailed_cve_data' not in st.session_state:
    with st.spinner("Loading vulnerability data..."):
        if search_button:
            # Apply filters when search button is clicked
            st.session_state.detailed_cve_data = get_search_results(
                cve_id=cve_search,
                keyword=keyword_search if keyword_search else None,
                priorities=priority_filter if priority_filter else None,
                is_in_kev=True if kev_filter else None
            )
        else:
            # Initial load - get all CVEs
            st.session_state.detailed_cve_data = load_cve_data()

# If no data, display a message
if not st.session_state.detailed_cve_data:
    st.info("No vulnerabilities found with the current search criteria. Try adjusting your search.")
    st.stop()

# Convert to DataFrame
df = pd.DataFrame(st.session_state.detailed_cve_data)

# Convert date strings to datetime with error handling
if 'published_date' in df.columns:
    # Use 'coerce' errors to handle various date formats
    df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce', format='mixed')
if 'kev_date_added' in df.columns:
    df['kev_date_added'] = pd.to_datetime(df['kev_date_added'], errors='coerce', format='mixed')

# Get a list of CVE IDs for selection
cve_list = df['cve_id'].tolist()

# Right-side selection box
selected_cve = st.selectbox(
    "Select a vulnerability for detailed analysis:",
    options=cve_list,
    index=0
)

# Get the selected CVE data
selected_data = df[df['cve_id'] == selected_cve].iloc[0].to_dict()

# Display the CVE details
st.markdown("---")

# Title and badges row
col1, col2 = st.columns([2, 3])

with col1:
    st.markdown(f"## {selected_cve}")
    
    # Generate badges
    priority_colors = {
        'HIGH': 'red',
        'MEDIUM': 'orange',
        'LOW': 'green'
    }
    priority = selected_data.get('gemini_priority', 'UNKNOWN')
    priority_color = priority_colors.get(priority, 'gray')
    
    # Format badges
    badges_html = f'''
    <div style="display: flex; gap: 10px; margin-bottom: 15px;">
        <span style="background-color: {priority_color}; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">
            {priority} Priority
        </span>
    '''
    
    if selected_data.get('is_in_kev'):
        badges_html += f'''
        <span style="background-color: #d9534f; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">
            CISA KEV
        </span>
        '''
    
    badges_html += "</div>"
    st.markdown(badges_html, unsafe_allow_html=True)
    
    # Basic metadata
    pub_date = selected_data.get('published_date')
    st.markdown(f"**Published Date:** {pub_date.strftime('%Y-%m-%d') if pd.notnull(pub_date) else 'Unknown'}")
    
    if selected_data.get('is_in_kev') and pd.notnull(selected_data.get('kev_date_added')):
        kev_date = selected_data.get('kev_date_added')
        st.markdown(f"**Added to KEV:** {kev_date.strftime('%Y-%m-%d') if pd.notnull(kev_date) else 'Unknown'}")

    # Add Microsoft information if available
    ms_severity = selected_data.get('microsoft_severity')
    if ms_severity:
        ms_product = selected_data.get('microsoft_product_family', 'Unknown')
        ms_specific = selected_data.get('microsoft_product_name', 'Unknown')
        patch_date = selected_data.get('patch_tuesday_date')
        
        # Format Microsoft information with styling based on severity
        severity_color = {
            'Critical': 'red',
            'Important': 'orange',
            'Moderate': 'blue',
            'Low': 'green'
        }.get(ms_severity, 'gray')
        
        st.markdown(f"""
        <div style="background-color: rgba(0,0,0,0.05); padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 4px solid {severity_color};">
            <span style="font-weight: bold; color: {severity_color};">Microsoft {ms_severity}</span><br>
            <b>Product Family:</b> {ms_product}<br>
            <b>Specific Product:</b> {ms_specific}<br>
            <b>Patch Tuesday:</b> {patch_date.strftime('%Y-%m-%d') if pd.notnull(patch_date) else 'Unknown'}
        </div>
        """, unsafe_allow_html=True)

with col2:
    st.markdown("### Description")
    st.markdown(selected_data.get('description', 'No description available'))

# Metrics row
st.markdown("---")
st.markdown("### Risk Metrics")

metric_cols = st.columns(5)

with metric_cols[0]:
    cvss = selected_data.get('cvss_v3_score')
    cvss_color = "normal"
    if cvss is not None and cvss >= 7.0:
        cvss_color = "off"
    st.metric(
        "CVSS Score", 
        f"{cvss:.1f}" if pd.notnull(cvss) else "N/A",
        delta_color=cvss_color
    )

with metric_cols[1]:
    epss = selected_data.get('epss_score')
    epss_color = "normal"
    if epss is not None and epss >= 0.5:
        epss_color = "off"
    st.metric(
        "EPSS Score", 
        f"{epss:.4f}" if pd.notnull(epss) else "N/A",
        delta_color=epss_color
    )

with metric_cols[2]:
    epss_percentile = selected_data.get('epss_percentile')
    st.metric(
        "EPSS Percentile", 
        f"{epss_percentile:.2f}" if pd.notnull(epss_percentile) else "N/A"
    )

with metric_cols[3]:
    risk_score = selected_data.get('risk_score')
    risk_color = "normal"
    if risk_score is not None and risk_score >= 0.7:
        risk_color = "off"
    st.metric(
        "Risk Score", 
        f"{risk_score:.2f}" if pd.notnull(risk_score) else "N/A",
        delta_color=risk_color
    )

with metric_cols[4]:
    ms_severity_value = selected_data.get('microsoft_severity')
    if pd.notnull(ms_severity_value):
        # Use color based on severity
        ms_delta_color = {
            'Critical': 'off',
            'Important': 'off',
            'Moderate': 'normal',
            'Low': 'normal'
        }.get(ms_severity_value, 'normal')
        
        st.metric(
            "MS Severity",
            ms_severity_value,
            delta_color=ms_delta_color
        )
    else:
        st.metric("MS Severity", "N/A")

# AI Analysis section
st.markdown("---")
st.markdown("### AI Analysis")

# Extract the priority explanation from the alerts
alerts = selected_data.get('alerts', [])
priority_reasoning = None

for alert in alerts:
    if "Priority assigned based on" in alert:
        priority_reasoning = alert
        break

if priority_reasoning:
    st.info(priority_reasoning)
else:
    st.info("The AI has assigned a priority level based on the vulnerability characteristics and context.")

# Alert cards for any additional alerts
if alerts:
    other_alerts = [a for a in alerts if a != priority_reasoning]
    if other_alerts:
        st.markdown("### Alerts and Concerns")
        for alert in other_alerts:
            st.warning(alert)

# Technical Details section
st.markdown("---")
st.markdown("### Technical Context")

# Historical trends for EPSS and CVE publication
context_cols = st.columns(2)

with context_cols[0]:
    # Show the EPSS history if we had it (would need additional data)
    st.markdown("#### Exploitation Probability")
    st.info("This vulnerability has an EPSS score that indicates the probability of exploitation within the next 30 days.")
    
    # Create a gauge chart for EPSS
    if pd.notnull(selected_data.get('epss_score')):
        epss_value = selected_data.get('epss_score')
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = epss_value,
            number = {"valueformat": ".4f"},
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "EPSS Score"},
            gauge = {
                'axis': {'range': [0, 1], 'tickwidth': 1},
                'bar': {'color': "darkred"},
                'steps': [
                    {'range': [0, 0.1], 'color': "lightgreen"},
                    {'range': [0.1, 0.3], 'color': "yellow"},
                    {'range': [0.3, 0.5], 'color': "orange"},
                    {'range': [0.5, 1], 'color': "red"},
                ],
                'threshold': {
                    'line': {'color': "black", 'width': 4},
                    'thickness': 0.75,
                    'value': epss_value
                }
            }
        ))
        fig.update_layout(height=250)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.write("EPSS data not available for this vulnerability.")

with context_cols[1]:
    st.markdown("#### Risk Factors")
    
    # Create a bullet chart for risk factors
    risk_factors = [
        {"name": "Base CVSS", "value": selected_data.get('cvss_v3_score', 0) if pd.notnull(selected_data.get('cvss_v3_score')) else 0},
        {"name": "EPSS Factor", "value": selected_data.get('epss_score', 0) * 10 if pd.notnull(selected_data.get('epss_score')) else 0},
        {"name": "KEV Factor", "value": 10 if selected_data.get('is_in_kev') else 0},
    ]
    
    # Create a horizontal bar chart
    risk_df = pd.DataFrame(risk_factors)
    fig = px.bar(
        risk_df, 
        x='value', 
        y='name',
        orientation='h',
        color='value',
        color_continuous_scale=['green', 'yellow', 'orange', 'red'],
        range_color=[0, 10],
        title="Risk Factor Breakdown"
    )
    fig.update_layout(height=250)
    st.plotly_chart(fig, use_container_width=True)

# Mitigation recommendations
st.markdown("---")
st.markdown("### Recommended Actions")

# Generate generic recommendations based on priority
priority = selected_data.get('gemini_priority')
if priority == 'HIGH':
    st.error("""
    ### Immediate Action Required
    
    - Apply patches or updates as soon as they become available
    - Implement temporary mitigations or workarounds if patches are not yet available
    - Monitor systems for signs of exploitation
    - Consider isolating vulnerable systems if mitigation is not possible
    """)
elif priority == 'MEDIUM':
    st.warning("""
    ### Action Recommended
    
    - Plan to apply patches during the next maintenance window
    - Review and implement available mitigations
    - Monitor for increases in exploitation activity
    - Include in regular vulnerability management processes
    """)
else:
    st.info("""
    ### Standard Remediation
    
    - Address according to normal vulnerability management procedures
    - Apply patches during regular maintenance cycles
    - Document in vulnerability tracking system
    """)

# If this is a KEV, add additional KEV-specific recommendation
if selected_data.get('is_in_kev'):
    st.error("""
    ### CISA KEV Directive
    
    This vulnerability is in CISA's Known Exploited Vulnerabilities (KEV) catalog, which means:
    
    - Federal agencies are required to remediate according to CISA timelines
    - Active exploitation has been observed in the wild
    - This vulnerability should be prioritized for remediation regardless of CVSS score
    """)

# If this has Microsoft patch information, add specific guidance
ms_severity = selected_data.get('microsoft_severity')
if ms_severity:
    if ms_severity == 'Critical':
        st.error("""
        ### Microsoft Critical Guidance
        
        Microsoft has rated this as a Critical vulnerability:
        
        - Deploy patches immediately, even outside regular patching cycles
        - Critical vulnerabilities often involve remote code execution or privilege escalation
        - Prioritize systems directly exposed to the internet
        - Consider emergency change approval if needed
        """)
    elif ms_severity == 'Important':
        st.warning("""
        ### Microsoft Important Guidance
        
        Microsoft has rated this as an Important vulnerability:
        
        - Apply patches according to your standard patching schedule (typically within 30 days)
        - Important vulnerabilities represent significant security risks but might require additional factors to exploit
        - Prioritize based on system exposure and criticality
        """)
    else:
        st.info(f"""
        ### Microsoft {ms_severity} Guidance
        
        Microsoft has rated this as a {ms_severity} vulnerability:
        
        - Apply patches during regular maintenance cycles
        - These vulnerabilities typically represent lower security risks
        - Prioritize based on system exposure and criticality
        """)

# Add a button to export the analysis as PDF (would require additional implementation)
st.download_button(
    label="Export Analysis Report (PDF)",
    data="This feature would generate a PDF report",
    file_name=f"{selected_cve}_analysis.pdf",
    mime="application/pdf",
    disabled=True  # Currently disabled as we'd need to implement PDF generation
)

# Add footer with timestamp
st.markdown("---")
st.markdown(f"*Analysis generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*") 
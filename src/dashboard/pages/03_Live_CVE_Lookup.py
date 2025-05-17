"""
VIPER CTI Dashboard - Live CVE Lookup Page
"""
import streamlit as st
import pandas as pd
import re
import asyncio
from datetime import datetime
import sys
import os

# Add the project root directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.utils.database_handler import (
    get_cve_details, 
    store_cves, 
    update_cve_epss_data, 
    update_cve_kev_status,
    update_cve_priority, 
    update_cve_risk_data
)
from src.clients.nvd_client import fetch_single_cve_details
from src.clients.epss_client import get_epss_score
from src.clients.cisa_kev_client import fetch_kev_catalog
from src.gemini_analyzer import analyze_cve_with_gemini_async
from src.risk_analyzer import analyze_cve_risk

# Set the page title
st.title("🔎 Live CVE Lookup")

# Sidebar with information about the tool
st.sidebar.header("About this Tool")
st.sidebar.markdown("""
This tool allows you to look up information about a specific CVE (Common Vulnerabilities and Exposures).

1. Enter a valid CVE ID in the format CVE-YYYY-NNNNN
2. The tool will first check the local database for information
3. You can fetch live data from external sources if needed
4. Analyze the vulnerability with Gemini AI
5. Save the results to your local database
""")

# Layout for the main function - CVE search
st.markdown("### Enter a CVE ID to lookup")
cve_input_col1, cve_input_col2 = st.columns([4, 1])

with cve_input_col1:
    cve_id = st.text_input("CVE ID", placeholder="e.g., CVE-2023-12345")

with cve_input_col2:
    lookup_button = st.button("Lookup", type="primary", use_container_width=True)

# Function to validate CVE ID format
def is_valid_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format (CVE-YYYY-NNNNN where NNNNN can be multiple digits)"""
    return bool(re.match(r'^CVE-\d{4}-\d+$', cve_id))

# Function to check for CVE in KEV catalog
def check_cve_in_kev(cve_id: str, kev_catalog: list) -> tuple:
    """Check if a CVE is in the KEV catalog and return status and date added if found"""
    for entry in kev_catalog:
        if entry.get('cve_id') == cve_id:
            return True, entry.get('date_added')
    return False, None

# Function to display CVE details
def display_cve_details(cve_data: dict, source: str = "Local Database"):
    """Display details for a CVE in a structured format"""
    st.markdown(f"## {cve_data.get('cve_id')}")
    
    # Display source and metadata
    st.markdown(f"**Source:** {source}")
    
    if source == "Local Database" and cve_data.get('processed_at'):
        st.markdown(f"**Last analyzed:** {cve_data.get('processed_at')}")
    
    # Display badges for priority, KEV status, etc.
    badges_html = '<div style="display: flex; gap: 10px; margin-bottom: 15px;">'
    
    # Priority badge
    priority = cve_data.get('gemini_priority')
    if priority:
        priority_colors = {
            'HIGH': 'red',
            'MEDIUM': 'orange',
            'LOW': 'green',
            'ERROR_ANALYZING': 'gray'
        }
        priority_color = priority_colors.get(priority, 'gray')
        badges_html += f'''
        <span style="background-color: {priority_color}; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">
            {priority} Priority
        </span>
        '''
    
    # KEV status badge
    if cve_data.get('is_in_kev'):
        badges_html += f'''
        <span style="background-color: #d9534f; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">
            CISA KEV
        </span>
        '''
        
    # Microsoft severity badge if available
    ms_severity = cve_data.get('microsoft_severity')
    if ms_severity:
        severity_color = {
            'Critical': 'red',
            'Important': 'orange',
            'Moderate': 'blue',
            'Low': 'green'
        }.get(ms_severity, 'gray')
        
        badges_html += f'''
        <span style="background-color: {severity_color}; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">
            MS {ms_severity}
        </span>
        '''
    
    badges_html += '</div>'
    st.markdown(badges_html, unsafe_allow_html=True)
    
    # Description and publication info
    st.markdown("### Description")
    st.markdown(cve_data.get('description', 'No description available.'))
    
    # Publication details
    pub_date = cve_data.get('published_date')
    if pub_date:
        try:
            if isinstance(pub_date, str):
                pub_date = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
            st.markdown(f"**Published Date:** {pub_date.strftime('%Y-%m-%d')}")
        except:
            st.markdown(f"**Published Date:** {pub_date}")
    
    # KEV details if available
    if cve_data.get('is_in_kev') and cve_data.get('kev_date_added'):
        kev_date = cve_data.get('kev_date_added')
        st.markdown(f"**Added to KEV:** {kev_date}")
    
    # Microsoft details if available
    if ms_severity:
        ms_product = cve_data.get('microsoft_product_family', 'Unknown')
        ms_specific = cve_data.get('microsoft_product_name', 'Unknown')
        patch_date = cve_data.get('patch_tuesday_date')
        
        st.markdown(f"""
        <div style="background-color: rgba(0,0,0,0.05); padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 4px solid {severity_color};">
            <span style="font-weight: bold; color: {severity_color};">Microsoft {ms_severity}</span><br>
            <b>Product Family:</b> {ms_product}<br>
            <b>Specific Product:</b> {ms_specific}<br>
            <b>Patch Tuesday:</b> {patch_date if patch_date else 'Unknown'}
        </div>
        """, unsafe_allow_html=True)
    
    # Metrics section
    st.markdown("### Risk Metrics")
    
    # Use columns for metrics
    metric_cols = st.columns(4)
    
    with metric_cols[0]:
        cvss = cve_data.get('cvss_v3_score')
        st.metric(
            "CVSS Score", 
            f"{cvss:.1f}" if cvss is not None else "N/A"
        )
    
    with metric_cols[1]:
        epss = cve_data.get('epss_score')
        st.metric(
            "EPSS Score", 
            f"{epss:.4f}" if epss is not None else "N/A"
        )
    
    with metric_cols[2]:
        epss_percentile = cve_data.get('epss_percentile')
        st.metric(
            "EPSS Percentile", 
            f"{epss_percentile:.2f}" if epss_percentile is not None else "N/A"
        )
    
    with metric_cols[3]:
        risk_score = cve_data.get('risk_score')
        st.metric(
            "Risk Score", 
            f"{risk_score:.2f}" if risk_score is not None else "N/A"
        )
    
    # Alerts section
    alerts = cve_data.get('alerts', [])
    if alerts:
        st.markdown("### Alerts")
        for alert in alerts:
            st.warning(alert)
    
    # References section if available
    references = cve_data.get('references', [])
    if references:
        st.markdown("### References")
        for ref in references:
            url = ref.get('url')
            source = ref.get('source')
            if url:
                st.markdown(f"- [{source if source else url}]({url})")
    
    # CPE entries if available
    cpe_entries = cve_data.get('cpe_entries', [])
    if cpe_entries:
        st.markdown("### Affected Products (CPE)")
        for cpe in cpe_entries[:10]:  # Limit to 10 to avoid cluttering the UI
            criteria = cpe.get('criteria', '')
            vulnerable = cpe.get('vulnerable', True)
            status = "Vulnerable" if vulnerable else "Not Vulnerable"
            status_color = "red" if vulnerable else "green"
            
            st.markdown(f'<span style="color: {status_color};">{status}</span>: `{criteria}`', unsafe_allow_html=True)
        
        if len(cpe_entries) > 10:
            st.markdown(f"*...and {len(cpe_entries) - 10} more CPE entries*")

# Main execution flow
if lookup_button and cve_id:
    # Validate CVE ID
    if not is_valid_cve_id(cve_id):
        st.error("Invalid CVE ID format. Please use the format CVE-YYYY-NNNNN (e.g., CVE-2023-12345).")
    else:
        # First check local database
        with st.spinner("Checking local database..."):
            local_cve_data = get_cve_details(cve_id)
        
        if local_cve_data:
            st.success("CVE found in local database!")
            display_cve_details(local_cve_data, "Local Database")
            
            # Offer option to fetch live data
            fetch_live = st.checkbox("Fetch live data and re-analyze", value=False)
            
            if fetch_live:
                perform_live_fetch = st.button("Fetch and Analyze", type="primary")
                
                if perform_live_fetch:
                    st.session_state.perform_live_fetch = True
        else:
            st.info(f"CVE {cve_id} not found in local database. Fetching live data...")
            st.session_state.perform_live_fetch = True
        
        # Perform live data fetch if required
        if st.session_state.get('perform_live_fetch', False):
            with st.spinner("Fetching live data from NVD..."):
                nvd_data = fetch_single_cve_details(cve_id)
                
                if not nvd_data:
                    st.error(f"CVE {cve_id} not found in the National Vulnerability Database.")
                    st.session_state.pop('perform_live_fetch', None)
                else:
                    st.success("Data successfully fetched from NVD!")
                    
                    # Prepare for complete analysis by getting EPSS score
                    with st.spinner("Fetching EPSS score..."):
                        epss_data = get_epss_score(cve_id)
                        if epss_data:
                            nvd_data['epss_score'] = epss_data.get('epss')
                            nvd_data['epss_percentile'] = epss_data.get('percentile')
                            st.success(f"EPSS score: {epss_data.get('epss'):.4f}")
                        else:
                            st.warning("EPSS score not available for this CVE.")
                    
                    # Check if CVE is in CISA KEV catalog
                    with st.spinner("Checking CISA KEV status..."):
                        kev_catalog = fetch_kev_catalog()
                        if kev_catalog:
                            is_in_kev, kev_date_added = check_cve_in_kev(cve_id, kev_catalog)
                            nvd_data['is_in_kev'] = is_in_kev
                            nvd_data['kev_date_added'] = kev_date_added
                            
                            if is_in_kev:
                                st.warning(f"This vulnerability is in the CISA Known Exploited Vulnerabilities catalog! Added on {kev_date_added}")
                            else:
                                st.info("This vulnerability is not in the CISA KEV catalog.")
                        else:
                            st.warning("Could not check CISA KEV status.")
                    
                    # Run Gemini analysis
                    with st.spinner("Analyzing with Gemini AI..."):
                        try:
                            priority, raw_response = asyncio.run(analyze_cve_with_gemini_async(nvd_data))
                            nvd_data['gemini_priority'] = priority
                            nvd_data['gemini_raw_response'] = raw_response
                            
                            priority_colors = {
                                'HIGH': 'red',
                                'MEDIUM': 'orange',
                                'LOW': 'green',
                                'ERROR_ANALYZING': 'gray'
                            }
                            priority_color = priority_colors.get(priority, 'gray')
                            
                            st.markdown(f'<div style="background-color: {priority_color}; color: white; padding: 10px; border-radius: 5px; text-align: center; font-weight: bold;">Gemini Priority: {priority}</div>', unsafe_allow_html=True)
                        except Exception as e:
                            st.error(f"Error analyzing with Gemini: {str(e)}")
                            nvd_data['gemini_priority'] = "ERROR_ANALYZING"
                    
                    # Calculate risk score
                    with st.spinner("Calculating risk score..."):
                        try:
                            risk_score, alerts = analyze_cve_risk(nvd_data)
                            nvd_data['risk_score'] = risk_score
                            nvd_data['alerts'] = alerts
                            
                            st.success(f"Risk score: {risk_score:.2f}")
                            
                            if alerts:
                                st.subheader("Alerts")
                                for alert in alerts:
                                    st.warning(alert)
                        except Exception as e:
                            st.error(f"Error calculating risk score: {str(e)}")
                    
                    # Display the complete analysis results
                    st.markdown("---")
                    st.subheader("Analysis Results")
                    display_cve_details(nvd_data, "Live Data")
                    
                    # Offer to save to database
                    save_to_db = st.button("Save to Database", type="primary")
                    
                    if save_to_db:
                        with st.spinner("Saving to database..."):
                            # First try to store the basic CVE data
                            store_result = store_cves([{
                                'cve_id': nvd_data.get('cve_id'),
                                'description': nvd_data.get('description'),
                                'cvss_v3_score': nvd_data.get('cvss_v3_score'),
                                'published_date': nvd_data.get('published_date')
                            }])
                            
                            # Update with priority from Gemini
                            if nvd_data.get('gemini_priority'):
                                update_cve_priority(
                                    nvd_data.get('cve_id'),
                                    nvd_data.get('gemini_priority'),
                                    nvd_data.get('gemini_raw_response')
                                )
                            
                            # Update with EPSS data if available
                            if nvd_data.get('epss_score') is not None and nvd_data.get('epss_percentile') is not None:
                                update_cve_epss_data(
                                    nvd_data.get('cve_id'),
                                    nvd_data.get('epss_score'),
                                    nvd_data.get('epss_percentile')
                                )
                            
                            # Update with KEV status if available
                            update_cve_kev_status(
                                nvd_data.get('cve_id'),
                                nvd_data.get('is_in_kev', False),
                                nvd_data.get('kev_date_added')
                            )
                            
                            # Update with risk score and alerts
                            if nvd_data.get('risk_score') is not None:
                                update_cve_risk_data(
                                    nvd_data.get('cve_id'),
                                    nvd_data.get('risk_score'),
                                    nvd_data.get('alerts', [])
                                )
                            
                            st.success(f"CVE {cve_id} has been saved to the database!")
                    
                    # Clear the fetch flag
                    st.session_state.pop('perform_live_fetch', None)
elif not cve_id and lookup_button:
    st.warning("Please enter a CVE ID.") 
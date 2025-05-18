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
import traceback  # Add for better error logging
import uuid  # For unique identifiers
import sqlite3  # Added for database connection check
import logging
import sys # sys.stderr için eklendi
from datetime import datetime # datetime için eklendi
page_logger = logging.getLogger(__name__) 


# Add the project root directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))



from src.utils.database_handler import (
    get_cve_details, 
    store_cves, 
    store_or_update_cve,
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

# Initialize session state for tracking operations
if 'save_attempted' not in st.session_state:
    st.session_state.save_attempted = False

if 'save_success' not in st.session_state:
    st.session_state.save_success = False

if 'saved_cve_data' not in st.session_state:
    st.session_state.saved_cve_data = None

if 'operation_id' not in st.session_state:
    st.session_state.operation_id = str(uuid.uuid4())

# Set the page title and add refresh button at the top right
title_col, refresh_col = st.columns([6, 1])
with title_col:
    st.title("🔎 Live CVE Lookup")
with refresh_col:
    st.markdown("<div style='margin-top: 15px;'></div>", unsafe_allow_html=True)  # Adding some vertical space
    if st.button("🔄 Refresh", type="primary", use_container_width=True):
        st.rerun()

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

# Create a form for CVE lookup
with st.form(key="cve_lookup_form"):
    cve_id = st.text_input("CVE ID", placeholder="e.g. CVE-2023-12345")
    lookup_button = st.form_submit_button("Look up CVE", type="primary")

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
    badges_html = '<div style="display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 15px;">'
    
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
        badges_html += f'<span style="background-color: {priority_color}; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">{priority} Priority</span>'
    
    # KEV status badge
    if cve_data.get('is_in_kev'):
        badges_html += '<span style="background-color: #d9534f; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">CISA KEV</span>'
        
    # Microsoft severity badge if available
    ms_severity = cve_data.get('microsoft_severity')
    if ms_severity:
        severity_color = {
            'Critical': 'red',
            'Important': 'orange',
            'Moderate': 'blue',
            'Low': 'green'
        }.get(ms_severity, 'gray')
        
        badges_html += f'<span style="background-color: {severity_color}; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">MS {ms_severity}</span>'
    
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
        
        ms_info_html = f"""
        <div style="background-color: rgba(0,0,0,0.05); padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 4px solid {severity_color};">
            <span style="font-weight: bold; color: {severity_color};">Microsoft {ms_severity}</span><br>
            <b>Product Family:</b> {ms_product}<br>
            <b>Specific Product:</b> {ms_specific}<br>
            <b>Patch Tuesday:</b> {patch_date if patch_date else 'Unknown'}
        </div>
        """
        st.markdown(ms_info_html, unsafe_allow_html=True)
    
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

# Add direct file logging for debugging
def log_debug(message):
    """Write debug message directly to a file for troubleshooting"""
    operation_id = st.session_state.get('operation_id', str(uuid.uuid4())[:8])
    
    # Set operation ID in session state if not present
    if 'operation_id' not in st.session_state:
        st.session_state.operation_id = operation_id
        
    try:
        with open("debug.log", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - [{operation_id}] {message}\n")
    except Exception as e:
        st.error(f"Error writing to debug log: {str(e)}")

# Function to check database status
def check_database_connection():
    """Check if database is accessible and return status info"""
    try:
        db_path = get_db_file_name()
        log_debug(f"Database path: {db_path}")
        
        # Check if file exists
        if not os.path.exists(db_path):
            return False, f"Database file does not exist at: {db_path}"
            
        # Test connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT sqlite_version()")
        version = cursor.fetchone()[0]
        conn.close()
        
        return True, f"Connected to SQLite version {version}, database at {db_path}"
    except Exception as e:
        log_debug(f"Database connection error: {str(e)}")
        return False, f"Database error: {str(e)}"

# Function to save CVE to database
def save_cve_to_database(cve_data):
    """Save or update CVE data in the database"""
    log_debug(f"Attempting to save CVE {cve_data.get('cve_id')} to database")
    
    # Add timestamp if not present
    if 'processed_at' not in cve_data:
        cve_data['processed_at'] = datetime.now().isoformat()
    
    # Add operation ID for tracking
    cve_data['operation_id'] = st.session_state.operation_id
    
    # Check database connection first
    db_ok, db_message = check_database_connection()
    if not db_ok:
        log_debug(f"Database connection check failed: {db_message}")
        st.error(f"Database connection issue: {db_message}")
        return False
        
    # Use store_or_update_cve for reliable saving
    save_result = store_or_update_cve(cve_data)
    log_debug(f"store_or_update_cve result: {save_result}")
    
    # Update session state
    st.session_state.save_attempted = True
    st.session_state.save_success = save_result
    if save_result:
        st.session_state.saved_cve_data = cve_data
        
        # Verify the save by reading back from database
        verification_data = get_cve_details(cve_data.get('cve_id'))
        if verification_data:
            log_debug(f"Verification successful - CVE found in database")
            log_debug(f"Saved timestamp: {verification_data.get('processed_at')}")
        else:
            log_debug(f"Verification failed - CVE not found in database after save")
            st.warning("Save operation completed but verification failed - CVE not found in database")
            return False
    
    return save_result

# Log session state at the start
log_debug(f"Page loaded/reloaded. Session state: save_attempted={st.session_state.save_attempted}, save_success={st.session_state.save_success}")

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
                        epss_score, epss_percentile = get_epss_score(cve_id)
                        
                        if epss_score is not None and epss_percentile is not None:
                            nvd_data['epss_score'] = epss_score
                            nvd_data['epss_percentile'] = epss_percentile
                            st.success(f"EPSS score: {epss_score:.4f} (percentile: {epss_percentile:.2f})")
                        else:
                            st.warning("Could not retrieve EPSS score for this CVE.")
                    
                    # Check if CVE is in CISA KEV catalog
                    with st.spinner("Checking CISA KEV status..."):
                        kev_catalog = fetch_kev_catalog()
                        
                        if kev_catalog:
                            is_in_kev, kev_date_added = check_cve_in_kev(cve_id, kev_catalog)
                            nvd_data['is_in_kev'] = is_in_kev
                            nvd_data['kev_date_added'] = kev_date_added
                            
                            if is_in_kev:
                                st.warning(f"⚠️ This vulnerability is in the CISA Known Exploited Vulnerabilities catalog! Added on {kev_date_added}")
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
                            
                            # Simplify HTML to avoid rendering issues
                            priority_html = f'<div style="background-color: {priority_color}; color: white; padding: 10px; border-radius: 5px; text-align: center; font-weight: bold;">Gemini Priority: {priority}</div>'
                            st.markdown(priority_html, unsafe_allow_html=True)
                        except Exception as e:
                            st.error(f"Error analyzing with Gemini: {str(e)}")
                            nvd_data['gemini_priority'] = "ERROR_ANALYZING"
                    
                    # Calculate risk score
                    with st.spinner("Calculating risk score..."):
                        try:
                            risk_score, alerts = analyze_cve_risk(nvd_data)
                            nvd_data['risk_score'] = risk_score
                            nvd_data['alerts'] = alerts
                            
                            if risk_score is not None:
                                st.success(f"Risk score: {risk_score:.2f}")
                                if alerts:
                                    st.warning(f"{len(alerts)} alerts generated")
                        except Exception as e:
                            st.error(f"Error calculating risk score: {str(e)}")
                    
                    # Display full details
                    display_cve_details(nvd_data, "National Vulnerability Database (Live)")
                    
                    # Option to save to database
                    save_col1, save_col2 = st.columns([1, 4])
                    with save_col1:
                        if st.button("💾 Save to Database", type="primary"):
                            log_debug(f"Save button clicked for CVE {cve_id}")
                            log_debug(f"[LIVE_LOOKUP] Data to be saved for {cve_id}: {nvd_data}")
                            
                            with st.spinner("Saving to database..."):
                                save_result = save_cve_to_database(nvd_data)
                                log_debug(f"[LIVE_LOOKUP] save_cve_to_database returned: {save_result} for {cve_id}") # YENİ LOG
                                log_debug(f"[LIVE_LOOKUP] Session state after save attempt: save_attempted={st.session_state.save_attempted}, save_success={st.session_state.save_success}") # YENİ LOG


                                if save_result:
                                    st.success("✅ CVE successfully saved to database!", icon="✅")
                                    log_debug("CVE successfully saved to database")
                                    
                                    # Add details about saved data
                                    with save_col2:
                                        st.info(f"Saved at: {nvd_data['processed_at']}")
                                else:
                                    st.error("❌ Failed to save CVE to database. See logs for details.", icon="❌")
                                    log_debug("Failed to save CVE to database")
                                    
                                    # Show debug info
                                    with save_col2:
                                        # Database status check
                                        db_ok, db_message = check_database_connection()
                                        status_color = "green" if db_ok else "red"
                                        st.markdown(f"Database status: <span style='color:{status_color};'>{db_message}</span>", unsafe_allow_html=True)
                                        
                                        # Add verify button
                                        if st.button("🔍 Verify Database"):
                                            verification_data = get_cve_details(cve_id)
                                            if verification_data:
                                                st.success(f"CVE {cve_id} found in database!")
                                                st.write(f"Last updated: {verification_data.get('processed_at', 'Unknown')}")
                                            else:
                                                st.error(f"CVE {cve_id} NOT found in database!")
                    
                    # Clear the fetch flag to allow new searches
                    st.session_state.pop('perform_live_fetch', None)

# Display saved CVE information
if st.session_state.save_attempted and st.session_state.save_success and st.session_state.saved_cve_data:
    st.markdown("---")
    st.markdown("### Saved CVE Details")
    
    # Create an expandable section with details
    with st.expander("View saved data", expanded=False):
        saved_data = st.session_state.saved_cve_data
        st.markdown(f"**CVE ID:** {saved_data.get('cve_id')}")
        st.markdown(f"**Priority:** {saved_data.get('gemini_priority', 'N/A')}")
        st.markdown(f"**CVSS Score:** {saved_data.get('cvss_v3_score', 'N/A')}")
        st.markdown(f"**Risk Score:** {saved_data.get('risk_score', 'N/A')}")
        st.markdown(f"**Saved at:** {saved_data.get('processed_at', 'N/A')}") 
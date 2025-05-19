"""
VIPER CTI Dashboard - Main Dashboard Page
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import calendar
import sys
import os

# Add the project root directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.utils.database_handler import get_filtered_cves, get_all_cves_with_details

# Set the page title and add refresh button at the top right
title_col, refresh_col = st.columns([6, 1])
with title_col:
    st.title("📊 Vulnerability Dashboard")
with refresh_col:
    st.markdown("<div style='margin-top: 15px;'></div>", unsafe_allow_html=True)  # Adding some vertical space
    if st.button("🔄 Refresh", type="primary", use_container_width=True):
        st.rerun()

# Create sidebar for filters
st.sidebar.header("Filters")

# Date filters with defaults (last 30 days)
today = datetime.now().date()
thirty_days_ago = today - timedelta(days=30)

col1, col2 = st.sidebar.columns(2)
with col1:
    date_start = st.date_input(
        "From Date",
        value=thirty_days_ago,
        format="YYYY-MM-DD"
    )
with col2:
    date_end = st.date_input(
        "To Date",
        value=today,
        format="YYYY-MM-DD"
    )

# Convert to string format that the database expects
date_start_str = date_start.isoformat() if date_start else None
date_end_str = date_end.isoformat() if date_end else None

# Priority filter
priorities = st.sidebar.multiselect(
    "Priority Level",
    options=["HIGH", "MEDIUM", "LOW"],
    default=["HIGH", "MEDIUM"]
)

# CVSS Score range
cvss_range = st.sidebar.slider(
    "CVSS Score Range",
    min_value=0.0,
    max_value=10.0,
    value=(0.0, 10.0),
    step=0.1
)
cvss_min, cvss_max = cvss_range

# EPSS Score range
epss_range = st.sidebar.slider(
    "EPSS Score Range",
    min_value=0.0,
    max_value=1.0,
    value=(0.0, 1.0),
    step=0.01
)
epss_min, epss_max = epss_range

# KEV filter
kev_filter = st.sidebar.radio(
    "CISA KEV Status",
    options=["All", "Only KEV", "Exclude KEV"],
    index=0
)

is_in_kev = None
if kev_filter == "Only KEV":
    is_in_kev = True
elif kev_filter == "Exclude KEV":
    is_in_kev = False

# Public Exploit filter
exploit_filter = st.sidebar.radio(
    "Public Exploit Status",
    options=["All", "Only with Exploits", "Exclude Exploits"],
    index=0
)

has_public_exploit = None
if exploit_filter == "Only with Exploits":
    has_public_exploit = True
elif exploit_filter == "Exclude Exploits":
    has_public_exploit = False

# Microsoft severity filter
ms_severity_filter = st.sidebar.selectbox(
    "Microsoft Severity",
    options=["All", "Critical", "Important", "Moderate", "Low"],
    index=0
)

microsoft_severity = None
if ms_severity_filter != "All":
    microsoft_severity = ms_severity_filter

# Microsoft product filter
ms_product_filter = st.sidebar.text_input("Microsoft Product (contains)", "")

# Keyword search
keyword = st.sidebar.text_input("Search Description", "")

# Apply filters button
apply_filters = st.sidebar.button("Apply Filters", type="primary")

# Fetch the CVE data with filters
if 'cve_data' not in st.session_state or apply_filters:
    with st.spinner("Loading vulnerability data..."):
        cve_data = get_filtered_cves(
            date_start=date_start_str,
            date_end=date_end_str,
            priorities=priorities if priorities else None,
            cvss_min=cvss_min,
            cvss_max=cvss_max,
            epss_min=epss_min,
            epss_max=epss_max,
            is_in_kev=is_in_kev,
            has_public_exploit=has_public_exploit,
            keyword=keyword if keyword else None,
            microsoft_severity=microsoft_severity,
            microsoft_product=ms_product_filter if ms_product_filter else None
        )
        st.session_state.cve_data = cve_data

# If no data, display a message
if not st.session_state.cve_data:
    st.info("No vulnerabilities found with the current filters. Try adjusting your filters.")
    st.stop()

# Convert the CVE data to a DataFrame for easier manipulation
df = pd.DataFrame(st.session_state.cve_data)

# Convert date strings to datetime
if 'published_date' in df.columns:
    df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce', utc=True)
if 'kev_date_added' in df.columns:
    df['kev_date_added'] = pd.to_datetime(df['kev_date_added'], errors='coerce', utc=True)

# --- Metrics Section ---
st.subheader("Summary Metrics")
metrics_cols = st.columns(5)

with metrics_cols[0]:
    st.metric("Total Vulnerabilities", len(df))

with metrics_cols[1]:
    high_priority = len(df[df['gemini_priority'] == 'HIGH'])
    st.metric("High Priority", high_priority)

with metrics_cols[2]:
    kev_count = int(df['is_in_kev'].sum())
    # Add a red color to the CISA KEV metric to make it stand out
    st.metric("In CISA KEV", kev_count, delta=f"{kev_count/len(df)*100:.1f}%" if len(df) > 0 else "0%", delta_color="off")
    
with metrics_cols[3]:
    # Add public exploit count metric
    exploit_count = int(df['has_public_exploit'].sum())
    st.metric("Public Exploits", exploit_count, delta=f"{exploit_count/len(df)*100:.1f}%" if len(df) > 0 else "0%", delta_color="off")

with metrics_cols[4]:
    avg_risk = df['risk_score'].mean()
    st.metric("Avg Risk Score", f"{avg_risk:.2f}" if not pd.isna(avg_risk) else "N/A")

# --- Priority Distribution ---
st.subheader("Priority Distribution")
priority_cols = st.columns(3)

with priority_cols[0]:
    priority_counts = df['gemini_priority'].value_counts().reset_index()
    priority_counts.columns = ['Priority', 'Count']
    
    # Define colors for priorities
    colors = {'HIGH': '#ff4b4b', 'MEDIUM': '#ffa64b', 'LOW': '#4bff4b'}
    
    fig_priority = px.pie(
        priority_counts, 
        values='Count', 
        names='Priority',
        color='Priority',
        color_discrete_map=colors,
        hole=0.4
    )
    fig_priority.update_traces(textposition='inside', textinfo='percent+label')
    fig_priority.update_layout(height=300, title="Priority Levels")
    st.plotly_chart(fig_priority, use_container_width=True)

with priority_cols[1]:
    # Add a new visualization for exploit vs non-exploit CVEs
    exploit_status = df['has_public_exploit'].map({True: 'Has Exploit', False: 'No Exploit'}).value_counts().reset_index()
    exploit_status.columns = ['Status', 'Count']
    
    fig_exploits = px.pie(
        exploit_status,
        values='Count',
        names='Status',
        color='Status',
        color_discrete_map={'Has Exploit': '#ff4b4b', 'No Exploit': '#4b4bff'},
        hole=0.4
    )
    fig_exploits.update_traces(textposition='inside', textinfo='percent+label')
    fig_exploits.update_layout(height=300, title="Public Exploit Availability")
    st.plotly_chart(fig_exploits, use_container_width=True)

with priority_cols[2]:
    # CVEs Over Time
    # Filter to only include valid datetime values before grouping
    df_date_valid = df.dropna(subset=['published_date'])
    # Handle dt.date access only on valid datetime values
    if not df_date_valid.empty:
        df_by_date = df_date_valid.groupby(df_date_valid['published_date'].dt.date).size().reset_index(name='count')
        df_by_date.columns = ['Date', 'CVEs']
        
        fig_timeline = px.line(
            df_by_date, 
            x='Date', 
            y='CVEs',
            markers=True,
            title="CVEs Over Time"
        )
        fig_timeline.update_layout(height=300)
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No valid publication dates available for timeline display.")

# --- KEV Distribution ---
st.subheader("CISA KEV Distribution")
kev_cols = st.columns(2)

with kev_cols[0]:
    # Create KEV distribution pie chart
    kev_data = pd.DataFrame({
        'Status': ['In KEV Catalog', 'Not in KEV Catalog'],
        'Count': [df['is_in_kev'].sum(), len(df) - df['is_in_kev'].sum()]
    })
    
    fig_kev_pie = px.pie(
        kev_data,
        values='Count',
        names='Status',
        color='Status',
        color_discrete_map={'In KEV Catalog': '#ff4b4b', 'Not in KEV Catalog': '#4bafff'},
        hole=0.4
    )
    fig_kev_pie.update_traces(textposition='inside', textinfo='percent+label')
    fig_kev_pie.update_layout(height=300)
    st.plotly_chart(fig_kev_pie, use_container_width=True)

with kev_cols[1]:
    # KEV by Priority Distribution
    kev_by_priority = df.groupby('gemini_priority')['is_in_kev'].agg(['sum', 'count']).reset_index()
    kev_by_priority['percentage'] = (kev_by_priority['sum'] / kev_by_priority['count'] * 100).round(1)
    kev_by_priority.columns = ['Priority', 'In KEV', 'Total', 'Percentage in KEV']
    
    fig_kev_priority = px.bar(
        kev_by_priority,
        x='Priority',
        y='Percentage in KEV',
        color='Priority',
        color_discrete_map=colors,
        text_auto='.1f'
    )
    fig_kev_priority.update_layout(
        title='KEV Distribution by Priority',
        xaxis_title='Priority',
        yaxis_title='Percentage in KEV',
        height=300
    )
    st.plotly_chart(fig_kev_priority, use_container_width=True)

# --- KEV vs Non-KEV Risk Distribution ---
st.subheader("Risk Score Distribution")
risk_cols = st.columns(2)

with risk_cols[0]:
    # Risk Distribution by KEV Status
    fig_risk = go.Figure()
    # Add KEV vulnerabilities
    kev_risks = df[df['is_in_kev'] == True]['risk_score'].dropna()
    non_kev_risks = df[df['is_in_kev'] == False]['risk_score'].dropna()
    
    if not kev_risks.empty:
        fig_risk.add_trace(go.Box(
            y=kev_risks,
            name='KEV',
            marker_color='#ff4b4b'
        ))
    
    if not non_kev_risks.empty:
        fig_risk.add_trace(go.Box(
            y=non_kev_risks,
            name='Non-KEV',
            marker_color='#4b9fff'
        ))
    
    fig_risk.update_layout(
        title='Risk Score Distribution by KEV Status',
        yaxis_title='Risk Score',
        height=300
    )
    st.plotly_chart(fig_risk, use_container_width=True)

with risk_cols[1]:
    # CVSS vs EPSS Scatter Plot
    df_scatter = df.dropna(subset=['cvss_v3_score', 'epss_score'])
    
    if not df_scatter.empty:
        # Make a copy and fill NaN risk scores with a default value
        scatter_df = df_scatter.copy()
        scatter_df['risk_score'] = scatter_df['risk_score'].fillna(1)  # Default size for points with no risk score
        
        fig_scatter = px.scatter(
            scatter_df,
            x='cvss_v3_score',
            y='epss_score',
            color='gemini_priority',
            size='risk_score',
            hover_name='cve_id',
            color_discrete_map=colors,
            opacity=0.7
        )
        fig_scatter.update_layout(
            title='CVSS vs EPSS with Risk Score',
            xaxis_title='CVSS Score',
            yaxis_title='EPSS Score',
            height=300
        )
        st.plotly_chart(fig_scatter, use_container_width=True)
    else:
        st.info("Insufficient data for CVSS vs EPSS visualization")

# --- Detailed Table ---
st.subheader("Vulnerability Details")

# Before showing the full table, show the most recent KEV entries
kev_entries = df[df['is_in_kev'] == True].copy()
if not kev_entries.empty and 'kev_date_added' in kev_entries.columns:
    # Sort by KEV date added (most recent first) and get top 5
    kev_entries = kev_entries.sort_values(by='kev_date_added', ascending=False)
    recent_kev = kev_entries.head(5)
    
    if not recent_kev.empty:
        st.markdown("### 🚨 Most Recent CISA KEV Entries")
        
        # Format for display
        recent_kev_display = recent_kev.copy()
        # Safely format dates
        if 'published_date' in recent_kev_display.columns:
            recent_kev_display['published_date'] = recent_kev_display['published_date'].apply(
                lambda x: x.strftime('%Y-%m-%d') if pd.notnull(x) else 'Unknown'
            )
        if 'kev_date_added' in recent_kev_display.columns:
            recent_kev_display['kev_date_added'] = recent_kev_display['kev_date_added'].apply(
                lambda x: x.strftime('%Y-%m-%d') if pd.notnull(x) else 'Unknown'
            )
        
        # Only select relevant columns
        recent_kev_display = recent_kev_display[['cve_id', 'kev_date_added', 'gemini_priority', 'cvss_v3_score', 'description']]
        
        # Format numbers
        if 'cvss_v3_score' in recent_kev_display.columns:
            recent_kev_display['cvss_v3_score'] = recent_kev_display['cvss_v3_score'].apply(lambda x: f"{x:.1f}" if pd.notnull(x) else "N/A")
        
        # Rename columns for display
        recent_kev_display.columns = ['CVE ID', 'KEV Date Added', 'Priority', 'CVSS', 'Description']
        
        # Style the table with a red background to draw attention
        st.markdown("""
        <style>
        .recent-kev {
            background-color: rgba(255, 0, 0, 0.05);
            border-radius: 5px;
            padding: 10px;
            border-left: 3px solid red;
        }
        </style>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="recent-kev">', unsafe_allow_html=True)
        st.dataframe(
            recent_kev_display,
            use_container_width=True,
            column_config={
                "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
                "KEV Date Added": st.column_config.TextColumn("KEV Date Added", width="medium"),
                "Description": st.column_config.TextColumn("Description", width="large")
            }
        )
        st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("""
        <div style="margin-bottom: 20px; text-align: right; font-style: italic; font-size: 0.9em;">
        ⚠️ These vulnerabilities have confirmed exploitation in the wild
        </div>
        """, unsafe_allow_html=True)

# Show Microsoft Critical Vulnerabilities
ms_critical = df[(df['microsoft_severity'] == 'Critical')].copy()
if not ms_critical.empty:
    # Sort by patch Tuesday date (most recent first)
    if 'patch_tuesday_date' in ms_critical.columns:
        ms_critical = ms_critical.sort_values(by='patch_tuesday_date', ascending=False)
    recent_critical = ms_critical.head(5)
    
    if not recent_critical.empty:
        st.markdown("### 🚨 Microsoft Critical Severity Vulnerabilities")
        
        # Format for display
        ms_critical_display = recent_critical.copy()
        if 'published_date' in ms_critical_display.columns:
            ms_critical_display['published_date'] = ms_critical_display['published_date'].apply(
                lambda x: x.strftime('%Y-%m-%d') if pd.notnull(x) else 'Unknown'
            )
        if 'patch_tuesday_date' in ms_critical_display.columns:
            ms_critical_display['patch_tuesday_date'] = ms_critical_display['patch_tuesday_date'].apply(
                lambda x: x.strftime('%Y-%m-%d') if pd.notnull(x) else 'Unknown'
            )
        
        # Only select relevant columns
        ms_critical_display = ms_critical_display[['cve_id', 'microsoft_severity', 'microsoft_product_family', 'patch_tuesday_date', 'gemini_priority', 'cvss_v3_score', 'description']]
        
        # Format numbers
        if 'cvss_v3_score' in ms_critical_display.columns:
            ms_critical_display['cvss_v3_score'] = ms_critical_display['cvss_v3_score'].apply(lambda x: f"{x:.1f}" if pd.notnull(x) else "N/A")
        
        # Rename columns for display
        ms_critical_display.columns = ['CVE ID', 'MS Severity', 'MS Product', 'Patch Tuesday', 'Priority', 'CVSS', 'Description']
        
        # Style the table with a red background to draw attention
        st.markdown("""
        <style>
        .ms-critical {
            background-color: rgba(255, 0, 0, 0.05);
            border-radius: 5px;
            padding: 10px;
            border-left: 3px solid red;
        }
        </style>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="ms-critical">', unsafe_allow_html=True)
        st.dataframe(
            ms_critical_display,
            use_container_width=True,
            column_config={
                "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
                "MS Severity": st.column_config.TextColumn("MS Severity", width="small"),
                "MS Product": st.column_config.TextColumn("MS Product", width="medium"),
                "Patch Tuesday": st.column_config.TextColumn("Patch Tuesday", width="medium"),
                "Description": st.column_config.TextColumn("Description", width="large")
            }
        )
        st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("""
        <div style="margin-bottom: 20px; text-align: right; font-style: italic; font-size: 0.9em;">
        ⚠️ Microsoft rates these vulnerabilities as Critical, the highest severity level
        </div>
        """, unsafe_allow_html=True)

# Format the dataframe for display
display_df = df.copy()
if 'published_date' in display_df.columns:
    display_df['published_date'] = display_df['published_date'].apply(
        lambda x: x.strftime('%Y-%m-%d') if pd.notnull(x) else 'Unknown'
    )
if 'kev_date_added' in display_df.columns:
    display_df['kev_date_added'] = display_df['kev_date_added'].apply(
        lambda x: x.strftime('%Y-%m-%d') if pd.notnull(x) else 'Unknown'
    )

# Format floating point numbers
if 'epss_score' in display_df.columns:
    display_df['epss_score'] = display_df['epss_score'].apply(lambda x: f"{x:.4f}" if pd.notnull(x) else None)
if 'epss_percentile' in display_df.columns:
    display_df['epss_percentile'] = display_df['epss_percentile'].apply(lambda x: f"{x:.2f}" if pd.notnull(x) else None)
if 'cvss_v3_score' in display_df.columns:
    display_df['cvss_v3_score'] = display_df['cvss_v3_score'].apply(lambda x: f"{x:.1f}" if pd.notnull(x) else None)
if 'risk_score' in display_df.columns:
    display_df['risk_score'] = display_df['risk_score'].apply(lambda x: f"{x:.2f}" if pd.notnull(x) else None)

# --- Format KEV status with icons for better visibility ---
# Create a new column that shows KEV status with an icon and date if available
display_df['KEV Status'] = display_df.apply(
    lambda row: f"🚨 Yes ({row['kev_date_added']})" if row['is_in_kev'] and pd.notnull(row['kev_date_added']) 
                else "🚨 Yes" if row['is_in_kev'] 
                else "No", 
    axis=1
)

# --- Format Microsoft info ---
# Create a new column for Microsoft information if available
display_df['MS Info'] = display_df.apply(
    lambda row: f"{row['microsoft_severity']} ({row['microsoft_product_family']})" 
                if pd.notnull(row['microsoft_severity']) and pd.notnull(row['microsoft_product_family'])
                else row['microsoft_severity'] if pd.notnull(row['microsoft_severity'])
                else "N/A",
    axis=1
)

# Remove the original columns since we now have the enhanced columns
display_df = display_df.drop(columns=['is_in_kev'])

# Reorder columns to put KEV Status and MS Info in a more prominent position
cols_to_display = ['cve_id', 'KEV Status', 'MS Info', 'gemini_priority', 'cvss_v3_score', 'epss_score', 'risk_score', 'published_date', 'description']
display_df = display_df[cols_to_display].rename(columns={
    'cve_id': 'CVE ID',
    'gemini_priority': 'AI Priority',
    'cvss_v3_score': 'CVSS',
    'epss_score': 'EPSS',
    'risk_score': 'Risk Score',
    'published_date': 'Published Date',
    'description': 'Description'
})

# Add CSS for highlighting KEV vulnerabilities in the table
st.markdown("""
<style>
    .kev-highlight {
        background-color: rgba(255, 75, 75, 0.1);
        border-left: 3px solid red;
        padding-left: 5px;
    }
</style>
""", unsafe_allow_html=True)

# Display the table with pagination
page_size = 10
total_pages = max(1, len(display_df) // page_size + (1 if len(display_df) % page_size > 0 else 0))

if len(display_df) > 0:
    page_col1, page_col2, page_col3 = st.columns([1, 3, 1])
    with page_col2:
        # Only show the slider if we have more than one page
        if total_pages > 1:
            page_number = st.slider('Page', 1, total_pages, 1)
        else:
            page_number = 1
            st.text('Page 1 of 1')
    
    start_idx = (page_number - 1) * page_size
    end_idx = min(start_idx + page_size, len(display_df))
    
    # Display the dataframe
    st.dataframe(
        display_df.iloc[start_idx:end_idx], 
        use_container_width=True,
        column_config={
            "KEV Status": st.column_config.TextColumn(
                "CISA KEV Status",
                help="Whether this vulnerability is in the CISA Known Exploited Vulnerabilities catalog",
                width="medium"
            ),
            "CVE ID": st.column_config.TextColumn(
                "CVE ID",
                width="medium"
            ),
            "Description": st.column_config.TextColumn(
                "Description",
                width="large"
            )
        }
    )
else:
    st.dataframe(display_df, use_container_width=True)

# --- Detail View for Selected CVE ---
st.subheader("CVE Detail View")
selected_cve = st.selectbox("Select a CVE to view details", options=df['cve_id'].tolist())

if selected_cve:
    selected_data = df[df['cve_id'] == selected_cve].iloc[0].to_dict()
    
    # Determine if this is a KEV vulnerability for styling
    is_kev = selected_data.get('is_in_kev', False)
    kev_badge = '<span style="background-color: #ff4b4b; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold; margin-left: 10px;">CISA KEV</span>' if is_kev else ""
    
    # Display CVE header with KEV badge if applicable
    st.markdown(f"### {selected_cve} {kev_badge}", unsafe_allow_html=True)
    
    detail_cols = st.columns(3)
    
    with detail_cols[0]:
        st.markdown(f"**Published:** {selected_data.get('published_date').strftime('%Y-%m-%d') if pd.notnull(selected_data.get('published_date')) else 'N/A'}")
        st.markdown(f"**AI Priority:** {selected_data.get('gemini_priority', 'N/A')}")
        st.markdown(f"**CVSS Score:** {selected_data.get('cvss_v3_score', 'N/A')}")
        st.markdown(f"**EPSS Score:** {selected_data.get('epss_score', 'N/A')}")
        
        # Make the KEV status more prominent
        if is_kev:
            kev_alert_html = """
            <div style="background-color: rgba(255, 75, 75, 0.1); padding: 10px; border-radius: 5px; border-left: 4px solid #ff4b4b; margin-top: 10px;">
            <b>⚠️ CISA Known Exploited Vulnerability</b><br>
            This vulnerability is being actively exploited in the wild
            </div>
            """
            st.markdown(kev_alert_html, unsafe_allow_html=True)
            
            if pd.notnull(selected_data.get('kev_date_added')):
                st.markdown(f"**KEV Added:** {selected_data.get('kev_date_added').strftime('%Y-%m-%d')}")
        else:
            st.markdown("**CISA KEV Status:** Not in KEV catalog")
            
        st.markdown(f"**Risk Score:** {selected_data.get('risk_score', 'N/A')}")
    
    with detail_cols[1]:
        st.markdown("### Description")
        st.markdown(selected_data.get('description', 'No description available'))
    
    with detail_cols[2]:
        st.markdown("### Alerts")
        alerts = selected_data.get('alerts', [])
        
        # Add a special KEV alert if it's in the KEV catalog
        if is_kev and not any("CISA KEV" in alert for alert in alerts):
            st.error("**ALERT:** This vulnerability is in the CISA Known Exploited Vulnerabilities (KEV) catalog, indicating it is being actively exploited in the wild.")
            
        if alerts:
            for alert in alerts:
                st.warning(alert)
        elif not is_kev:
            st.info("No specific alerts for this vulnerability")

# Top CVSS Vulnerabilities Table
top_cvss = df.sort_values(by='cvss_v3_score', ascending=False).head(5)
if not top_cvss.empty:
    st.subheader("Top CVSS Score Vulnerabilities")
    
    # Format the table
    formatted_top_cvss = top_cvss[['cve_id', 'cvss_v3_score', 'gemini_priority', 'risk_score']].copy()
    
    # Format the columns
    formatted_top_cvss['cve_id'] = formatted_top_cvss['cve_id'].apply(
        lambda x: f"<a href='./Detailed_Analysis?selected_cve={x}' target='_self'>{x}</a>"
    )
    formatted_top_cvss['cvss_v3_score'] = formatted_top_cvss['cvss_v3_score'].apply(lambda x: f"{x:.1f}")
    formatted_top_cvss['risk_score'] = formatted_top_cvss['risk_score'].apply(lambda x: f"{x:.2f}" if pd.notnull(x) else "N/A")
    
    # Rename the columns for display
    formatted_top_cvss.columns = ['CVE ID', 'CVSS Score', 'Priority', 'Risk Score']
    
    # Display with HTML formatting to enable clickable links
    st.markdown(
        formatted_top_cvss.to_html(escape=False, index=False),
        unsafe_allow_html=True
    )

# Public Exploits Section
st.markdown("---")
st.subheader("🚨 Vulnerabilities with Public Exploits")

# Filter the DataFrame for CVEs with public exploits
exploitable_cves = df[df['has_public_exploit'] == True].sort_values(by=['risk_score', 'cvss_v3_score'], ascending=False)

if not exploitable_cves.empty:
    # Create two columns - one for metrics and one for the table
    exploit_cols = st.columns([1, 3])
    
    with exploit_cols[0]:
        # Display metrics about exploitable CVEs
        st.metric("Total Exploitable", len(exploitable_cves))
        
        high_risk_exploitable = len(exploitable_cves[exploitable_cves['risk_score'] >= 0.7])
        st.metric("High Risk & Exploitable", high_risk_exploitable, 
                 delta=f"{high_risk_exploitable/len(exploitable_cves)*100:.1f}%" if len(exploitable_cves) > 0 else "0%", 
                 delta_color="off")
        
        # Count high priority and exploitable
        high_priority_exploitable = len(exploitable_cves[exploitable_cves['gemini_priority'] == 'HIGH'])
        st.metric("High Priority & Exploitable", high_priority_exploitable,
                 delta=f"{high_priority_exploitable/len(exploitable_cves)*100:.1f}%" if len(exploitable_cves) > 0 else "0%",
                 delta_color="off")
        
        # Also in KEV
        kev_and_exploitable = len(exploitable_cves[exploitable_cves['is_in_kev'] == True])
        st.metric("In KEV & Exploitable", kev_and_exploitable,
                 delta=f"{kev_and_exploitable/len(exploitable_cves)*100:.1f}%" if len(exploitable_cves) > 0 else "0%",
                 delta_color="off")
    
    with exploit_cols[1]:
        # Display a table of top exploitable CVEs
        st.markdown("#### Critical Vulnerabilities with Public Exploits")
        
        # Get top 10 exploitable CVEs based on risk score
        top_exploitable = exploitable_cves.head(10)
        
        # Format the table
        formatted_exploitable = top_exploitable[['cve_id', 'cvss_v3_score', 'gemini_priority', 'risk_score', 'is_in_kev']].copy()
        
        # Format the columns
        formatted_exploitable['cve_id'] = formatted_exploitable['cve_id'].apply(
            lambda x: f"<a href='./Detailed_Analysis?selected_cve={x}' target='_self'>{x}</a>"
        )
        formatted_exploitable['cvss_v3_score'] = formatted_exploitable['cvss_v3_score'].apply(lambda x: f"{x:.1f}")
        formatted_exploitable['risk_score'] = formatted_exploitable['risk_score'].apply(lambda x: f"{x:.2f}" if pd.notnull(x) else "N/A")
        formatted_exploitable['is_in_kev'] = formatted_exploitable['is_in_kev'].apply(lambda x: "✓" if x else "")
        
        # Rename the columns for display
        formatted_exploitable.columns = ['CVE ID', 'CVSS Score', 'Priority', 'Risk Score', 'In KEV']
        
        # Display with HTML formatting to enable clickable links
        st.markdown(
            formatted_exploitable.to_html(escape=False, index=False),
            unsafe_allow_html=True
        )
        
        # Add note about exploitable vulnerabilities
        st.markdown("""
        <div style="background-color: #ffcccb; padding: 10px; border-radius: 5px; margin-top: 10px;">
            <strong>⚠️ Warning:</strong> These vulnerabilities have publicly available exploits and should be prioritized for patching.
            Click on any CVE ID to view detailed information, including links to the exploits.
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("No vulnerabilities with public exploits found in the current filtered set.")

# Add footer with timestamp
st.markdown("---")
st.markdown(f"*Dashboard refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

# Add a live search feature in the sidebar
st.sidebar.markdown("---")
st.sidebar.header("🔍 Live Exploit Search")

with st.sidebar.form("exploit_search_form"):
    search_cve = st.text_input("Enter CVE ID", placeholder="e.g., CVE-2021-44228")
    search_submitted = st.form_submit_button("Search GitHub")

if search_submitted and search_cve:
    # Validate CVE format
    if not search_cve.startswith("CVE-") or len(search_cve.split("-")) != 3:
        st.sidebar.error("Please enter a valid CVE ID (e.g., CVE-2021-44228)")
    else:
        with st.sidebar.spinner(f"Searching for {search_cve}..."):
            try:
                # Import necessary modules
                import sys
                import os
                # Add the project root to the path
                sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
                
                from src.clients.exploit_search_client import search_github
                
                # Search for exploits on GitHub
                exploits = search_github(search_cve)
                
                # Display results
                if exploits and len(exploits) > 0:
                    st.sidebar.warning(f"Found {len(exploits)} potential exploit(s)!")
                    
                    # Show in expander to save space
                    with st.sidebar.expander("View Results", expanded=True):
                        for i, exploit in enumerate(exploits[:5]):  # Limit to 5 to avoid sidebar overflow
                            st.markdown(f"**{exploit.get('title', 'Unknown')}**")
                            st.markdown(f"Type: {exploit.get('type', 'Unknown')}")
                            st.markdown(f"[View on GitHub]({exploit.get('url', '#')})")
                            
                            if i < min(len(exploits), 5) - 1:
                                st.markdown("---")
                        
                        if len(exploits) > 5:
                            st.info(f"{len(exploits) - 5} more results not shown. Visit Detailed Analysis for full results.")
                else:
                    st.sidebar.success("No exploits found on GitHub.")
                
            except Exception as e:
                st.sidebar.error(f"Error searching: {str(e)}")
                st.sidebar.info("Make sure GitHub token is configured.") 
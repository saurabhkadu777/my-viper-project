"""
VIPER CTI Dashboard - Analytics & Trends Page
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
import sys
import os
from collections import Counter

# Add the project root directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.utils.database_handler import get_all_cves_with_details

# Set the page title
st.title("📈 Analytics & Trends")

# Load all CVEs with details
@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_cve_data():
    return get_all_cves_with_details()

# Get the CVE data
with st.spinner("Loading vulnerability data for analysis..."):
    all_cve_data = load_cve_data()

# If no data, display a message
if not all_cve_data:
    st.info("No vulnerability data available for analysis.")
    st.stop()

# Convert to DataFrame
df = pd.DataFrame(all_cve_data)

# Convert date strings to datetime
if 'published_date' in df.columns:
    df['published_date'] = pd.to_datetime(df['published_date'])
if 'kev_date_added' in df.columns:
    df['kev_date_added'] = pd.to_datetime(df['kev_date_added'], errors='coerce')
if 'processed_at' in df.columns:
    df['processed_at'] = pd.to_datetime(df['processed_at'], errors='coerce')

# Add time range selection
st.sidebar.header("Time Range")

# Calculate default time range (last 12 months)
today = datetime.now().date()
one_year_ago = today - timedelta(days=365)

date_range = st.sidebar.date_input(
    "Select Date Range",
    value=(one_year_ago, today),
    max_value=today,
    format="YYYY-MM-DD"
)

# Apply date filter if both dates are selected
if len(date_range) == 2:
    start_date, end_date = date_range
    start_date = pd.to_datetime(start_date)
    end_date = pd.to_datetime(end_date) + timedelta(days=1)  # Include end date
    
    df = df[(df['published_date'] >= start_date) & (df['published_date'] < end_date)]

# If no data after filtering, show a message
if df.empty:
    st.warning("No data available for the selected time period. Please adjust your filter.")
    st.stop()

# Create tabs for different analyses
tab1, tab2, tab3, tab4, tab5 = st.tabs(["Temporal Analysis", "Priority Analysis", "KEV Analysis", "Risk Distribution", "Microsoft Analysis"])

# Temporal Analysis Tab
with tab1:
    st.subheader("Vulnerability Trends Over Time")
    
    # Group by week or month depending on the date range
    date_diff = (df['published_date'].max() - df['published_date'].min()).days
    
    if date_diff > 90:  # If more than 90 days, group by month
        df['period'] = df['published_date'].dt.to_period('M')
        period_type = "Monthly"
    else:  # Otherwise group by week
        df['period'] = df['published_date'].dt.to_period('W')
        period_type = "Weekly"
    
    # Create the time series data
    ts_data = df.groupby(['period']).size().reset_index(name='count')
    ts_data['period_start'] = ts_data['period'].dt.start_time
    
    # Create the time series plot
    fig = px.line(
        ts_data, 
        x='period_start', 
        y='count',
        title=f"{period_type} Vulnerability Count",
        markers=True
    )
    fig.update_layout(
        xaxis_title="Date",
        yaxis_title="Number of Vulnerabilities",
        height=400
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Priority trends over time
    st.subheader("Priority Trends Over Time")
    
    # Create priority time series
    df_priority_ts = df.copy()
    df_priority_ts['priority_value'] = df_priority_ts['gemini_priority'].map({
        'HIGH': 3, 
        'MEDIUM': 2, 
        'LOW': 1
    })
    
    priority_ts = df_priority_ts.groupby(['period']).agg({
        'priority_value': 'mean',
        'published_date': 'count'
    }).reset_index()
    
    priority_ts['period_start'] = priority_ts['period'].dt.start_time
    priority_ts['avg_priority'] = priority_ts['priority_value'].map(
        lambda x: 'HIGH' if x > 2.5 else ('MEDIUM' if x > 1.5 else 'LOW')
    )
    
    # Create two y-axis plot
    fig = go.Figure()
    
    # Add priority trend line
    fig.add_trace(
        go.Scatter(
            x=priority_ts['period_start'],
            y=priority_ts['priority_value'],
            name="Avg Priority (3=HIGH, 2=MEDIUM, 1=LOW)",
            line=dict(color='red', width=3)
        )
    )
    
    # Add count bars
    fig.add_trace(
        go.Bar(
            x=priority_ts['period_start'],
            y=priority_ts['published_date'],
            name="CVE Count",
            marker_color='lightblue',
            opacity=0.7
        )
    )
    
    fig.update_layout(
        title=f"{period_type} Priority Trend with Vulnerability Count",
        xaxis_title="Date",
        yaxis_title="Priority Value",
        yaxis=dict(
            title="Avg Priority Value",
            range=[1, 3],
            tickvals=[1, 2, 3],
            ticktext=["LOW", "MEDIUM", "HIGH"]
        ),
        yaxis2=dict(
            title="CVE Count",
            overlaying="y",
            side="right"
        ),
        height=400,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig, use_container_width=True)

# Priority Analysis Tab
with tab2:
    st.subheader("Vulnerability Priority Analysis")
    
    # Priority distribution
    priority_counts = df['gemini_priority'].value_counts().reset_index()
    priority_counts.columns = ['Priority', 'Count']
    
    # Define colors for priorities
    colors = {'HIGH': '#ff4b4b', 'MEDIUM': '#ffa64b', 'LOW': '#4bff4b'}
    
    # Create the priority distribution chart
    fig_priority = px.pie(
        priority_counts, 
        values='Count', 
        names='Priority',
        color='Priority',
        color_discrete_map=colors,
        title="Distribution of AI-Assigned Priorities"
    )
    fig_priority.update_traces(textposition='inside', textinfo='percent+label')
    st.plotly_chart(fig_priority, use_container_width=True)
    
    # CVSS vs Priority
    st.subheader("CVSS Score by Priority Level")
    
    # Box plot of CVSS by priority
    fig_cvss_priority = px.box(
        df.dropna(subset=['cvss_v3_score']), 
        x='gemini_priority', 
        y='cvss_v3_score',
        color='gemini_priority',
        color_discrete_map=colors,
        title="CVSS Score Distribution by Priority",
        labels={"cvss_v3_score": "CVSS Score", "gemini_priority": "AI Priority"}
    )
    st.plotly_chart(fig_cvss_priority, use_container_width=True)
    
    # EPSS vs Priority
    st.subheader("EPSS Score by Priority Level")
    
    # Box plot of EPSS by priority
    fig_epss_priority = px.box(
        df.dropna(subset=['epss_score']), 
        x='gemini_priority', 
        y='epss_score',
        color='gemini_priority',
        color_discrete_map=colors,
        title="EPSS Score Distribution by Priority",
        labels={"epss_score": "EPSS Score", "gemini_priority": "AI Priority"}
    )
    fig_epss_priority.update_layout(yaxis_range=[0, min(1.0, df['epss_score'].max() * 1.1)])
    st.plotly_chart(fig_epss_priority, use_container_width=True)
    
    # Common keywords per priority
    st.subheader("Common Vulnerability Types by Priority")
    
    # Extract keywords from descriptions
    common_keywords = [
        "remote code execution", "arbitrary code", "buffer overflow",
        "sql injection", "cross-site scripting", "xss", "authentication bypass",
        "privilege escalation", "denial of service", "information disclosure",
        "memory corruption", "cross-site request forgery", "csrf",
        "path traversal", "command injection", "file inclusion", "race condition"
    ]
    
    # Initialize counters
    keyword_counts = {
        'HIGH': Counter(),
        'MEDIUM': Counter(),
        'LOW': Counter()
    }
    
    # Count keywords by priority
    for _, row in df.iterrows():
        desc = row['description'].lower() if pd.notnull(row['description']) else ""
        priority = row['gemini_priority']
        
        if priority in keyword_counts:
            for keyword in common_keywords:
                if keyword in desc:
                    keyword_counts[priority][keyword] += 1
    
    # Create data for visualization
    keyword_data = []
    
    for priority in keyword_counts:
        for keyword, count in keyword_counts[priority].most_common(5):
            if count > 0:
                keyword_data.append({
                    'Priority': priority,
                    'Keyword': keyword,
                    'Count': count
                })
    
    if keyword_data:
        keyword_df = pd.DataFrame(keyword_data)
        
        # Create bar chart
        fig_keywords = px.bar(
            keyword_df,
            x='Keyword',
            y='Count',
            color='Priority',
            color_discrete_map=colors,
            title="Top Vulnerability Types by Priority",
            barmode='group'
        )
        st.plotly_chart(fig_keywords, use_container_width=True)
    else:
        st.info("Insufficient data for keyword analysis.")

# KEV Analysis Tab
with tab3:
    st.subheader("CISA KEV Analysis")
    
    # KEV vs Non-KEV distribution
    kev_count = df['is_in_kev'].sum()
    non_kev_count = len(df) - kev_count
    
    kev_data = pd.DataFrame({
        'Category': ['In KEV', 'Not in KEV'],
        'Count': [kev_count, non_kev_count]
    })
    
    # Create KEV distribution chart
    fig_kev = px.pie(
        kev_data,
        values='Count',
        names='Category',
        color='Category',
        color_discrete_map={'In KEV': '#ff4b4b', 'Not in KEV': '#4b9fff'},
        title="Proportion of Vulnerabilities in CISA KEV Catalog"
    )
    fig_kev.update_traces(textposition='inside', textinfo='percent+label')
    st.plotly_chart(fig_kev, use_container_width=True)
    
    # KEV vulnerabilities over time
    if 'kev_date_added' in df.columns and df['is_in_kev'].sum() > 0:
        # Filter to KEV entries
        kev_df = df[df['is_in_kev'] == True].copy()
        
        # Group by month of addition to KEV
        if not kev_df['kev_date_added'].isna().all():
            kev_df['kev_month'] = kev_df['kev_date_added'].dt.to_period('M')
            kev_monthly = kev_df.groupby('kev_month').size().reset_index(name='count')
            kev_monthly['month_start'] = kev_monthly['kev_month'].dt.start_time
            
            # Create time series chart
            fig_kev_time = px.line(
                kev_monthly,
                x='month_start',
                y='count',
                title="Monthly Additions to CISA KEV Catalog",
                markers=True
            )
            fig_kev_time.update_layout(
                xaxis_title="Month",
                yaxis_title="Number of Vulnerabilities Added",
                height=400
            )
            st.plotly_chart(fig_kev_time, use_container_width=True)
        else:
            st.info("KEV date added information is not available.")
    
    # KEV by priority
    st.subheader("KEV Status by Priority Level")
    
    # Calculate proportions
    kev_by_priority = df.groupby('gemini_priority')['is_in_kev'].agg(['sum', 'count']).reset_index()
    kev_by_priority['percentage'] = (kev_by_priority['sum'] / kev_by_priority['count'] * 100).round(1)
    
    # Create chart
    fig_kev_priority = px.bar(
        kev_by_priority,
        x='gemini_priority',
        y='percentage',
        color='gemini_priority',
        color_discrete_map=colors,
        title="Percentage of Vulnerabilities in KEV by Priority",
        labels={"gemini_priority": "AI Priority", "percentage": "% in KEV"}
    )
    fig_kev_priority.update_layout(
        yaxis_title="Percentage in KEV",
        xaxis_title="AI Priority"
    )
    st.plotly_chart(fig_kev_priority, use_container_width=True)
    
    # Time to KEV analysis if enough data
    kev_df = df[df['is_in_kev'] == True].copy()
    if not kev_df.empty and not kev_df['kev_date_added'].isna().all():
        kev_df['days_to_kev'] = (kev_df['kev_date_added'] - kev_df['published_date']).dt.days
        
        # Filter out negative values and outliers
        kev_df = kev_df[(kev_df['days_to_kev'] >= 0) & (kev_df['days_to_kev'] <= 365)]
        
        if not kev_df.empty:
            st.subheader("Time from Publication to KEV Addition")
            
            # Histogram of days to KEV
            fig_days_to_kev = px.histogram(
                kev_df,
                x='days_to_kev',
                nbins=20,
                title="Days from CVE Publication to KEV Catalog Addition",
                labels={"days_to_kev": "Days"}
            )
            fig_days_to_kev.update_layout(
                yaxis_title="Number of Vulnerabilities",
                xaxis_title="Days to KEV Addition"
            )
            st.plotly_chart(fig_days_to_kev, use_container_width=True)
            
            # Statistics
            mean_days = kev_df['days_to_kev'].mean()
            median_days = kev_df['days_to_kev'].median()
            max_days = kev_df['days_to_kev'].max()
            
            st.metric("Average Days to KEV", f"{mean_days:.1f}")
            st.metric("Median Days to KEV", f"{median_days:.1f}")
            st.metric("Maximum Days to KEV", f"{max_days:.0f}")

# Risk Distribution Tab
with tab4:
    st.subheader("Risk Score Distribution Analysis")
    
    # Overall risk score distribution
    if 'risk_score' in df.columns:
        # Create histogram of risk scores
        fig_risk_hist = px.histogram(
            df.dropna(subset=['risk_score']),
            x='risk_score',
            nbins=20,
            title="Distribution of Risk Scores",
            color_discrete_sequence=['#4b9fff']
        )
        st.plotly_chart(fig_risk_hist, use_container_width=True)
        
        # Risk score by priority
        fig_risk_priority = px.box(
            df.dropna(subset=['risk_score']),
            x='gemini_priority',
            y='risk_score',
            color='gemini_priority',
            color_discrete_map=colors,
            title="Risk Score by Priority Level",
            labels={"gemini_priority": "AI Priority", "risk_score": "Risk Score"}
        )
        st.plotly_chart(fig_risk_priority, use_container_width=True)
        
        # Risk score components
        st.subheader("Risk Score Components")
        
        # Create a scatter plot of CVSS vs EPSS
        df_scatter = df.dropna(subset=['cvss_v3_score', 'epss_score', 'risk_score'])
        
        if not df_scatter.empty:
            fig_components = px.scatter(
                df_scatter,
                x='cvss_v3_score',
                y='epss_score',
                color='risk_score',
                size='risk_score',
                hover_name='cve_id',
                color_continuous_scale=['blue', 'yellow', 'red'],
                title="Risk Score Components: CVSS vs EPSS"
            )
            fig_components.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="EPSS Score",
                height=500
            )
            st.plotly_chart(fig_components, use_container_width=True)
            
            # Add a legend/explanation
            st.info("""
            **Understanding Risk Score Components:**
            
            - **CVSS Score:** Base vulnerability severity (0-10)
            - **EPSS Score:** Probability of exploitation in the next 30 days (0-1)
            - **KEV Status:** Known to be actively exploited (yes/no)
            - **AI Analysis:** Contextual analysis of the vulnerability description
            
            These components are weighted and combined to produce the final risk score.
            """)
        else:
            st.info("Insufficient data for risk component analysis.")
    else:
        st.info("Risk score data is not available.")

# Microsoft Analysis Tab
with tab5:
    st.subheader("Microsoft Patch Tuesday Analysis")
    
    # Filter only CVEs with Microsoft data
    ms_df = df.dropna(subset=['microsoft_severity']).copy()
    
    if ms_df.empty:
        st.info("No Microsoft patch data available for the selected time period.")
    else:
        # Microsoft severity distribution
        st.subheader("Microsoft Severity Distribution")
        
        severity_counts = ms_df['microsoft_severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        
        # Define colors for severities
        ms_colors = {
            'Critical': '#ff4b4b', 
            'Important': '#ffa64b', 
            'Moderate': '#4b9fff', 
            'Low': '#4bff4b'
        }
        
        # Create the severity distribution chart
        fig_severity = px.pie(
            severity_counts, 
            values='Count', 
            names='Severity',
            color='Severity',
            color_discrete_map=ms_colors,
            title="Microsoft Severity Rating Distribution"
        )
        fig_severity.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig_severity, use_container_width=True)
        
        # Product family distribution
        st.subheader("Top Affected Microsoft Products")
        
        # Process product families (they might be comma-separated)
        all_products = []
        for products in ms_df['microsoft_product_family'].dropna():
            all_products.extend([p.strip() for p in products.split(',')])
        
        # Count occurrences
        product_counts = pd.Series(all_products).value_counts().reset_index()
        product_counts.columns = ['Product', 'Count']
        
        # Take top 10 products
        top_products = product_counts.head(10)
        
        # Create bar chart
        fig_products = px.bar(
            top_products,
            x='Product',
            y='Count',
            title="Top 10 Affected Microsoft Products",
            color='Count',
            color_continuous_scale=['lightblue', 'blue', 'darkblue']
        )
        fig_products.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig_products, use_container_width=True)
        
        # Critical vulnerabilities over time
        st.subheader("Critical Vulnerabilities Over Time")
        
        # Group by month and severity
        if 'patch_tuesday_date' in ms_df.columns:
            ms_df['patch_month'] = ms_df['patch_tuesday_date'].dt.to_period('M')
            severity_by_month = ms_df.groupby(['patch_month', 'microsoft_severity']).size().unstack(fill_value=0).reset_index()
            severity_by_month['month_start'] = severity_by_month['patch_month'].dt.start_time
            
            # Create time series chart for severity distribution
            fig_severity_time = px.line(
                severity_by_month,
                x='month_start',
                y=severity_by_month.columns[1:-1],  # All severity columns
                title="Microsoft Severity Distribution Over Time",
                markers=True,
                color_discrete_map=ms_colors
            )
            fig_severity_time.update_layout(
                xaxis_title="Month",
                yaxis_title="Number of Vulnerabilities",
                legend_title="Severity",
                height=400
            )
            st.plotly_chart(fig_severity_time, use_container_width=True)
        else:
            st.info("Patch Tuesday date information is not available.")
        
        # Critical vulnerabilities correlation with CVSS and EPSS
        st.subheader("Microsoft Severity vs. Other Metrics")
        
        # Create a box plot of CVSS by Microsoft severity
        fig_ms_cvss = px.box(
            ms_df.dropna(subset=['cvss_v3_score']),
            x='microsoft_severity',
            y='cvss_v3_score',
            color='microsoft_severity',
            color_discrete_map=ms_colors,
            title="CVSS Score Distribution by Microsoft Severity",
            category_orders={"microsoft_severity": ["Critical", "Important", "Moderate", "Low"]}
        )
        st.plotly_chart(fig_ms_cvss, use_container_width=True)
        
        # Create a box plot of EPSS by Microsoft severity
        fig_ms_epss = px.box(
            ms_df.dropna(subset=['epss_score']),
            x='microsoft_severity',
            y='epss_score',
            color='microsoft_severity',
            color_discrete_map=ms_colors,
            title="EPSS Score Distribution by Microsoft Severity",
            category_orders={"microsoft_severity": ["Critical", "Important", "Moderate", "Low"]}
        )
        st.plotly_chart(fig_ms_epss, use_container_width=True)
        
        # Microsoft severity vs AI priority comparison
        st.subheader("Microsoft Severity vs AI Priority")
        
        # Create a crosstab of Microsoft severity and Gemini priority
        ms_ai_cross = pd.crosstab(
            ms_df['microsoft_severity'], 
            ms_df['gemini_priority'],
            normalize='index'
        ).reset_index()
        
        # Melt the dataframe for plotting
        ms_ai_melted = ms_ai_cross.melt(
            id_vars=['microsoft_severity'],
            var_name='AI Priority',
            value_name='Percentage'
        )
        
        # Convert to percentage
        ms_ai_melted['Percentage'] = ms_ai_melted['Percentage'] * 100
        
        # Create the comparison chart
        fig_ms_ai = px.bar(
            ms_ai_melted,
            x='microsoft_severity',
            y='Percentage',
            color='AI Priority',
            barmode='stack',
            title="Microsoft Severity vs AI Priority Distribution",
            color_discrete_map={'HIGH': '#ff4b4b', 'MEDIUM': '#ffa64b', 'LOW': '#4bff4b'},
            category_orders={"microsoft_severity": ["Critical", "Important", "Moderate", "Low"]}
        )
        fig_ms_ai.update_layout(
            xaxis_title="Microsoft Severity",
            yaxis_title="Percentage",
            yaxis_ticksuffix="%"
        )
        st.plotly_chart(fig_ms_ai, use_container_width=True)

# Add footer with timestamp
st.markdown("---")
st.markdown(f"*Analysis generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*") 
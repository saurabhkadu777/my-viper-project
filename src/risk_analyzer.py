"""
Risk analyzer module for the VIPER CTI feed application.
Handles calculating risk scores and generating alerts based on configurable rules.
"""
import logging
from typing import Dict, List, Union, Optional, Tuple
from src.utils.config import (
    get_risk_score_weights,
    get_gemini_priority_factors,
    get_alert_rules,
    get_kev_boost_factor,
    get_microsoft_severity_factors
)

# Initialize module logger
logger = logging.getLogger(__name__)

def calculate_combined_risk_score(cve_data: Dict) -> float:
    """
    Calculates a combined risk score based on Gemini priority, CVSS score, EPSS data, CISA KEV status,
    and Microsoft severity rating.
    The score is a weighted combination of these factors, normalized to a 0-1 scale.
    
    Args:
        cve_data (Dict): Dictionary containing CVE data with gemini_priority, cvss_v3_score, 
                         epss_score, epss_percentile, is_in_kev, and microsoft_severity fields
    
    Returns:
        float: Combined risk score between 0-1, where higher values indicate higher risk
    """
    cve_id = cve_data.get('cve_id', 'Unknown')
    
    try:
        # Get weights from configuration
        weights = get_risk_score_weights()
        
        # If there are only 3 weights, use default 0 weight for Microsoft severity
        if len(weights) == 3:
            w_gemini, w_cvss, w_epss = weights
            w_ms = 0.0
        else:
            w_gemini, w_cvss, w_epss, w_ms = weights
        
        # Get priority factors for converting Gemini's text priority to a number
        priority_factors = get_gemini_priority_factors()
        
        # Extract priority from CVE data
        gemini_priority = cve_data.get('gemini_priority')
        priority_factor = priority_factors.get(gemini_priority, priority_factors.get(None))
        
        # Extract CVSS score and normalize to 0-1 scale (CVSS is on a 0-10 scale)
        cvss_score = cve_data.get('cvss_v3_score')
        if cvss_score is not None:
            cvss_normalized = min(max(float(cvss_score) / 10.0, 0.0), 1.0)
        else:
            cvss_normalized = 0.0
            logger.warning(f"Missing CVSS score for {cve_id}, using 0.0 in risk calculation")
        
        # Extract EPSS score (already on a 0-1 scale)
        epss_score = cve_data.get('epss_score')
        if epss_score is not None:
            epss_normalized = float(epss_score)
        else:
            epss_normalized = 0.0
            logger.warning(f"Missing EPSS score for {cve_id}, using 0.0 in risk calculation")
        
        # Extract Microsoft severity and convert to factor
        ms_severity = cve_data.get('microsoft_severity')
        ms_severity_factors = get_microsoft_severity_factors()
        ms_factor = ms_severity_factors.get(ms_severity, ms_severity_factors.get(None, 0.0))
        
        # Calculate weighted score
        combined_score = (
            w_gemini * priority_factor + 
            w_cvss * cvss_normalized + 
            w_epss * epss_normalized +
            w_ms * ms_factor
        )
        
        # Apply KEV boost if the CVE is in CISA KEV catalog
        is_in_kev = cve_data.get('is_in_kev', False)
        if is_in_kev:
            kev_boost = get_kev_boost_factor()
            combined_score = min(combined_score * (1 + kev_boost), 1.0)
            logger.info(f"Applied KEV boost to {cve_id}, increasing score by {kev_boost*100}%")
        
        logger.info(
            f"Risk score for {cve_id}: {combined_score:.4f} "
            f"(Gemini: {priority_factor:.2f}*{w_gemini:.2f}, "
            f"CVSS: {cvss_normalized:.2f}*{w_cvss:.2f}, "
            f"EPSS: {epss_normalized:.4f}*{w_epss:.2f}, "
            f"MS: {ms_factor:.2f}*{w_ms:.2f}, "
            f"KEV: {is_in_kev})"
        )
        
        return combined_score
    
    except Exception as e:
        logger.error(f"Error calculating risk score for {cve_id}: {str(e)}")
        return 0.0

def generate_alerts(cve_data: Dict) -> List[str]:
    """
    Generates alerts for a CVE based on configurable rules.
    
    Args:
        cve_data (Dict): Dictionary containing CVE data
    
    Returns:
        List[str]: List of alert messages if any rules are triggered, empty list otherwise
    """
    cve_id = cve_data.get('cve_id', 'Unknown')
    alerts = []
    
    try:
        # Get alert rules from configuration
        rules = get_alert_rules()
        
        # Extract necessary data from the CVE
        description = cve_data.get('description', '').lower()
        cvss_score = cve_data.get('cvss_v3_score')
        epss_score = cve_data.get('epss_score')
        gemini_priority = cve_data.get('gemini_priority')
        is_in_kev = cve_data.get('is_in_kev', False)
        kev_date_added = cve_data.get('kev_date_added')
        microsoft_severity = cve_data.get('microsoft_severity')
        ms_product = cve_data.get('microsoft_product_family')
        
        # Rule 1: Critical Exploitability Risk
        if epss_score is not None and epss_score >= rules['critical_epss']:
            alerts.append(f"CRITICAL EXPLOITABILITY: {cve_id} has a {epss_score:.2%} probability of exploitation (threshold: {rules['critical_epss']:.2%})")
        
        # Rule 2: Severe Impact & Likely Exploit
        if (cvss_score is not None and cvss_score >= rules['severe_cvss'] and 
            epss_score is not None and epss_score >= rules['severe_epss']):
            alerts.append(f"SEVERE IMPACT & LIKELY EXPLOIT: {cve_id} has a high CVSS score ({cvss_score}) and significant exploitation probability ({epss_score:.2%})")
        
        # Rule 3: High Impact Technique
        if epss_score is not None and epss_score >= rules['high_impact_epss']:
            # Check if any keywords are in the description
            for keyword in rules['high_impact_keywords']:
                if keyword in description:
                    alerts.append(f"HIGH IMPACT TECHNIQUE: {cve_id} matches keyword '{keyword}' and has significant exploitation probability ({epss_score:.2%})")
                    break
        
        # Rule 4: High Priority from Gemini
        if gemini_priority == "HIGH":
            alerts.append(f"AI FLAGGED: {cve_id} was flagged as HIGH priority by Gemini analysis")
        
        # Rule 5: CISA KEV Status
        if is_in_kev:
            added_info = f" on {kev_date_added}" if kev_date_added else ""
            alerts.append(f"KNOWN EXPLOITED: {cve_id} is in CISA's Known Exploited Vulnerabilities catalog (added{added_info})")
        
        # Rule 6: Microsoft Critical Severity
        if microsoft_severity == "Critical":
            alerts.append(f"MICROSOFT CRITICAL: {cve_id} is rated as Critical severity by Microsoft for {ms_product}")
        
        if alerts:
            logger.info(f"Generated {len(alerts)} alerts for {cve_id}")
        
        return alerts
    
    except Exception as e:
        logger.error(f"Error generating alerts for {cve_id}: {str(e)}")
        return []

def analyze_cve_risk(cve_data: Dict) -> Tuple[float, List[str]]:
    """
    Analyzes a CVE for risk scoring and alert generation.
    
    Args:
        cve_data (Dict): Dictionary containing CVE data
    
    Returns:
        Tuple[float, List[str]]: (risk_score, alerts) tuple
    """
    # Calculate combined risk score
    risk_score = calculate_combined_risk_score(cve_data)
    
    # Generate alerts
    alerts = generate_alerts(cve_data)
    
    return risk_score, alerts 
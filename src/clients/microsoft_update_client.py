"""
Microsoft Update Client module for the VIPER CTI feed application.
Handles fetching Microsoft security update information, focusing on Patch Tuesday releases.

Data source: Microsoft Security Update Guide (SUG) API
API Documentation: https://api.msrc.microsoft.com/cvrf/v2.0/swagger/index
This API provides security update information in the Common Vulnerability Reporting Framework (CVRF) format.
"""
import requests
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Union
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from src.utils.config import (
    get_msrc_api_key,
    get_retry_max_attempts,
    get_retry_wait_multiplier,
    get_retry_wait_min_seconds,
    get_retry_wait_max_seconds
)

# Initialize module logger
logger = logging.getLogger(__name__)

# Microsoft Security Update Guide API base URL
MSRC_API_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v2.0"

@retry(
    retry=retry_if_exception_type((
        requests.exceptions.Timeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.HTTPError
    )),
    wait=wait_exponential(
        multiplier=get_retry_wait_multiplier(),
        min=get_retry_wait_min_seconds(),
        max=get_retry_wait_max_seconds()
    ),
    stop=stop_after_attempt(get_retry_max_attempts()),
    before_sleep=lambda retry_state: logger.warning(
        f"Retrying MSRC API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    )
)
def _fetch_from_msrc_api(endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Helper function to fetch data from the Microsoft Security Response Center API with retry logic.
    
    Args:
        endpoint (str): API endpoint to call
        params (Dict, optional): Parameters for the API request.
        
    Returns:
        Dict: The JSON response from the API.
        
    Raises:
        requests.exceptions.HTTPError: If the HTTP request returns an unsuccessful status code.
    """
    try:
        # Get the API key if available
        api_key = get_msrc_api_key()
        headers = {
            'Accept': 'application/json',
            'api-key': api_key
        } if api_key else {'Accept': 'application/json'}
        
        url = f"{MSRC_API_BASE_URL}/{endpoint}"
        response = requests.get(url, headers=headers, params=params)
        
        # Raise for status to trigger retry on HTTP errors
        response.raise_for_status()
        
        return response.json()
    except (ValueError, KeyError) as e:
        logger.error(f"Error processing MSRC API response: {str(e)}")
        raise

def _get_patch_tuesday_date(year: int, month: int) -> datetime:
    """
    Calculate the Patch Tuesday date for a given year and month.
    Patch Tuesday is the second Tuesday of each month.
    
    Args:
        year (int): Year
        month (int): Month (1-12)
        
    Returns:
        datetime: The date of Patch Tuesday for the specified year and month
    """
    # Start with the first day of the month
    d = datetime(year, month, 1)
    
    # Find the first Tuesday
    while d.weekday() != 1:  # Tuesday is 1 in Python's datetime weekday
        d += timedelta(days=1)
    
    # Add 7 days to get to the second Tuesday
    patch_tuesday = d + timedelta(days=7)
    
    return patch_tuesday

def _find_latest_patch_tuesday() -> tuple[int, int]:
    """
    Determine the year and month of the most recent Patch Tuesday.
    
    Returns:
        tuple: (year, month) of the latest Patch Tuesday
    """
    today = datetime.now()
    
    # If we're before the second Tuesday of this month, use last month
    current_month_patch_tuesday = _get_patch_tuesday_date(today.year, today.month)
    
    if today.date() < current_month_patch_tuesday.date():
        # Use previous month
        if today.month == 1:
            # If January, go back to December of previous year
            return today.year - 1, 12
        else:
            return today.year, today.month - 1
    else:
        # We're past Patch Tuesday this month
        return today.year, today.month

def _parse_cvrf_doc(cvrf_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse a CVRF document to extract security update information for each vulnerability.
    
    Args:
        cvrf_data (Dict): CVRF document JSON data from MSRC API
        
    Returns:
        List[Dict]: List of dictionaries, each containing information about a vulnerability
    """
    try:
        vulnerabilities = []
        
        # Extract document publication date
        release_date = cvrf_data.get('DocumentPublished')
        document_title = cvrf_data.get('DocumentTitle', '')
        document_tracking_id = cvrf_data.get('DocumentTrackingID', '')
        
        # Process each vulnerability in the document
        for vuln in cvrf_data.get('Vulnerability', []):
            # Get CVE ID
            cve_id = None
            for cve in vuln.get('CVE', []):
                if cve.startswith('CVE-'):
                    cve_id = cve
                    break
            
            if not cve_id:
                logger.warning(f"Skipping vulnerability without valid CVE ID in document {document_tracking_id}")
                continue
            
            # Get title and description
            title = vuln.get('Title', {}).get('Value', 'N/A')
            description = None
            for note in vuln.get('Notes', []):
                if note.get('Type') == 'Description':
                    description = note.get('Value', 'N/A')
                    break
            
            # Get severity/impact information
            threat_info = {}
            for threat in vuln.get('Threats', []):
                if threat.get('Type') == 'Impact':
                    threat_info = threat
                    break
            
            severity = threat_info.get('Description', {}).get('Value', 'N/A')
            
            # Get affected products and productIDs
            affected_products = []
            product_families = set()
            
            for product_status in vuln.get('ProductStatuses', []):
                if product_status.get('Type') == 'Known Affected':
                    product_ids = product_status.get('ProductID', [])
                    for product_id in product_ids:
                        # Map product ID to product name
                        for product_tree in cvrf_data.get('ProductTree', {}).get('FullProductName', []):
                            if product_tree.get('ProductID') == product_id:
                                product_name = product_tree.get('Value', 'Unknown Product')
                                affected_products.append(product_name)
                                
                                # Try to extract product family from name
                                parts = product_name.split()
                                if len(parts) >= 2:
                                    family = ' '.join(parts[:2])
                                    product_families.add(family)
                                break
            
            # Extract KB article IDs or other references
            references = []
            kb_articles = []
            for ref in vuln.get('References', []):
                ref_url = ref.get('URL', '')
                ref_text = ref.get('Description', {}).get('Value', '')
                references.append({'url': ref_url, 'description': ref_text})
                
                # Extract KB article IDs from references
                if 'KB' in ref_text and 'article' in ref_text.lower():
                    # Try to extract KB article ID using common formats
                    parts = ref_text.split()
                    for part in parts:
                        if part.startswith('KB') and part[2:].isdigit():
                            kb_articles.append(part)
            
            # Create vulnerability entry
            vulnerability = {
                'cve_id': cve_id,
                'msrc_id': document_tracking_id,
                'product_family': ', '.join(product_families) if product_families else 'Unknown',
                'product_name': ', '.join(affected_products) if affected_products else 'Unknown',
                'severity': severity,
                'release_date': release_date,
                'title': title,
                'description': description,
                'references': references,
                'kb_articles': kb_articles,
                'document_title': document_title
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    except Exception as e:
        logger.error(f"Error parsing CVRF document: {str(e)}")
        return []

def fetch_patch_tuesday_data(year: int, month: int) -> Optional[List[Dict[str, Any]]]:
    """
    Fetch Microsoft security update information for a specific Patch Tuesday.
    
    Args:
        year (int): Year of the Patch Tuesday
        month (int): Month of the Patch Tuesday (1-12)
        
    Returns:
        Optional[List[Dict]]: List of dictionaries containing security update information, 
                              or None if an error occurred
    """
    try:
        logger.info(f"Fetching Microsoft security updates for {year}-{month:02d}")
        
        # Get the list of security update documents for the specified year and month
        cvrf_ids = _fetch_from_msrc_api("updates")
        
        # Convert month number to name for filtering
        month_name = datetime(year, month, 1).strftime('%B')
        
        # Filter for updates released in the target month and year
        # MSRC often uses the format "YYYY Month" in the document ID
        target_prefix = f"{year} {month_name}"
        
        # Also look for MSRC's alt format "Month YYYY"
        alt_target_prefix = f"{month_name} {year}"
        
        matching_ids = []
        for cvrf_id in cvrf_ids.get('value', []):
            if cvrf_id.startswith(target_prefix) or cvrf_id.startswith(alt_target_prefix):
                matching_ids.append(cvrf_id)
        
        if not matching_ids:
            logger.warning(f"No security updates found for {month_name} {year}")
            return []
        
        logger.info(f"Found {len(matching_ids)} security update documents for {month_name} {year}")
        
        # For each matching document, fetch the details and parse vulnerabilities
        all_vulnerabilities = []
        
        for doc_id in matching_ids:
            try:
                logger.info(f"Fetching document: {doc_id}")
                cvrf_doc = _fetch_from_msrc_api(f"cvrf/{doc_id}")
                vulnerabilities = _parse_cvrf_doc(cvrf_doc)
                logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from document {doc_id}")
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                logger.error(f"Error processing document {doc_id}: {str(e)}")
                continue
        
        logger.info(f"Fetched a total of {len(all_vulnerabilities)} vulnerabilities for {month_name} {year}")
        return all_vulnerabilities
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error fetching Microsoft security updates: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching Microsoft security updates: {str(e)}")
        return None

def fetch_latest_patch_tuesday_data() -> Optional[List[Dict[str, Any]]]:
    """
    Fetch Microsoft security update information for the latest Patch Tuesday.
    
    Returns:
        Optional[List[Dict]]: List of dictionaries containing security update information,
                              or None if an error occurred
    """
    year, month = _find_latest_patch_tuesday()
    logger.info(f"Determined latest Patch Tuesday to be in {year}-{month:02d}")
    return fetch_patch_tuesday_data(year, month) 
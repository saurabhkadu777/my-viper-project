"""
CISA KEV Client module for the VIPER CTI feed application.
Handles retrieving and processing the CISA Known Exploited Vulnerabilities (KEV) catalog.
"""
import requests
import logging
import json
from typing import List, Dict, Optional
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from src.utils.config import (
    get_retry_max_attempts,
    get_retry_wait_multiplier,
    get_retry_wait_min_seconds,
    get_retry_wait_max_seconds
)

# Initialize module logger
logger = logging.getLogger(__name__)

# CISA KEV catalog URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

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
        f"Retrying CISA KEV API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    )
)
def _fetch_from_cisa_kev_api():
    """
    Helper function to fetch data from the CISA KEV API with retry logic.
    
    Returns:
        dict: The JSON response from the API.
        
    Raises:
        requests.exceptions.HTTPError: If the HTTP request returns an unsuccessful status code.
    """
    response = requests.get(CISA_KEV_URL)
    response.raise_for_status()
    return response.json()

def fetch_kev_catalog() -> Optional[List[Dict]]:
    """
    Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog.
    
    Returns:
        Optional[List[Dict]]: A list of dictionaries containing KEV entries, or None if an error occurred.
        Each dictionary contains at least the cveID, and optionally dateAdded, vendorProject, product,
        and vulnerabilityName.
    """
    try:
        logger.info("Fetching CISA KEV catalog")
        
        # Fetch the catalog with retry logic
        kev_data = _fetch_from_cisa_kev_api()
        
        # Parse the catalog - typical structure has a 'vulnerabilities' list
        vulnerabilities = kev_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            logger.warning("No vulnerabilities found in the CISA KEV catalog")
            return []
        
        # Process each vulnerability
        kev_entries = []
        for vuln in vulnerabilities:
            try:
                # Extract required fields
                cve_id = vuln.get('cveID')
                if not cve_id:
                    logger.warning(f"Skipping KEV entry without cveID: {vuln}")
                    continue
                
                # Create entry with required and optional fields
                entry = {
                    'cve_id': cve_id,
                    'date_added': vuln.get('dateAdded'),
                    'vendor_project': vuln.get('vendorProject'),
                    'product': vuln.get('product'),
                    'vulnerability_name': vuln.get('vulnerabilityName')
                }
                
                kev_entries.append(entry)
            except Exception as e:
                logger.error(f"Error processing KEV entry {vuln}: {str(e)}")
                continue
        
        logger.info(f"Successfully processed {len(kev_entries)} KEV entries")
        return kev_entries
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching CISA KEV catalog: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing CISA KEV catalog JSON: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching CISA KEV catalog: {str(e)}")
        return None 
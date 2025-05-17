"""
EPSS Client module for the VIPER CTI feed application.
Handles retrieving Exploit Prediction Scoring System (EPSS) data from FIRST.org API.
"""
import requests
import logging
from typing import Dict, List, Union, Optional
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from src.utils.config import (
    get_retry_max_attempts,
    get_retry_wait_multiplier,
    get_retry_wait_min_seconds,
    get_retry_wait_max_seconds
)

# Initialize module logger
logger = logging.getLogger(__name__)

# EPSS API base URL from FIRST.org
EPSS_API_BASE_URL = "https://api.first.org/data/v1/epss"

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
        f"Retrying EPSS API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    )
)
def _fetch_from_epss_api(params):
    """
    Helper function to fetch data from the EPSS API with retry logic.
    
    Args:
        params (dict): Parameters for the API request.
        
    Returns:
        dict: The JSON response from the API.
        
    Raises:
        requests.exceptions.HTTPError: If the HTTP request returns an unsuccessful status code.
    """
    response = requests.get(EPSS_API_BASE_URL, params=params)
    response.raise_for_status()
    return response.json()

def get_epss_score(cve_id: str) -> Optional[Dict[str, float]]:
    """
    Retrieves the EPSS score and percentile for a specific CVE.
    
    Args:
        cve_id (str): The CVE ID to look up (e.g., "CVE-2023-12345").
        
    Returns:
        Optional[Dict[str, float]]: A dictionary containing 'epss' (probability) and 'percentile' values if found,
                         or None if not found or an error occurred.
                         Example: {'epss': 0.75, 'percentile': 0.95}
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        logger.error(f"Invalid CVE ID format: {cve_id}")
        return None
    
    try:
        logger.info(f"Fetching EPSS score for {cve_id}")
        
        # Set up parameters for the EPSS API request
        params = {
            "cve": cve_id,
            "pretty": "false"
        }
        
        # Make the API request with retry logic
        response_data = _fetch_from_epss_api(params)
        
        # Process the response
        if response_data.get("status") == "OK" and response_data.get("data"):
            # EPSS API returns scores as strings, convert to float
            cve_data = response_data["data"][0]
            if "epss" in cve_data and "percentile" in cve_data:
                result = {
                    "epss": float(cve_data["epss"]),
                    "percentile": float(cve_data["percentile"])
                }
                logger.info(f"EPSS data for {cve_id}: score={result['epss']:.4f}, percentile={result['percentile']:.4f}")
                return result
        
        logger.warning(f"No EPSS data found for {cve_id}")
        return None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching EPSS data for {cve_id}: {str(e)}")
        return None
    except (ValueError, KeyError, IndexError) as e:
        logger.error(f"Error parsing EPSS data for {cve_id}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching EPSS data for {cve_id}: {str(e)}")
        return None

def get_epss_scores_batch(cve_ids: List[str]) -> Dict[str, Optional[Dict[str, float]]]:
    """
    Retrieves EPSS scores for multiple CVEs in a single batch request.
    
    Args:
        cve_ids (List[str]): List of CVE IDs to look up.
        
    Returns:
        Dict[str, Optional[Dict[str, float]]]: Dictionary mapping each CVE ID to its score data 
                                    (or None if not found/error).
                                    Example: {'CVE-2023-12345': {'epss': 0.75, 'percentile': 0.95},
                                              'CVE-2023-67890': None}
    """
    if not cve_ids:
        logger.warning("Empty list of CVE IDs provided")
        return {}
    
    # Filter out invalid CVE IDs
    valid_cve_ids = [cve_id for cve_id in cve_ids if cve_id and cve_id.startswith("CVE-")]
    if not valid_cve_ids:
        logger.error("No valid CVE IDs in the provided list")
        return {cve_id: None for cve_id in cve_ids}
    
    # Initialize result dictionary with None for all CVEs
    result = {cve_id: None for cve_id in cve_ids}
    
    try:
        logger.info(f"Fetching EPSS scores for {len(valid_cve_ids)} CVEs in batch")
        
        # EPSS API accepts comma-separated CVE IDs
        # The API has a limit of 2000 characters for the cve parameter
        # We'll split into chunks if needed to avoid exceeding this limit
        
        # Prepare the CVE IDs as comma-separated string
        cve_param = ",".join(valid_cve_ids)
        
        # If the parameter is too long, we need to make multiple requests
        if len(cve_param) > 1900:  # Allow some buffer below the 2000 char limit
            logger.info("CVE list too long, splitting into multiple requests")
            
            # Calculate roughly how many CVEs we can include per request
            avg_cve_length = len(cve_param) / len(valid_cve_ids)
            cves_per_batch = int(1900 / (avg_cve_length + 1))  # +1 for the comma
            
            # Process CVEs in batches
            for i in range(0, len(valid_cve_ids), cves_per_batch):
                batch = valid_cve_ids[i:i+cves_per_batch]
                batch_results = get_epss_scores_batch(batch)
                result.update(batch_results)
            
            return result
        
        # Set up parameters for the EPSS API request
        params = {
            "cve": cve_param,
            "pretty": "false"
        }
        
        # Make the API request with retry logic
        response_data = _fetch_from_epss_api(params)
        
        # Process the response
        if response_data.get("status") == "OK" and response_data.get("data"):
            for cve_data in response_data["data"]:
                cve_id = cve_data.get("cve")
                if cve_id and "epss" in cve_data and "percentile" in cve_data:
                    result[cve_id] = {
                        "epss": float(cve_data["epss"]),
                        "percentile": float(cve_data["percentile"])
                    }
        
        # Log stats on how many CVEs were found
        found_count = sum(1 for v in result.values() if v is not None)
        logger.info(f"Found EPSS data for {found_count} out of {len(cve_ids)} CVEs")
        
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching batch EPSS data: {str(e)}")
        return result
    except Exception as e:
        logger.error(f"Unexpected error fetching batch EPSS data: {str(e)}")
        return result 
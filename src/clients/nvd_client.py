"""
NVD Client module for the VIPER CTI feed application.
Handles fetching CVE data from the National Vulnerability Database API.
"""
import requests
import logging
from datetime import datetime, timedelta, timezone
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from src.utils.config import (
    get_nvd_api_base_url,
    get_nvd_results_per_page,
    get_nvd_pagination_delay,
    get_retry_max_attempts,
    get_retry_wait_multiplier,
    get_retry_wait_min_seconds,
    get_retry_wait_max_seconds
)

# Initialize module logger
logger = logging.getLogger(__name__)

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
        f"Retrying NVD API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    )
)
def _fetch_from_nvd_api(params):
    """
    Fetches data from the NVD API with retry logic.
    
    Args:
        params (dict): Parameters for the API request.
        
    Returns:
        dict: The JSON response from the API.
        
    Raises:
        requests.exceptions.HTTPError: If the HTTP request returns an unsuccessful status code.
    """
    response = requests.get(get_nvd_api_base_url(), params=params)
    
    # Raise for status to trigger retry on HTTP errors
    response.raise_for_status()
    
    return response.json()

def fetch_recent_cves(days_published_ago=None):
    """
    Fetches CVEs published within the specified number of days up to the current time.
    
    Args:
        days_published_ago (int, optional): Number of days to look back for CVEs.
            If None, uses the value from configuration.
        
    Returns:
        list: A list of dictionaries containing CVE data.
    """
    try:
        # Use configuration value if not specified
        if days_published_ago is None:
            from src.utils.config import get_nvd_days_published_ago
            days_published_ago = get_nvd_days_published_ago()
            
        # Calculate the start and end dates for the query
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days_published_ago)
        
        # Format dates as per NVD API requirements (YYYY-MM-DDTHH:MM:SSZ)
        start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Parameters for the NVD API request
        params = {
            "pubStartDate": start_date_str,
            "pubEndDate": end_date_str,
            "resultsPerPage": get_nvd_results_per_page()
        }
        
        logger.info(f"Fetching CVEs published between {start_date_str} and {end_date_str}")
        
        # Use the retry-enabled function to fetch data
        data = _fetch_from_nvd_api(params)
        
        # totalResults check (useful for pagination in the future)
        total_results = data.get("totalResults", 0)
        logger.info(f"NVD API reported {total_results} total matching CVEs for the period.")

        vulnerabilities = data.get("vulnerabilities", [])
        
        processed_cves = []
        for cve_entry in vulnerabilities:
            try:
                cve = cve_entry.get("cve", {})
                cve_id = cve.get("id")
                
                description = ""
                for desc_entry in cve.get("descriptions", []):
                    if desc_entry.get("lang") == "en":
                        description = desc_entry.get("value")
                        break
                
                cvss_v3_score = None
                metrics = cve.get("metrics", {})
                # Check both cvssMetricV31 and cvssMetricV30
                cvss_v3_metrics_list = metrics.get("cvssMetricV31", []) 
                if not cvss_v3_metrics_list:
                    cvss_v3_metrics_list = metrics.get("cvssMetricV30", [])

                if cvss_v3_metrics_list:
                    cvss_v3_score = cvss_v3_metrics_list[0].get("cvssData", {}).get("baseScore")
                
                published_date = cve.get("published")
                
                if cve_id and description:
                    processed_cves.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_v3_score": cvss_v3_score,
                        "published_date": published_date
                    })
                else:
                    logger.warning(f"Skipping CVE due to missing ID or description: {cve_entry}")
            except Exception as e:
                logger.error(f"Error processing individual CVE entry {cve_entry.get('cve', {}).get('id', 'UNKNOWN_ID')}: {str(e)}")
                continue
        
        logger.info(f"Successfully processed {len(processed_cves)} CVEs from the current API response page.")
        return processed_cves
    
    except requests.exceptions.RequestException as e:
        logger.critical(f"Critical error fetching data from NVD API after retries: {str(e)}")
        return []
    except Exception as e:
        logger.critical(f"Unexpected critical error in fetch_recent_cves: {str(e)}")
        return []

"""
Microsoft Update Client module for the VIPER CTI feed application.
Handles fetching Microsoft security update information, focusing on Patch Tuesday releases.

Data source: Microsoft Security Update Guide (SUG) API
API Documentation: https://api.msrc.microsoft.com/cvrf/v2.0/swagger/index
This API provides security update information in the Common Vulnerability Reporting Framework (CVRF) format.
"""
import json
import logging
import traceback
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from src.utils.config import (
    get_msrc_api_key,
    get_retry_max_attempts,
    get_retry_wait_max_seconds,
    get_retry_wait_min_seconds,
    get_retry_wait_multiplier,
)

# Initialize module logger
logger = logging.getLogger(__name__)

# Microsoft Security Update Guide API base URLs
# Use v2.0 API for CVRF documents as it's confirmed working
MSRC_API_BASE_URL_V2 = "https://api.msrc.microsoft.com/cvrf/v2.0/"
# Use v3.0 API for updates listing (both v2.0 and v3.0 work for this)
MSRC_API_BASE_URL_V3 = "https://api.msrc.microsoft.com/cvrf/v3.0/"


@retry(
    retry=retry_if_exception_type(
        (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        )
    ),
    wait=wait_exponential(
        multiplier=get_retry_wait_multiplier(),
        min=get_retry_wait_min_seconds(),
        max=get_retry_wait_max_seconds(),
    ),
    stop=stop_after_attempt(get_retry_max_attempts()),
    before_sleep=lambda retry_state: logger.warning(
        f"Retrying MSRC API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    ),
)
def _fetch_from_msrc_api(endpoint: str, use_v3: bool = False, params: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Helper function to fetch data from the Microsoft Security Response Center API with retry logic.

    Args:
        endpoint (str): API endpoint to call
        use_v3 (bool): Whether to use the v3 API (defaults to v2 which is known to work for CVRF docs)
        params (Dict, optional): Parameters for the API request.

    Returns:
        Dict: The JSON response from the API.

    Raises:
        requests.exceptions.HTTPError: If the HTTP request returns an unsuccessful status code.
    """
    try:
        # Get the API key if available
        api_key = get_msrc_api_key()
        headers = {"Accept": "application/json", "api-key": api_key} if api_key else {"Accept": "application/json"}

        # Select the appropriate base URL based on the endpoint and version flag
        base_url = MSRC_API_BASE_URL_V3 if use_v3 else MSRC_API_BASE_URL_V2
        url = f"{base_url}/{endpoint}"

        logger.debug(f"Making API request to: {url} with params: {params}")

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
        release_date = cvrf_data.get("DocumentPublished")

        # Extract document title
        document_title = None
        if isinstance(cvrf_data.get("DocumentTitle"), dict):
            document_title = cvrf_data.get("DocumentTitle", {}).get("Value", "")
        else:
            document_title = cvrf_data.get("DocumentTitle", "")

        # Extract document tracking ID
        document_tracking = cvrf_data.get("DocumentTracking", {})
        document_tracking_id = (
            document_tracking.get("Identification", {}).get("ID", "") if isinstance(document_tracking, dict) else ""
        )

        if not document_tracking_id:
            document_tracking_id = cvrf_data.get("DocumentTrackingID", "")

        # Get product tree for mapping product IDs to names
        product_tree = cvrf_data.get("ProductTree", {})
        product_id_map = {}

        if product_tree:
            for product in product_tree.get("FullProductName", []):
                product_id = product.get("ProductID")
                product_name = product.get("Value")
                if product_id and product_name:
                    product_id_map[product_id] = product_name

        # Process each vulnerability in the document
        for vuln in cvrf_data.get("Vulnerability", []):
            # Get CVE ID - in v2.0 API it can be a direct string instead of an array
            cve_id = None
            if "CVE" in vuln:
                cve_value = vuln.get("CVE")
                if isinstance(cve_value, str) and cve_value.startswith("CVE-"):
                    cve_id = cve_value
                elif isinstance(cve_value, list):
                    for cve in cve_value:
                        if isinstance(cve, str) and cve.startswith("CVE-"):
                            cve_id = cve
                            break

            if not cve_id:
                logger.warning(f"Skipping vulnerability without valid CVE ID in document {document_tracking_id}")
                continue

            # Get title
            title = None
            if isinstance(vuln.get("Title"), dict):
                title = vuln.get("Title", {}).get("Value", "N/A")
            else:
                title = vuln.get("Title", "N/A")

            # Get description from Notes
            description = None
            for note in vuln.get("Notes", []):
                note_type = note.get("Type")
                # Type 2 = Description in v2.0 API
                if (note_type == "Description" or note_type == 2) and "Value" in note:
                    description = note.get("Value", "N/A")
                    break
                elif note.get("Title") == "Description":
                    if "Value" in note:
                        description = note.get("Value", "N/A")
                    break

            # If no description was found, try looking for Title = Description
            if not description:
                for note in vuln.get("Notes", []):
                    if note.get("Title") == "Description":
                        description = note.get("Value", "N/A")
                        break

            # Get severity/impact information
            severity = "N/A"
            for threat in vuln.get("Threats", []):
                # Type 0 = Impact in v2.0 API
                if threat.get("Type") == 0 or threat.get("Type") == "Impact":
                    threat_desc = threat.get("Description")
                    if isinstance(threat_desc, dict):
                        severity = threat_desc.get("Value", "N/A")
                    else:
                        severity = threat_desc if threat_desc else "N/A"
                    break

            # Get affected products and productIDs
            affected_products = []
            product_families = set()

            for product_status in vuln.get("ProductStatuses", []):
                # Type 3 = Known Affected in v2.0 API
                if product_status.get("Type") == 3 or product_status.get("Type") == "Known Affected":
                    product_ids = product_status.get("ProductID", [])
                    for product_id in product_ids:
                        # Look up product name from our map
                        if product_id in product_id_map:
                            product_name = product_id_map[product_id]
                            affected_products.append(product_name)

                            # Try to extract product family from name
                            parts = product_name.split()
                            if len(parts) >= 2:
                                family = " ".join(parts[:2])
                                product_families.add(family)

            # Extract KB article IDs or other references
            references = []
            kb_articles = []

            for ref in vuln.get("References", []):
                ref_url = ref.get("URL", "")
                ref_desc = ref.get("Description")

                ref_text = None
                if isinstance(ref_desc, dict):
                    ref_text = ref_desc.get("Value", "")
                else:
                    ref_text = ref_desc if ref_desc else ""

                references.append({"url": ref_url, "description": ref_text})

                # Extract KB article IDs from references
                if ref_text and "KB" in ref_text and "article" in ref_text.lower():
                    # Try to extract KB article ID using common formats
                    parts = ref_text.split()
                    for part in parts:
                        if part.startswith("KB") and part[2:].isdigit():
                            kb_articles.append(part)

            # Create vulnerability entry
            vulnerability = {
                "cve_id": cve_id,
                "msrc_id": document_tracking_id,
                "product_family": ", ".join(product_families) if product_families else "Unknown",
                "product_name": ", ".join(affected_products) if affected_products else "Unknown",
                "severity": severity,
                "release_date": release_date,
                "title": title,
                "description": description,
                "references": references,
                "kb_articles": kb_articles,
                "document_title": document_title,
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

        # Format the document ID in the expected format for MSRC API (YYYY-MMM)
        month_name = datetime(year, month, 1).strftime("%b")
        doc_id = f"{year}-{month_name}"

        logger.info(f"Fetching CVRF document with ID: {doc_id}")

        try:
            # First try to get the specific CVRF document by ID (using v2.0 API which we know works)
            cvrf_doc = _fetch_from_msrc_api(f"cvrf/{doc_id}")

            # Parse the CVRF document to extract vulnerabilities
            vulnerabilities = _parse_cvrf_doc(cvrf_doc)
            logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from CVRF document {doc_id}")

            return vulnerabilities
        except requests.exceptions.HTTPError as e:
            # If we couldn't get the document directly, try to list all updates first
            logger.warning(
                f"Direct CVRF document fetch failed: {str(e)}. Trying to find document ID from updates list."
            )

            # Calculate date range for filtering updates
            start_date = datetime(year, month, 1)
            if month == 12:
                end_date = datetime(year + 1, 1, 1)
            else:
                end_date = datetime(year, month + 1, 1)

            # Format dates for OData filter
            start_date_str = start_date.strftime("%Y-%m-%dT00:00:00Z")
            end_date_str = end_date.strftime("%Y-%m-%dT00:00:00Z")

            # Use OData filtering to get updates only for the specified month
            odata_filter = f"InitialReleaseDate ge {start_date_str} and InitialReleaseDate lt {end_date_str}"

            # Get the list of security updates for the specified date range (using v3.0 API)
            update_params = {"$filter": odata_filter}
            update_response = _fetch_from_msrc_api("Updates", use_v3=True, params=update_params)
            updates = update_response.get("value", [])

            if not updates:
                logger.warning(f"No security updates found for {year}-{month:02d}")
                return []

            logger.info(f"Found {len(updates)} security update documents for {year}-{month:02d}")

            # For each update, fetch the CVRF document and parse vulnerabilities
            all_vulnerabilities = []

            for update in updates:
                try:
                    update_id = update.get("ID")
                    if not update_id:
                        logger.warning(f"Skipping update without ID: {update}")
                        continue

                    logger.info(f"Fetching CVRF document: {update_id}")
                    # Use v2.0 API for CVRF documents
                    cvrf_doc = _fetch_from_msrc_api(f"cvrf/{update_id}")
                    vulnerabilities = _parse_cvrf_doc(cvrf_doc)
                    logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from document {update_id}")
                    all_vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    logger.error(f"Error processing document {update.get('ID', 'Unknown')}: {str(e)}")
                    continue

            logger.info(f"Fetched a total of {len(all_vulnerabilities)} vulnerabilities for {year}-{month:02d}")
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


# Simple test function to verify API connectivity
if __name__ == "__main__":
    # Configure basic logging
    logging.basicConfig(level=logging.INFO)

    print("Testing Microsoft Update Client with MSRC API")
    print(f"Using CVRF API v2.0: {MSRC_API_BASE_URL_V2}")
    print(f"Using Updates API v3.0: {MSRC_API_BASE_URL_V3}")

    # Test 1: Test with a known date range
    test_year, test_month = 2023, 4  # April 2023

    try:
        print("\n=== TEST 1: Fetch specific month data ===")
        # Format the document ID properly for MSRC API
        month_name = datetime(test_year, test_month, 1).strftime("%b")
        doc_id = f"{test_year}-{month_name}"

        print(f"Testing fetch for {test_year}-{test_month:02d} (April 2023)")
        print(f"Using document ID format: {doc_id}")

        # Try direct document access first (v2.0 API)
        print(f"\nStep 1: Directly fetching CVRF document with ID: {doc_id}")
        try:
            cvrf_doc = _fetch_from_msrc_api(f"cvrf/{doc_id}")
            print(f"Successfully fetched CVRF document {doc_id}")

            if isinstance(cvrf_doc.get("DocumentTitle"), dict):
                print(f"Document title: {cvrf_doc.get('DocumentTitle', {}).get('Value', 'Unknown')}")
            else:
                print(f"Document title: {cvrf_doc.get('DocumentTitle', 'Unknown')}")

            print(f"Published: {cvrf_doc.get('DocumentPublished', 'Unknown')}")

            # Parse the document using our function
            print("\nStep 2: Parsing CVRF document for vulnerabilities")
            vulnerabilities = _parse_cvrf_doc(cvrf_doc)
            print(f"Found {len(vulnerabilities)} vulnerabilities in document")

            # Print info for first 3 vulnerabilities
            for i, vuln in enumerate(vulnerabilities[:3]):
                print(f"\nVulnerability {i+1}:")
                print(f"  CVE ID: {vuln.get('cve_id')}")
                print(f"  Severity: {vuln.get('severity')}")
                print(f"  Product Family: {vuln.get('product_family')}")

        except Exception as e:
            print(f"Error fetching or parsing CVRF document: {str(e)}")
            traceback.print_exc()

            # Try the updates listing workflow as alternative (v3.0 API)
            print("\nStep 3: Trying updates listing workflow instead")

            # Calculate date range
            start_date = datetime(test_year, test_month, 1)
            if test_month == 12:
                end_date = datetime(test_year + 1, 1, 1)
            else:
                end_date = datetime(test_year, test_month + 1, 1)

            # Format dates for OData filter
            start_date_str = start_date.strftime("%Y-%m-%dT00:00:00Z")
            end_date_str = end_date.strftime("%Y-%m-%dT00:00:00Z")
            odata_filter = f"InitialReleaseDate ge {start_date_str} and InitialReleaseDate lt {end_date_str}"

            print(f"Using OData filter: {odata_filter}")
            update_params = {"$filter": odata_filter}

            # Use v3.0 API for updates listing
            update_response = _fetch_from_msrc_api("Updates", use_v3=True, params=update_params)
            updates = update_response.get("value", [])

            print(f"Found {len(updates)} updates for {test_year}-{test_month:02d}")

            # Display first few updates
            for i, update in enumerate(updates[:3]):
                print(f"Update {i+1}:")
                print(f"  ID: {update.get('ID')}")
                print(f"  Title: {update.get('Title')}")
                print(f"  Initial Release Date: {update.get('InitialReleaseDate')}")

        # Test 2: Test the main function to fetch latest Patch Tuesday data
        print("\n=== TEST 2: Fetch latest Patch Tuesday data ===")
        print("Calling fetch_latest_patch_tuesday_data()...")

        latest_year, latest_month = _find_latest_patch_tuesday()
        print(f"Latest Patch Tuesday determined to be: {latest_year}-{latest_month:02d}")

        latest_vulns = fetch_latest_patch_tuesday_data()

        if latest_vulns:
            print(f"Successfully fetched {len(latest_vulns)} vulnerabilities for latest Patch Tuesday")

            # Print info for first 3 vulnerabilities from latest patch Tuesday
            for i, vuln in enumerate(latest_vulns[:3]):
                print(f"\nLatest Patch Tuesday Vulnerability {i+1}:")
                print(f"  CVE ID: {vuln.get('cve_id')}")
                print(f"  Severity: {vuln.get('severity')}")
                print(f"  Product Family: {vuln.get('product_family')}")
        else:
            print("Failed to fetch vulnerabilities for latest Patch Tuesday or none were found")

    except Exception as e:
        print(f"Error during testing: {str(e)}")
        traceback.print_exc()

    print("\nTest completed")

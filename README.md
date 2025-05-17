# 🛡️ VIPER - Vulnerability Intelligence, Prioritization, and Exploitation Reporter

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**VIPER is your AI-powered co-pilot in the complex world of cyber threats, designed to provide actionable Vulnerability Intelligence, Prioritization, and Exploitation Reporting.**

In an era of ever-increasing cyber threats, VIPER cuts through the noise. It ingests data from critical sources like NVD, EPSS, and the CISA KEV catalog, then leverages Google Gemini AI for deep contextual analysis and vulnerability prioritization. All this intelligence is centralized, enriched, and presented through an interactive Streamlit dashboard, empowering security teams to focus on what truly matters and remediate effectively.
## 📋 Table of Contents

1.  [🎯 Screenhots](#-main-dashboard)
2.  [✨ Core Features](#-core-features)
3.  [🛠️ Live CVE Lookup](#-live-cve-lookup)
4.  [🛠️ Technology Stack](#-tech-stack)
5.  [🚀 Installation & Setup](#-installation--setup)
6.  [⚙️ Usage](#-usage)
7.  [📈 Development Status & Roadmap](#-project-roadmap--future-vision)

---
## Dashboard

VIPER provides a comprehensive dashboard for visualizing and analyzing vulnerability data:

### Home Screen
![Home](https://i.imgur.com/5Ri40Oc.png)

### Main Dashboard
![Dashboard](https://i.imgur.com/yT3PKpU.png)

### Detailed Analysis View
![Detailed Analysis](https://i.imgur.com/YnYxObv.png)

### Live CVE Lookup
![Live CVE Lookup](https://i.imgur.com/l4hPoW8.png)

### Analytics & Trends
![Analytics](https://i.imgur.com/uWX0Y2g.png)


## ✨ Core Features

* **Multi-Source Data Ingestion:**
    * ✅ **NVD (National Vulnerability Database):** Up-to-the-minute CVE information.
    * ✅ **EPSS (Exploit Prediction Scoring System):** Likelihood sıcaklık of vulnerability exploitation.
    * ✅ **CISA KEV (Known Exploited Vulnerabilities) Catalog:** Confirmed actively exploited vulnerabilities.
    * ✅ **Microsoft Patch Tuesday Updates:** Security bulletins and patch information.
* **AI-Powered Analysis & Prioritization:**
    * 🧠 Deep contextual analysis of CVE descriptions and related data using **Google Gemini AI**.
    * Automated priority assignment (HIGH, MEDIUM, LOW) based on AI assessment.
* **Comprehensive Risk Scoring:**
    * 📈 Customizable weighted risk scoring combining CVSS, EPSS, KEV status, Microsoft severity, and Gemini AI analysis.
    * Configurable boost factor for vulnerabilities present in the CISA KEV catalog.
* **Automated Alert Generation:**
    * 🔔 Configurable rules engine to generate alerts for critical vulnerabilities based on EPSS scores, CVSS & EPSS combinations, keyword matches, KEV status, and AI-assigned priority.
* **Centralized & Enriched Data Storage:**
    * 🗄️ SQLite database for all collected and enriched vulnerability intelligence.
    * Mechanisms to prevent duplicate data processing and storage.
* **Interactive Streamlit Dashboard:**
    * 🖥️ User-friendly web interface for data exploration and analysis.
    * Advanced filtering (date range, priority, CVSS, EPSS, KEV status, keywords).
    * Key Performance Indicator (KPI) metrics and summary statistics.
    * Detailed CVE views with all enriched data points.
    * Trend analysis and visualizations powered by Plotly.
    * 🔎 **Live CVE Lookup:** Real-time search and analysis of any CVE from NVD.
* **Resilient API Clients:**
    * 💪 Automated retry mechanisms with exponential backoff for API calls (`tenacity` library).
* **Flexible Configuration:**
    * ⚙️ Easy management of all critical parameters (API keys, model names, thresholds, weights) via a `.env` file.
* **Modular and Extensible Architecture:**
    * 🏗️ Designed for straightforward integration of new data sources and analysis modules.
* **Dual Operation Modes:**
    * 💻 **CLI Mode:** For backend data processing, fetching, and analysis.
    * 📊 **Dashboard Mode:** For interactive visualization and reporting.

## 🔍 Live CVE Lookup

The Live CVE Lookup feature allows you to perform real-time analysis of any CVE:

* **Instant CVE Lookups:** Enter any CVE ID to get comprehensive details.
* **Local Database First:** Checks your local database before making external API calls.
* **Dynamic Data Enrichment:**
  * NVD data with descriptions, CVSS scores, references, and affected products
  * EPSS exploitation probability scores
  * CISA KEV status verification
  * Live Gemini AI analysis and priority assignment
  * Real-time risk scoring and alert generation
* **Save to Database:** Option to save or update the analyzed CVE in your local database for future reference.

This feature is ideal for:
* Investigating breaking vulnerabilities as they're published
* Ad-hoc analysis of CVEs mentioned in threat reports
* Quick verification of vulnerability details during incident response

## 🚀 Tech Stack

* **Backend & Analysis:** Python
* **AI Model:** Google Gemini
* **Web Interface/Dashboard:** Streamlit
* **Database:** SQLite
* **API Clients:** `requests`, `google-generativeai`
* **Data Manipulation:** Pandas, NumPy
* **Visualization:** Plotly
* **Error Handling & Retries:** `tenacity`
* **Configuration:** `python-dotenv`
* **Logging:** `logging`

## 🛠️ Installation & Setup

1.  **Clone the Repository:**
    ```bash
    git clone git@github.com:ozanunal0/viper.git
    cd viper
    ```

2.  **Create and Activate a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    # On Linux/macOS:
    source venv/bin/activate
    # On Windows:
    # venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure API Keys and Settings:**
    * Copy the example environment file:
        ```bash
        cp .env.example .env
        ```
    * Open the `.env` file in a text editor and add your **Google Gemini API Key** to the `GEMINI_API_KEY` variable.
        ```dotenv
        GEMINI_API_KEY=AIzaSyYOUR_ACTUAL_GEMINI_KEY_HERE
        # Review and optionally modify other settings in this file as needed.
        ```

## ⚙️ Usage

VIPER can be operated in two primary modes:

### 1. Command Line Interface (CLI)

Use the CLI to fetch, process, and analyze vulnerability data. The results (high/medium priority CVEs and alerts) will be printed to the console.

```bash
python main.py cli --days <NUMBER_OF_DAYS>
```

### Dashboard

Launch the Streamlit dashboard:
```
python main.py dashboard
```
Or directly with:
```
./scripts/run_dashboard.sh
```

The dashboard provides:
- Interactive filtering of vulnerabilities
- Visualizations of vulnerability distributions
- Detailed analysis of individual CVEs
- Risk scoring and alert information
- CISA KEV catalog integration
- Microsoft Patch Tuesday analysis
- Live CVE lookup and real-time analysis

## Project Structure

```
viper/
├── main.py                  # Main entry point script
├── requirements.txt         # Project dependencies
├── README.md                # Project documentation
├── .gitignore               # Git ignore file
├── data/                    # Data storage directory
│   └── threat_intel_gemini_mvp.db  # SQLite database
├── logs/                    # Log files directory
│   └── viper.log            # Application logs
├── scripts/                 # Utility scripts
│   └── run_dashboard.sh     # Script to run the dashboard
├── src/                     # Source code
│   ├── clients/             # API clients
│   │   ├── cisa_kev_client.py        # CISA KEV API client
│   │   ├── epss_client.py            # EPSS API client
│   │   ├── nvd_client.py             # NVD API client
│   │   └── microsoft_update_client.py # Microsoft Patch Tuesday API client
│   ├── dashboard/           # Dashboard application
│   │   ├── app.py              # Main dashboard app
│   │   └── pages/              # Dashboard pages
│   │       ├── 01_Dashboard.py           # Main dashboard page
│   │       ├── 02_Detailed_Analysis.py   # Detailed CVE analysis page
│   │       ├── 03_Live_CVE_Lookup.py     # Live CVE lookup and analysis
│   │       └── 04_Analytics.py           # Analytics and trends page
│   ├── utils/               # Utility modules
│   │   ├── config.py            # Configuration management
│   │   └── database_handler.py  # Database operations
│   ├── gemini_analyzer.py   # Gemini AI analysis
│   ├── main_mvp.py          # CLI application logic
│   └── risk_analyzer.py     # Risk scoring and alerts
```

## Risk Scoring

VIPER calculates a combined risk score for each vulnerability using:
- Gemini AI priority assessment (HIGH, MEDIUM, LOW)
- CVSS v3 score (0-10 scale)
- EPSS score (probability of exploitation)
- CISA KEV status (with a customizable boost factor)
- Microsoft severity rating (Critical, Important, Moderate, Low)

The weights for each factor can be configured via environment variables:
- `RISK_WEIGHT_GEMINI` (default: 0.4)
- `RISK_WEIGHT_CVSS` (default: 0.3)
- `RISK_WEIGHT_EPSS` (default: 0.3)
- `RISK_WEIGHT_MS_SEVERITY` (default: 0.2)
- `KEV_BOOST_FACTOR` (default: 0.5)

## Alert Generation

VIPER generates alerts based on configurable rules:
1. Critical Exploitability Risk - CVEs with very high EPSS scores
2. Severe Impact & Likely Exploit - High CVSS score combined with significant EPSS score
3. High Impact Technique - CVEs matching specific keywords with substantial EPSS scores
4. AI Flagged - CVEs rated as HIGH priority by Gemini AI
5. CISA KEV Status - CVEs in the CISA Known Exploited Vulnerabilities catalog
6. Microsoft Critical - CVEs rated as Critical severity by Microsoft

Alert thresholds can be configured via environment variables (see config.py).

## API Integration

### NVD API
VIPER integrates with the National Vulnerability Database API to:
- Fetch recent CVEs based on specified time periods
- Look up detailed information for specific CVEs
- Extract CVSS scores, descriptions, and affected products

### EPSS API
Integration with the FIRST.org EPSS API provides:
- Probability scores for vulnerability exploitation
- Percentile ranking for exploitation likelihood
- Both batch and single-CVE lookup capabilities

### CISA KEV API
Integration with the CISA Known Exploited Vulnerabilities catalog provides:
- Status checks for whether CVEs are actively exploited
- Dates when vulnerabilities were added to the KEV catalog
- Vendor and product information when available

### Microsoft Security Update API
Integration with the Microsoft Security Response Center (MSRC) API provides:
- Patch Tuesday update information
- Security bulletin details
- Microsoft-specific vulnerability information and severity ratings

## Dependencies

- `requests` - For making HTTP requests to the NVD, EPSS, CISA, and Microsoft APIs
- `python-dotenv` - For loading environment variables from .env file
- `google-generativeai` - For interacting with the Google Gemini API
- `tenacity` - For robust error handling and retry logic
- `streamlit` - For the interactive dashboard
- `pandas` - For data manipulation
- `plotly` - For interactive visualizations
- `numpy` - For numerical operations


## 🗺️ Project Roadmap & Future Vision

VIPER aims to be a comprehensive, AI-driven Cyber Threat Intelligence (CTI) platform, drawing inspiration from advanced, multi-layered CTI systems. Our current version provides a strong foundation with NVD, EPSS, CISA KEV, and Microsoft MSRC data ingestion, coupled with Gemini AI for analysis, risk scoring, and an interactive Streamlit dashboard with real-time CVE lookup.

Here's where we're headed:

### Phase 1: Core Enhancements & Data Completeness (Immediate Focus)

* **Full NVD API Pagination:** Ensure complete ingestion of all relevant CVEs from NVD by implementing robust pagination in `nvd_client.py` to handle large result sets (addressing current partial data fetching ).
* **Solidify Retry Mechanisms:** Continuously refine and test `tenacity` based retry logic across all external API clients (`nvd_client.py`, `epss_client.py`, `cisa_kev_client.py`, `microsoft_update_client.py`, `gemini_analyzer.py`) for maximum resilience.
* **Dashboard Usability & Features:**
    * Refine real-time CVE lookup: Optimize display and ensure all enrichment (EPSS, KEV, MSData, Gemini re-analysis) is available for live queries.
    * Enhance filtering and sorting options on all data tables.
    * Implement detailed CVE view modals or dedicated pages for better readability of all enriched data.
* **Automated Periodic Execution:** Integrate `APScheduler` or configure system `cron` jobs to run the `main_mvp.py` data pipeline automatically at configurable intervals.

### Phase 2: Expanding Data Ingestion & Enrichment

* **[ ] MalwareBazaar Integration:**
    * Fetch data on recent malware samples, hashes, and associated threat intelligence.
    * Store and display this information, potentially linking malware IOCs to CVEs or threat actors.
* **[ ] Other CISA Products & Feeds:**
    * Explore and integrate other relevant CISA feeds beyond the KEV catalog (e.g., CISA Alerts, Industrial Control Systems Advisories if applicable).
* **[ ] Comprehensive Microsoft Patch Tuesday Parsing:**
    * Further refine `microsoft_update_client.py` to ensure accurate and detailed extraction of product families, specific product versions, and direct links to KB articles/MSRC guidance from CVRF/CSAF data.

### Phase 3: Developing "Threat Analyst Agent" Capabilities

* **[ ] Semantic Web Search Integration (e.g., EXA AI):**
    * For high-priority CVEs or emerging threats, automatically search the web for technical analyses, blog posts, news articles, and threat actor reports.
    * Store relevant article metadata (URL, title, snippet, source) linked to CVEs.
* **[ ] AI-Powered Content Analysis (Gemini):**
    * **Summarization:** Use Gemini to summarize fetched articles and reports related to a CVE.
    * **Key Information Extraction:** Extract TTPs (Tactics, Techniques, and Procedures), affected software/hardware, and potential mitigations from unstructured text.
    * **Cross-Validation Support:** Assist analysts by comparing information from different sources regarding a specific threat.

### Phase 4: Building "Threat Hunting Agent" Foundations

* **[ ] Enhanced IOC Extraction:**
    * Expand IOC (IPs, domains, hashes, URLs, mutexes, registry keys) extraction from all ingested text sources (NVD descriptions, MSRC summaries, KEV details, fetched articles) using Gemini's advanced understanding or specialized libraries like `iocextract`.
    * Create a robust, searchable IOC database.
* **[ ] Natural Language to Query Translation (Advanced):**
    * Leverage Gemini to translate natural language threat hunting hypotheses (e.g., "Are there any Cobalt Strike beacons communicating with newly registered domains?") into structured query formats like OCSF, KQL (Azure Sentinel), or Splunk SPL.

### Phase 5: Broader Intelligence Gathering & Advanced Analytics

* **[ ] Social Media Monitoring & Clustering (Advanced):**
    * Ingest data from platforms like Twitter/X or specific Reddit communities (e.g., r/netsec) for early signals of new vulnerabilities or exploits.
    * Apply LLM-based semantic clustering (Gemini) to group discussions and identify emerging threat trends.
* **[ ] Threat Actor & Malware Profiling:**
    * Begin associating CVEs and IOCs with known threat actors and malware families (potentially integrating with MISP or other OSINT feeds).
    * Visualize these relationships in the dashboard.
* **[ ] Advanced Dashboard Analytics:**
    * Implement more sophisticated trend analysis, predictive insights (beyond EPSS), and customizable reporting features.

### Phase 6: Platform Maturity & Usability

* **[ ] User Accounts & Collaboration (Long-term):** Allow multiple users, role-based access, and collaborative analysis features (e.g., shared notes, investigation assignments).
* **[ ] Notification System:** Implement email or other notifications for high-priority alerts or newly discovered critical CVEs matching predefined criteria.
* **[ ] Database Optimization/Migration:** For larger deployments, consider migrating from SQLite to a more scalable database like PostgreSQL.

This roadmap is ambitious and will evolve. Community contributions and feedback are highly encouraged as we build VIPER into a powerful open-source CTI tool!
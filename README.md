# 🛡️ VIPER - Vulnerability Intelligence, Prioritization, and Exploitation Reporter

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
**VIPER is your AI-powered co-pilot in the complex world of cyber threats, designed to provide actionable Vulnerability Intelligence, Prioritization, and Exploitation Reporting.**

In an era of ever-increasing cyber threats, VIPER cuts through the noise. It ingests data from critical sources like NVD, EPSS, and the CISA KEV catalog, then leverages Google Gemini AI for deep contextual analysis and vulnerability prioritization. All this intelligence is centralized, enriched, and presented through an interactive Streamlit dashboard, empowering security teams to focus on what truly matters and remediate effectively.

## ✨ Core Features

* **Multi-Source Data Ingestion:**
    * ✅ **NVD (National Vulnerability Database):** Up-to-the-minute CVE information.
    * ✅ **EPSS (Exploit Prediction Scoring System):** Likelihood sıcaklık of vulnerability exploitation.
    * ✅ **CISA KEV (Known Exploited Vulnerabilities) Catalog:** Confirmed actively exploited vulnerabilities.
    * *(Planned: Microsoft Patch Tuesday, MalwareBazaar, Semantic Web Search, Social Media Trends)*
* **AI-Powered Analysis & Prioritization:**
    * 🧠 Deep contextual analysis of CVE descriptions and related data using **Google Gemini AI**.
    * Automated priority assignment (HIGH, MEDIUM, LOW) based on AI assessment.
* **Comprehensive Risk Scoring:**
    * 📈 Customizable weighted risk scoring combining CVSS, EPSS, KEV status, and Gemini AI analysis.
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
* **Resilient API Clients:**
    * 💪 Automated retry mechanisms with exponential backoff for API calls (`tenacity` library).
* **Flexible Configuration:**
    * ⚙️ Easy management of all critical parameters (API keys, model names, thresholds, weights) via a `.env` file.
* **Modular and Extensible Architecture:**
    * 🏗️ Designed for straightforward integration of new data sources and analysis modules.
* **Dual Operation Modes:**
    * 💻 **CLI Mode:** For backend data processing, fetching, and analysis.
    * 📊 **Dashboard Mode:** For interactive visualization and reporting.

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
    git clone [https://github.com/YOUR_USERNAME/viper.git](https://github.com/YOUR_USERNAME/viper.git) 
    # Replace YOUR_USERNAME with your actual GitHub username
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
│   │   ├── cisa_kev_client.py   # CISA KEV API client
│   │   ├── epss_client.py       # EPSS API client
│   │   └── nvd_client.py        # NVD API client
│   ├── dashboard/           # Dashboard application
│   │   ├── app.py              # Main dashboard app
│   │   └── pages/              # Dashboard pages
│   │       ├── 01_Dashboard.py      # Main dashboard page
│   │       ├── 02_Detailed_Analysis.py # Detailed CVE analysis page
│   │       └── 03_Analytics.py      # Analytics and trends page
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

## Dependencies

- `requests` - For making HTTP requests to the NVD, EPSS, CISA, and Microsoft APIs
- `python-dotenv` - For loading environment variables from .env file
- `google-generativeai` - For interacting with the Google Gemini API
- `tenacity` - For robust error handling and retry logic
- `streamlit` - For the interactive dashboard
- `pandas` - For data manipulation
- `plotly` - For interactive visualizations
- `numpy` - For numerical operations
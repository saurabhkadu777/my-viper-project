"""
PDF report generation utilities for VIPER Vulnerability Analysis
"""
import base64
import datetime
import io

from fpdf import FPDF


class VulnerabilityReport(FPDF):
    """
    Custom PDF class for generating vulnerability reports
    """

    def __init__(self):
        # Use utf8 encoding to support more characters
        super().__init__()
        self.WIDTH = 210
        self.HEIGHT = 297

    def header(self):
        # Logo
        self.set_font("Arial", "B", 15)
        self.cell(self.WIDTH - 20, 10, "VIPER Vulnerability Analysis Report", 0, 1, "R")
        self.ln(10)

    def footer(self):
        # Footer with page number and timestamp
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", 0, 0, "C")
        self.cell(0, 10, f'Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 0, "R")

    def chapter_title(self, title):
        # Add chapter title
        self.set_font("Arial", "B", 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, "L", 1)
        self.ln(4)

    def chapter_body(self, body):
        # Add chapter body
        self.set_font("Arial", "", 10)
        # Replace Unicode bullet points with standard dash for compatibility
        body = body.replace("•", "-").replace("\u2022", "-")
        self.multi_cell(0, 5, body)
        self.ln()

    def severity_color(self, severity):
        """Get color tuple based on severity"""
        if severity == "HIGH" or severity == "Critical":
            return (255, 75, 75)  # Red
        elif severity == "MEDIUM" or severity == "Important":
            return (255, 165, 75)  # Orange
        elif severity == "LOW" or severity == "Moderate" or severity == "Low":
            return (75, 255, 75)  # Green
        else:
            return (150, 150, 150)  # Grey


def generate_cve_report(cve_data):
    """
    Generate a PDF report for a single CVE

    Args:
        cve_data (dict): CVE data dictionary

    Returns:
        bytes: PDF file as bytes
    """
    pdf = VulnerabilityReport()
    pdf.alias_nb_pages()
    pdf.add_page()

    # Add CVE title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Vulnerability Report: {cve_data.get('cve_id')}", 0, 1)

    # Add summary section
    pdf.chapter_title("Summary")

    # Priority badge
    priority = cve_data.get("gemini_priority", "UNKNOWN")
    r, g, b = pdf.severity_color(priority)
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(30, 6, f"{priority} Priority", 0, 0, "C", 1)

    # KEV badge if applicable
    if cve_data.get("is_in_kev"):
        pdf.cell(5, 6, "", 0, 0)  # Spacing
        pdf.set_fill_color(217, 83, 79)  # Red for KEV
        pdf.cell(25, 6, "CISA KEV", 0, 0, "C", 1)

    # Microsoft severity if available
    ms_severity = cve_data.get("microsoft_severity")
    if ms_severity:
        pdf.cell(5, 6, "", 0, 0)  # Spacing
        r, g, b = pdf.severity_color(ms_severity)
        pdf.set_fill_color(r, g, b)
        pdf.cell(30, 6, f"MS {ms_severity}", 0, 0, "C", 1)

    pdf.ln(10)

    # Reset text color
    pdf.set_text_color(0, 0, 0)

    # Description
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 6, "Description:", 0, 1)
    pdf.set_font("Arial", "", 10)
    desc = cve_data.get("description", "No description available.")
    # Replace Unicode characters for compatibility
    desc = desc.replace("•", "-").replace("\u2022", "-")
    pdf.multi_cell(0, 5, desc)
    pdf.ln(5)

    # Metrics table
    pdf.chapter_title("Risk Metrics")
    pdf.set_font("Arial", "B", 10)

    # Table header
    col_width = 47.5  # 190/4
    pdf.cell(col_width, 6, "CVSS Score", 1, 0, "C")
    pdf.cell(col_width, 6, "EPSS Score", 1, 0, "C")
    pdf.cell(col_width, 6, "EPSS Percentile", 1, 0, "C")
    pdf.cell(col_width, 6, "Risk Score", 1, 1, "C")

    # Table data
    pdf.set_font("Arial", "", 10)
    pdf.cell(col_width, 6, f"{cve_data.get('cvss_v3_score', 'N/A')}", 1, 0, "C")
    pdf.cell(col_width, 6, f"{cve_data.get('epss_score', 'N/A')}", 1, 0, "C")
    pdf.cell(col_width, 6, f"{cve_data.get('epss_percentile', 'N/A')}", 1, 0, "C")
    pdf.cell(col_width, 6, f"{cve_data.get('risk_score', 'N/A')}", 1, 1, "C")
    pdf.ln(5)

    # AI Analysis
    pdf.chapter_title("AI Analysis")

    # Extract priority reasoning
    alerts = cve_data.get("alerts", [])
    priority_reasoning = None

    for alert in alerts:
        if "Priority assigned based on" in alert:
            priority_reasoning = alert
            break

    if priority_reasoning:
        pdf.chapter_body(priority_reasoning)
    else:
        pdf.chapter_body("The AI has assigned a priority level based on the vulnerability characteristics and context.")

    # Other alerts
    if alerts:
        other_alerts = [a for a in alerts if a != priority_reasoning]
        if other_alerts:
            pdf.chapter_title("Alerts and Concerns")
            for alert in other_alerts:
                # Replace bullet points with dashes for compatibility
                pdf.chapter_body(f"- {alert}")

    # Recommended actions section
    pdf.chapter_title("Recommended Actions")

    # Generate recommendations based on priority
    if priority == "HIGH":
        recommendations = """
Immediate Action Required:
- Apply patches or updates as soon as they become available
- Implement temporary mitigations or workarounds if patches are not yet available
- Monitor systems for signs of exploitation
- Consider isolating vulnerable systems if mitigation is not possible
        """
    elif priority == "MEDIUM":
        recommendations = """
Action Recommended:
- Plan to apply patches during the next maintenance window
- Review and implement available mitigations
- Monitor for increases in exploitation activity
- Include in regular vulnerability management processes
        """
    else:
        recommendations = """
Standard Remediation:
- Address according to normal vulnerability management procedures
- Apply patches during regular maintenance cycles
- Document in vulnerability tracking system
        """

    pdf.chapter_body(recommendations)

    # KEV-specific recommendation
    if cve_data.get("is_in_kev"):
        pdf.ln(2)
        pdf.set_font("Arial", "B", 10)
        pdf.cell(0, 6, "CISA KEV Directive:", 0, 1)
        pdf.set_font("Arial", "", 10)

        kev_recommendations = """
This vulnerability is in CISA's Known Exploited Vulnerabilities (KEV) catalog, which means:
- Federal agencies are required to remediate according to CISA timelines
- Active exploitation has been observed in the wild
- This vulnerability should be prioritized for remediation regardless of CVSS score
        """
        pdf.multi_cell(0, 5, kev_recommendations)

    # Microsoft-specific recommendations
    ms_severity = cve_data.get("microsoft_severity")
    if ms_severity:
        pdf.ln(2)
        pdf.set_font("Arial", "B", 10)
        pdf.cell(0, 6, f"Microsoft {ms_severity} Guidance:", 0, 1)
        pdf.set_font("Arial", "", 10)

        if ms_severity == "Critical":
            ms_recommendations = """
Microsoft has rated this as a Critical vulnerability:
- Deploy patches immediately, even outside regular patching cycles
- Critical vulnerabilities often involve remote code execution or privilege escalation
- Prioritize systems directly exposed to the internet
- Consider emergency change approval if needed
            """
        elif ms_severity == "Important":
            ms_recommendations = """
Microsoft has rated this as an Important vulnerability:
- Apply patches according to your standard patching schedule (typically within 30 days)
- Important vulnerabilities represent significant security risks but might require additional factors to exploit
- Prioritize based on system exposure and criticality
            """
        else:
            ms_recommendations = f"""
Microsoft has rated this as a {ms_severity} vulnerability:
- Apply patches during regular maintenance cycles
- These vulnerabilities typically represent lower security risks
- Prioritize based on system exposure and criticality
            """

        pdf.multi_cell(0, 5, ms_recommendations)

    # References section
    references = cve_data.get("references", [])
    if references:
        pdf.add_page()
        pdf.chapter_title("References")
        for ref in references:
            url = ref.get("url")
            source = ref.get("source")
            if url:
                pdf.chapter_body(f"- {source if source else url}: {url}")

    # Affected Products section if available
    cpe_entries = cve_data.get("cpe_entries", [])
    if cpe_entries:
        pdf.add_page()
        pdf.chapter_title("Affected Products (CPE)")
        for i, cpe in enumerate(cpe_entries):
            if i >= 20:  # Limit to 20 entries
                pdf.chapter_body(f"...and {len(cpe_entries) - 20} more CPE entries")
                break

            criteria = cpe.get("criteria", "")
            vulnerable = cpe.get("vulnerable", True)
            status = "Vulnerable" if vulnerable else "Not Vulnerable"

            pdf.set_font("Arial", "B", 9)
            pdf.cell(25, 5, status + ":", 0, 0)
            pdf.set_font("Arial", "", 9)
            pdf.multi_cell(0, 5, criteria)

    # Get the PDF as bytes
    try:
        pdf_bytes = pdf.output(dest="S").encode("latin1")
        return pdf_bytes
    except UnicodeEncodeError:
        # If encoding fails, try to handle by replacing problematic characters
        # Log the error and return fallback PDF with simplified content
        print("Warning: Unicode encoding error encountered - generating simplified PDF")
        return generate_simplified_pdf(cve_data)


def generate_simplified_pdf(cve_data):
    """
    Generate a simplified PDF with minimal formatting for cases where encoding fails
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Vulnerability Report: {cve_data.get('cve_id')}", 0, 1)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Summary", 0, 1)

    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 5, cve_data.get("description", "No description available."))

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Risk Information", 0, 1)

    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(
        0,
        5,
        (
            f"Priority: {cve_data.get('gemini_priority', 'N/A')}\n"
            f"CVSS Score: {cve_data.get('cvss_v3_score', 'N/A')}\n"
            f"EPSS Score: {cve_data.get('epss_score', 'N/A')}\n"
            f"Risk Score: {cve_data.get('risk_score', 'N/A')}\n"
            f"In KEV: {'Yes' if cve_data.get('is_in_kev') else 'No'}"
        ),
    )

    return pdf.output(dest="S").encode("latin1")


def generate_base64_pdf(cve_data):
    """
    Generate a base64 encoded PDF for embedding in HTML

    Args:
        cve_data (dict): CVE data dictionary

    Returns:
        str: Base64 encoded PDF
    """
    pdf_bytes = generate_cve_report(cve_data)
    return base64.b64encode(pdf_bytes).decode("ascii")

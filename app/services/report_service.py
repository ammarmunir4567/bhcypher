from __future__ import annotations

from datetime import datetime
from pathlib import Path    

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from .ai_service import generate_full_report_with_gemini


TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
REPORT_TEMPLATE = "pentest_report.html"  # New professional template
# REPORT_TEMPLATE = "report.html"  # Old simple template


def _get_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def parse_scan(scan: dict) -> dict:
    """Parse JSON scan file and extract all relevant data for report generation."""
    sys = scan.get("systemStats", {}).get("system", {})
    hostname = sys.get("hostname")
    os_name = sys.get("os_name")
    os_version = sys.get("os_version")
    
    vulns = scan.get("vulnerabilities", {}).get("vulnerabilities", [])
    summary = scan.get("vulnerabilities", {}).get("summary", {})
    
    parsed_findings = []
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        descs = cve.get("descriptions", [])
        en = next((d["value"] for d in descs if d.get("lang") == "en"), None)
        parsed_findings.append({
            "cve_id": cve_id,
            "description": en,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
        })
    
    return {
        "host": {
            "hostname": hostname,
            "os": os_name,
            "os_version": os_version,
        },
        "findings": parsed_findings,
        "summary": {
            "total_vulnerabilities": summary.get("total_vulnerabilities", len(parsed_findings)),
            "critical_count": summary.get("critical_count", 0),
            "high_count": summary.get("high_count", 0),
            "medium_count": summary.get("medium_count", 0),
            "low_count": summary.get("low_count", 0),
            "risk_score": summary.get("risk_score", 0.0),
        }
    }


def render_report(report_data: dict) -> tuple[str, bytes]:
    """Render Gemini-generated report into HTML and PDF (landscape orientation)."""
    env = _get_env()
    template = env.get_template(REPORT_TEMPLATE)
    # Add timestamp for report generation
    render_context = {**report_data, "now": datetime.now()}
    html_str = template.render(**render_context)
    
    # Generate PDF with landscape orientation
    # The CSS @page rule in the template already sets landscape mode
    pdf_bytes = HTML(string=html_str).write_pdf()
    return html_str, pdf_bytes


def generate_report_from_scan(scan_json: dict) -> tuple[str, bytes, dict, dict]:
    """
    Main workflow:
    1. Parse scan JSON → extract vulnerabilities and host info
    2. Send ALL parsed data to Gemini → generate complete report
    3. Render Gemini output → HTML/PDF
    """
    # Parse scan data
    parsed_scan = parse_scan(scan_json)
    
    # Send parsed data to Gemini and generate full report
    report_data = generate_full_report_with_gemini(parsed_scan)
    
    # Render report into HTML/PDF
    html_str, pdf_bytes = render_report(report_data)
    
    summary = {
        "hostname": parsed_scan.get("host", {}).get("hostname"),
        "findings_count": len(report_data.get("findings", [])),
        "risk_score": report_data.get("risk_score", 0.0),
        "risk_level": report_data.get("risk_level", "Unknown"),
    }
    
    return html_str, pdf_bytes, summary, report_data

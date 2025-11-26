"""
Qualitative Security Report Generation Service

This module generates comprehensive qualitative security reports using the
LangGraph-based multi-agent architecture from qualitative_report_agent.py.
"""

from __future__ import annotations

import logging
from typing import Tuple, Dict
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.services.pdf_generator import html_to_pdf
from app.services.qualitative_report_agent import SecurityReportOrchestrator

logger = logging.getLogger(__name__)

# Template configuration
TEMPLATE_DIR = Path(__file__).parent / "templates"
QUALITATIVE_TEMPLATE = "qualitative_report.html"


def _get_env() -> Environment:
    """Get Jinja2 environment with markdown filter."""
    from app.services.report_service import _markdown_filter, _markdown_inline
    
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    
    # Add markdown filters
    env.filters["markdown"] = _markdown_filter
    env.filters["markdown_inline"] = _markdown_inline
    
    return env


def parse_scan_for_qualitative(scan_json: dict) -> dict:
    """
    Parse scan JSON into the format expected by SecurityReportOrchestrator.
    
    Args:
        scan_json: Raw scan data
        
    Returns:
        Parsed scan data with host, findings, system_data, etc.
    """
    # Extract host information
    sys = scan_json.get("systemStats", {}).get("system", {})
    host_info = {
        "hostname": sys.get("hostname", "Unknown"),
        "os": sys.get("os_name", "Unknown"),
        "os_version": sys.get("os_version", ""),
        "ip_address": sys.get("ip_address", "Unknown")
    }
    
    # Extract vulnerabilities as findings
    vulns = scan_json.get("vulnerabilities", {})
    findings = []
    
    for cve_id, vuln_data in vulns.items():
        if isinstance(vuln_data, dict):
            findings.append({
                "cve_id": cve_id,
                "description": vuln_data.get("description", "No description available"),
                "severity": vuln_data.get("severity", "Unknown"),
                "cvss_score": vuln_data.get("cvss_score"),
                "affected_software": vuln_data.get("affected_software", [])
            })
    
    # Extract system data
    system_data = scan_json.get("systemData", {})
    
    # Extract credentials if available
    credentials = {
        "browsers": scan_json.get("browsers", []),
        "apps": scan_json.get("apps", []),
        "os": scan_json.get("os", [])
    }
    
    # Extract metadata
    scan_metadata = {
        "scan_timestamp": scan_json.get("systemData", {}).get("collected_at") or datetime.now().isoformat(),
        "collected_at": scan_json.get("systemData", {}).get("collected_at")
    }
    
    return {
        "host": host_info,
        "findings": findings,
        "system_data": system_data,
        "credentials": credentials,
        "scan_metadata": scan_metadata
    }


def render_qualitative_report(report_data: dict) -> Tuple[str, bytes]:
    """
    Render qualitative report into HTML and PDF.
    
    Args:
        report_data: Complete report data from SecurityReportOrchestrator
        
    Returns:
        Tuple of (html_string, pdf_bytes)
    """
    logger.info("📄 Rendering qualitative report HTML...")
    
    env = _get_env()
    template = env.get_template(QUALITATIVE_TEMPLATE)
    
    # Add current timestamp for report generation
    render_context = {
        **report_data,
        "now": datetime.now(),
    }
    
    # Render HTML
    html_str = template.render(**render_context)
    logger.info("✅ Qualitative report HTML rendered")
    
    # Generate PDF
    logger.info("📊 Generating qualitative PDF report...")
    pdf_bytes = html_to_pdf(html_str, method="auto")
    logger.info("✅ Qualitative PDF generated successfully")
    
    return html_str, pdf_bytes


def _enhance_report_data(report_data: dict) -> dict:
    """
    Enhance report data with additional fields required by the template.
    Adds charts, metadata, and formatted data structures.
    
    Args:
        report_data: Report data from SecurityReportOrchestrator
        
    Returns:
        Enhanced report data with all template fields populated
    """
    import base64
    from io import BytesIO
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
    
    logger.info("🎨 Enhancing report data with charts and metadata...")
    
    # Generate severity charts if we have data
    severity_breakdown = report_data.get("severity_breakdown", {})
    critical = severity_breakdown.get("critical", 0)
    high = severity_breakdown.get("high", 0)
    medium = severity_breakdown.get("medium", 0)
    low = severity_breakdown.get("low", 0)
    info = severity_breakdown.get("info", 0)
    
    total = critical + high + medium + low + info
    
    if total > 0:
        # Generate bar chart
        labels = ["Critical", "High", "Medium", "Low", "Info"]
        values = [critical, high, medium, low, info]
        colors = ["#dc2626", "#ea580c", "#ca8a04", "#3b82f6", "#6b7280"]
        
        bar_fig = Figure(figsize=(8, 4), dpi=120)
        bar_ax = bar_fig.add_subplot(1, 1, 1)
        bar_ax.bar(labels, values, color=colors, edgecolor="#1f2937", linewidth=1.5)
        bar_ax.set_ylabel("Findings", fontsize=12, fontweight="bold")
        bar_ax.set_title("Findings by Severity", fontsize=14, fontweight="bold", pad=15)
        bar_ax.grid(axis="y", linestyle="--", alpha=0.3)
        bar_ax.set_axisbelow(True)
        bar_ax.tick_params(axis="x", labelsize=10)
        bar_ax.tick_params(axis="y", labelsize=10)
        
        # Convert to base64
        buffer = BytesIO()
        FigureCanvas(bar_fig).print_png(buffer)
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        bar_fig.clear()
        report_data["severity_bar_chart"] = f"data:image/png;base64,{encoded}"
        
        # Generate pie chart
        pie_fig = Figure(figsize=(8, 4), dpi=120)
        pie_ax = pie_fig.add_subplot(1, 1, 1)
        pie_ax.pie(
            values,
            labels=labels,
            colors=colors,
            autopct=lambda pct: f"{pct:.0f}%" if pct >= 1 else "",
            startangle=135,
            explode=[0.03 if v > 0 else 0 for v in values],
            textprops={"color": "#0f172a", "fontsize": 10, "weight": "bold"},
        )
        pie_ax.set_title("Distribution of Findings", fontsize=14, fontweight="bold", pad=15)
        pie_ax.axis("equal")
        
        buffer = BytesIO()
        FigureCanvas(pie_fig).print_png(buffer)
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        pie_fig.clear()
        report_data["severity_pie_chart"] = f"data:image/png;base64,{encoded}"
    else:
        report_data["severity_bar_chart"] = None
        report_data["severity_pie_chart"] = None
    
    # Ensure assessment_scope is in the correct format for template
    if "assessment_scope" in report_data and isinstance(report_data["assessment_scope"], list):
        report_data["assessment_scope_items"] = report_data["assessment_scope"]
    else:
        report_data["assessment_scope_items"] = []
    
    # Add classification if not present
    if "classification" not in report_data:
        report_data["classification"] = "Confidential and Proprietary"
    
    # Add test_type if not present
    if "test_type" not in report_data:
        report_data["test_type"] = "Comprehensive Security Assessment"
    
    # Generate conclusion if not present
    if "conclusion" not in report_data:
        findings_count = len(report_data.get("findings", []))
        risk_level = report_data.get("risk_level", "Unknown")
        client_name = report_data.get("client_name", "the organization")
        
        report_data["conclusion"] = (
            f"This comprehensive security assessment of {client_name} has identified {findings_count} security findings "
            f"with an overall risk level of **{risk_level}**. The assessment reveals critical security gaps that require "
            f"immediate attention, including exposed credentials, publicly accessible critical services, and unpatched vulnerabilities. "
            f"\n\n"
            f"**Immediate Actions Required:**\n"
            f"- Rotate all exposed credentials within 24-48 hours\n"
            f"- Implement network segmentation and firewall rules to restrict critical service access\n"
            f"- Apply security patches for all identified CVE vulnerabilities\n"
            f"- Deploy endpoint detection and response (EDR) solutions\n"
            f"\n"
            f"The security posture can be significantly improved by addressing the high-priority findings outlined in this report. "
            f"Continuous monitoring, regular security assessments, and adherence to security best practices are essential "
            f"to maintain a robust security posture and protect against evolving threats."
        )
    
    # Ensure all count fields exist
    report_data.setdefault("critical_count", critical)
    report_data.setdefault("high_count", high)
    report_data.setdefault("medium_count", medium)
    report_data.setdefault("low_count", low)
    report_data.setdefault("info_count", info)
    
    # Ensure report_date is set
    if "report_date" not in report_data:
        report_data["report_date"] = datetime.now().strftime("%B %Y")
    
    logger.info("✅ Report data enhanced successfully")
    logger.info(f"   - Findings: {len(report_data.get('findings', []))}")
    logger.info(f"   - Assessment Scope Items: {len(report_data.get('assessment_scope_items', []))}")
    logger.info(f"   - Testing Methodology: {len(report_data.get('testing_methodology', []))}")
    logger.info(f"   - Attack Vectors: {len(report_data.get('attack_vectors', []))}")
    logger.info(f"   - Security Concerns: {len(report_data.get('security_concerns', []))}")
    logger.info(f"   - Charts: {'✓' if report_data.get('severity_bar_chart') else '✗'}")
    
    return report_data


def generate_qualitative_report_from_scan(scan_json: dict) -> Tuple[str, bytes, dict, dict]:
    """
    Generate comprehensive qualitative security report using LangGraph multi-agent system.
    
    This function:
    1. Parses scan JSON data
    2. Uses SecurityReportOrchestrator (LangGraph) to generate detailed analysis
    3. Enhances report with additional metadata
    4. Renders the report into HTML and PDF
    
    Args:
        scan_json: Raw scan data from security assessment
        
    Returns:
        Tuple of (html_string, pdf_bytes, summary_dict, full_report_data)
        
    Example:
        ```python
        html, pdf, summary, data = generate_qualitative_report_from_scan(scan_data)
        ```
    """
    logger.info("🎯 Generating qualitative security report with LangGraph agents...")
    
    # Parse scan data
    parsed_scan = parse_scan_for_qualitative(scan_json)
    logger.info(f"📦 Parsed scan data: {len(parsed_scan.get('findings', []))} findings")
    
    # Use LangGraph orchestrator to generate report
    orchestrator = SecurityReportOrchestrator()
    report_data = orchestrator.generate_report(parsed_scan)
    
    logger.info("✅ LangGraph report generation complete")
    
    # Enhance report with additional fields expected by template
    report_data = _enhance_report_data(report_data)
    
    # Render report into HTML/PDF
    html_str, pdf_bytes = render_qualitative_report(report_data)
    
    # Extract summary for API response
    summary = {
        "hostname": parsed_scan.get("host", {}).get("hostname", "Unknown"),
        "findings_count": len(report_data.get("findings", [])),
        "risk_score": report_data.get("risk_score", 0.0),
        "risk_level": report_data.get("risk_level", "Unknown"),
        "critical_count": report_data.get("critical_count", 0),
        "high_count": report_data.get("high_count", 0),
        "medium_count": report_data.get("medium_count", 0),
        "low_count": report_data.get("low_count", 0),
    }
    
    logger.info("✅ Qualitative report generation complete")
    
    return html_str, pdf_bytes, summary, report_data


from __future__ import annotations

import base64
from datetime import datetime
from io import BytesIO
from pathlib import Path    
from typing import Dict

import markdown2  # type: ignore[import]
from jinja2 import Environment, FileSystemLoader, select_autoescape
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.figure import Figure
from .ai_service import generate_full_report_with_gemini
from .pdf_generator import html_to_pdf
from app.core.config import settings

# Import Pentest LangGraph multi-agent system
try:
    from app.services.pentest_multi_agent_service import PentestReportOrchestrator
    PENTEST_AGENT_AVAILABLE = True
except ImportError:
    PENTEST_AGENT_AVAILABLE = False


TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
REPORT_TEMPLATE = "pentest_report.html"  # Old pentest template
PENTEST_V2_TEMPLATE = "pentest_report_v2.html"  # New A4 portrait template with N/A markers
MSP_TEMPLATE = "msp_report.html"  # MSP report template

SEVERITY_SERIES = [
    ("critical_count", "Critical", "#dc2626"),
    ("high_count", "High", "#ea580c"),
    ("medium_count", "Medium", "#ca8a04"),
    ("low_count", "Low", "#3b82f6"),
    ("info_count", "Info", "#6b7280"),
]

DEFAULT_SCOPE_LABELS = [
    "External Network",
    "Internal Network",
    "Web Applications",
    "Wireless Networks",
]


def _get_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["markdown"] = _markdown_filter
    env.filters["markdown_inline"] = _markdown_inline
    return env


def _markdown_filter(value: str | None) -> str:
    if not value:
        return ""
    return markdown2.markdown(
        value,
        extras=["fenced-code-blocks", "tables", "strike", "break-on-newline"],
    )


def _markdown_inline(value: str | None) -> str:
    html = _markdown_filter(value)
    if not html:
        return ""
    normalized = html.strip()
    if normalized.startswith("<p>") and normalized.endswith("</p>"):
        normalized = normalized[3:-4].strip()
    return normalized


def parse_scan(scan: dict) -> dict:
    """Parse comprehensive JSON scan file and extract all relevant data for report generation."""
    
    # Extract system stats
    sys = scan.get("systemStats", {}).get("system", {})
    hostname = sys.get("hostname", "Unknown")
    os_name = sys.get("os_name")
    os_version = sys.get("os_version")
    
    # Extract vulnerabilities
    vulns = scan.get("vulnerabilities", {}).get("vulnerabilities", [])
    summary = scan.get("vulnerabilities", {}).get("summary", {})
    scan_timestamp = scan.get("vulnerabilities", {}).get("scan_timestamp")
    
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
    
    # Extract credential data
    browsers = scan.get("browsers", [])
    os_creds = scan.get("os", [])
    apps = scan.get("apps", [])
    stats_data = scan.get("statsData", {})
    
    # Extract system data
    system_data = scan.get("systemData", {})
    open_ports = system_data.get("open_ports", [])
    installed_software = system_data.get("installed_software", [])
    user_accounts = system_data.get("user_accounts", [])
    hardware_info = system_data.get("hardware_info", {})
    
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
        },
        # Additional pentest data
        "credentials": {
            "browsers": browsers,
            "os": os_creds,
            "apps": apps,
            "stats": stats_data
        },
        "system_data": {
            "open_ports": open_ports,
            "installed_software": installed_software,
            "user_accounts": user_accounts,
            "hardware_info": hardware_info
        },
        "scan_metadata": {
            "scan_timestamp": scan_timestamp,
            "collected_at": system_data.get("collected_at")
        }
    }


def render_report(report_data: dict, template_name: str = None) -> tuple[str, bytes]:
    """Render Gemini-generated report into HTML and PDF.
    
    Args:
        report_data: Report data dictionary
        template_name: Optional template name (defaults to REPORT_TEMPLATE)
    """
    env = _get_env()
    template = env.get_template(template_name or REPORT_TEMPLATE)

    # Only generate charts for old template
    if template_name == PENTEST_V2_TEMPLATE:
        # New pentest template doesn't use charts
        render_context = {
            **report_data,
            "now": datetime.now(),
        }
    else:
        # Old template with charts
        severity_counts = _extract_severity_counts(report_data)
        charts = _generate_severity_charts(severity_counts)
        
        # Use assessment_scope directly if it's already a list, otherwise build from legacy format
        scope_items = report_data.get("assessment_scope")
        if not isinstance(scope_items, list):
            scope_items = _build_scope_items(scope_items)

        # Add timestamp for report generation
        render_context = {
            **report_data,
            **charts,
            "assessment_scope_items": scope_items,
            "now": datetime.now(),
        }
    
    html_str = template.render(**render_context)
    
    # Generate PDF using wkhtmltoimage (HTML -> PNG -> PDF)
    # This provides maximum stability for complex HTML layouts
    pdf_bytes = html_to_pdf(html_str, method="auto")
    return html_str, pdf_bytes


def generate_report_from_scan(scan_json: dict, report_type: str = "basic") -> tuple[str, bytes, dict, dict]:
    """
    Main workflow:
    1. Parse scan JSON → extract vulnerabilities and host info
    2. Send ALL parsed data to AI (Agent or direct Gemini) → generate complete report
    3. Render AI output → HTML/PDF
    
    Args:
        scan_json: Raw scan data
        report_type: "basic" for standard report, "pentest" for comprehensive pentest report
    """
    if report_type == "pentest" and PENTEST_AGENT_AVAILABLE:
        # Use pentest multi-agent system for comprehensive analysis
        return generate_pentest_report(scan_json)
    
    # Parse scan data
    parsed_scan = parse_scan(scan_json)
    
    # Send parsed data to AI and generate full report (uses agent by default if configured)
    report_data = generate_full_report_with_gemini(parsed_scan, use_agent=settings.use_agent)
    
    # Render report into HTML/PDF
    html_str, pdf_bytes = render_report(report_data)
    
    summary = {
        "hostname": parsed_scan.get("host", {}).get("hostname"),
        "findings_count": len(report_data.get("findings", [])),
        "risk_score": report_data.get("risk_score", 0.0),
        "risk_level": report_data.get("risk_level", "Unknown"),
    }
    
    return html_str, pdf_bytes, summary, report_data


def generate_pentest_report(scan_json: dict) -> tuple[str, bytes, dict, dict]:
    """
    Generate comprehensive penetration test report using LLM-based analysis.
    
    This uses the PentestReportOrchestrator to:
    - Analyze software for vulnerabilities
    - Map CVEs to installed software
    - Identify service and port exposure
    - Detect configuration issues
    - Assess credential security
    - Generate realistic security findings
    """
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("🎯 Generating comprehensive pentest report with LLM analysis...")
    
    # Use pentest orchestrator
    orchestrator = PentestReportOrchestrator()
    enriched_data = orchestrator.generate_report(scan_json)
    
    # Transform enriched data to report format
    report_data = transform_pentest_data(enriched_data, scan_json)
    
    # Render pentest report using new A4 portrait template
    html_str, pdf_bytes = render_report(report_data, template_name=PENTEST_V2_TEMPLATE)
    
    summary = {
        "hostname": scan_json.get("systemStats", {}).get("system", {}).get("hostname", "Unknown"),
        "findings_count": len(enriched_data.get("cve_vulnerabilities", [])),
        "risk_score": enriched_data.get("overall_risk_score", 75),
        "risk_level": "Critical" if enriched_data.get("overall_risk_score", 75) >= 85 else "High",
    }
    
    logger.info("✅ Pentest report generation complete")
    
    return html_str, pdf_bytes, summary, report_data


def transform_pentest_data(enriched_data: dict, scan_json: dict) -> dict:
    """Transform LLM-enriched pentest data to template format."""
    devices = enriched_data.get("devices", [])
    
    # If no devices generated, create at least one from scan data
    if not devices:
        hostname = scan_json.get("systemStats", {}).get("system", {}).get("hostname", "WORKSTATION-01")
        devices = [{
            "device_id": "DEV-001",
            "hostname": hostname,
            "ip_address": "192.168.1.100",
            "device_type": "Workstation",
            "is_primary_scan": True
        }]
    
    # Build company info
    scan_date = datetime.now().strftime("%B %d, %Y")
    
    # Ensure all data structures exist
    return {
        "company_name": "Client Company",
        "scan_date": scan_date,
        "report_title": "System Security Analysis Report",
        "methodology_description": "BH THREAT ARCHITECT Assessment Framework",
        
        # Device list
        "devices": devices,
        
        # Main findings sections (default to empty dicts)
        "outdated_software": enriched_data.get("outdated_software", {}),
        "running_services": enriched_data.get("running_services", {}),
        "open_ports": enriched_data.get("open_ports", {}),
        "deep_scan_findings": enriched_data.get("deep_scan_findings", {}),
        "edr_findings": enriched_data.get("edr_findings", {}),
        "firewall_findings": enriched_data.get("firewall_findings", {}),
        "misconfigurations": enriched_data.get("misconfigurations", {}),
        "dark_web_exposure": enriched_data.get("dark_web_exposure", {}),
        "pii_findings": enriched_data.get("pii_findings", {}),
        "admin_passwords": enriched_data.get("admin_passwords", {}),
        
        # CVE vulnerabilities (default to empty list)
        "cve_vulnerabilities": enriched_data.get("cve_vulnerabilities", []),
        
        # Risk rankings (default to empty list)
        "risk_rankings": enriched_data.get("risk_rankings", [
            {"concern": "Critical RCE Vulnerabilities", "percentage": 100},
            {"concern": "Outdated Operating Systems", "percentage": 95},
            {"concern": "Exposed Database Servers", "percentage": 92},
            {"concern": "Weak Admin Passwords", "percentage": 90},
            {"concern": "Misconfigured EDR Systems", "percentage": 88},
            {"concern": "SMBv1 Enabled", "percentage": 85},
            {"concern": "Disabled Security Controls", "percentage": 82},
            {"concern": "Dark Web Credential Exposure", "percentage": 80},
            {"concern": "Unencrypted PII Storage", "percentage": 78},
            {"concern": "Open RDP Ports", "percentage": 75},
        ]),
        
        # Executive summary
        "executive_summary": enriched_data.get("executive_summary", 
            "The security assessment of the client organization's infrastructure has revealed critical "
            "vulnerabilities that pose an immediate and severe risk to business operations, data integrity, "
            "and regulatory compliance. Immediate action is required to address these findings."
        ),
        
        # Overall metrics
        "overall_risk_score": enriched_data.get("overall_risk_score", 75),
        "total_devices": len(devices),
        "total_vulnerabilities": len(enriched_data.get("cve_vulnerabilities", [])),
        
        # Metadata
        "report_generated_date": datetime.now(),
    }


def _extract_severity_counts(report_data: dict) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for key, label, _ in SEVERITY_SERIES:
        value = report_data.get(key, 0)
        try:
            counts[label] = int(value or 0)
        except (TypeError, ValueError):
            counts[label] = 0
    return counts


def _generate_severity_charts(counts: Dict[str, int]) -> Dict[str, str | None]:
    total = sum(counts.values())
    if total == 0:
        return {"severity_bar_chart": None, "severity_pie_chart": None}

    labels = [label for _, label, _ in SEVERITY_SERIES]
    colors = [color for _, _, color in SEVERITY_SERIES]
    values = [counts.get(label, 0) for label in labels]

    bar_fig = Figure(figsize=(6, 3), dpi=120)
    bar_ax = bar_fig.add_subplot(1, 1, 1)
    bar_ax.bar(labels, values, color=colors, edgecolor="#1f2937")
    bar_ax.set_ylabel("Findings")
    bar_ax.set_title("Findings by Severity")
    bar_ax.grid(axis="y", linestyle="--", alpha=0.3)
    bar_ax.set_axisbelow(True)
    bar_ax.tick_params(axis="x", rotation=10)
    bar_uri = _figure_to_data_uri(bar_fig)

    pie_fig = Figure(figsize=(6, 3.2), dpi=120)
    pie_ax = pie_fig.add_subplot(1, 1, 1)
    pie_ax.pie(
        values,
        labels=labels,
        colors=colors,
        autopct=lambda pct: f"{pct:.0f}%" if pct >= 1 else "",
        startangle=135,
        explode=[0.03 if v > 0 else 0 for v in values],
        textprops={"color": "#0f172a", "fontsize": 9, "weight": "bold"},
    )
    pie_ax.set_title("Distribution of Findings")
    pie_ax.axis("equal")
    pie_uri = _figure_to_data_uri(pie_fig)

    return {
        "severity_bar_chart": bar_uri,
        "severity_pie_chart": pie_uri,
    }


def _figure_to_data_uri(fig: Figure) -> str:
    buffer = BytesIO()
    FigureCanvas(fig).print_png(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    fig.clear()
    return f"data:image/png;base64,{encoded}"


def _build_scope_items(scope_data) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    normalized_map: Dict[str, dict[str, str]] = {}

    default_set = {_normalize_label(label) for label in DEFAULT_SCOPE_LABELS}

    if isinstance(scope_data, list):
        for entry in scope_data:
            label = str(entry.get("label") or "").strip()
            if not label:
                continue
            value = str(entry.get("value") or "N/A").strip() or "N/A"
            normalized_map[_normalize_label(label)] = {"label": label, "value": value}

    for default_label in DEFAULT_SCOPE_LABELS:
        normalized = _normalize_label(default_label)
        if normalized in normalized_map:
            items.append(normalized_map[normalized])
        else:
            items.append({"label": default_label, "value": "N/A"})

    for normalized, entry in normalized_map.items():
        if normalized not in default_set:
            items.append(entry)

    return items


def _normalize_label(label: str) -> str:
    return label.replace(":", "").replace(" ", "").lower()

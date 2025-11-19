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
from weasyprint import HTML

from .ai_service import generate_full_report_with_gemini
from app.core.config import settings


TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
REPORT_TEMPLATE = "pentest_report.html"  # New professional template
# REPORT_TEMPLATE = "report.html"  # Old simple template

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

    severity_counts = _extract_severity_counts(report_data)
    charts = _generate_severity_charts(severity_counts)
    scope_items = _build_scope_items(report_data.get("assessment_scope"))

    # Add timestamp for report generation
    render_context = {
        **report_data,
        **charts,
        "assessment_scope_items": scope_items,
        "now": datetime.now(),
    }
    html_str = template.render(**render_context)
    
    # Generate PDF with landscape orientation
    # The CSS @page rule in the template already sets landscape mode
    pdf_bytes = HTML(string=html_str).write_pdf()
    return html_str, pdf_bytes


def generate_report_from_scan(scan_json: dict) -> tuple[str, bytes, dict, dict]:
    """
    Main workflow:
    1. Parse scan JSON → extract vulnerabilities and host info
    2. Send ALL parsed data to AI (Agent or direct Gemini) → generate complete report
    3. Render AI output → HTML/PDF
    """
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

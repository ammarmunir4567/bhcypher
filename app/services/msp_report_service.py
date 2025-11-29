"""
MSP Report Service

This module handles MSP Cyber Hygiene & Credential Exposure report generation,
including data parsing, AI-powered analysis, and HTML/PDF rendering.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import settings
from .pdf_generator import html_to_pdf
from app.services.msp_multi_agent_service import MSPReportOrchestrator

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"
MSP_TEMPLATE = "msp_report.html"


def _get_env() -> Environment:
    """Create Jinja2 environment for template rendering."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    return env


def parse_msp_scan(scan_json: dict) -> dict:
    """
    Parse MSP credential scanner output and extract relevant data.
    
    Expected JSON structure from credential scanner:
    {
        "browsers": [
            {
                "url": "https://github.com",
                "username": "user@example.com",
                "password": "encrypted",
                "browser": "Chrome",
                "profile": "Default"
            }
        ],
        "os": [
            {
                "service": "VPN Connection",
                "account": "CorporateVPN",
                "password": "encrypted",
                "source": "Credential Manager"
            }
        ],
        "apps": [
            {
                "application": "FileZilla",
                "username": "ftp_user",
                "password": "encrypted",
                "filepath": "C:\\Users\\User\\AppData\\Roaming/filezilla"
            }
        ],
        "statsData": {
            "browser_count": 3,
            "os_count": 2,
            "app_count": 2,
            "encrypted_count": 7
        },
        "systemData": {
            "user_accounts": [...],
            "installed_software": [...],
            "open_ports": [...],
            "hardware_info": {...}
        },
        "systemStats": {
            "system": {
                "hostname": "DESKTOP-5UU61JF",
                "os_name": "Windows",
                "os_version": "10 (19045) 19045"
            }
        },
        "vulnerabilities": {...}
    }
    """
    
    # Extract endpoint information from systemStats
    system_stats = scan_json.get("systemStats", {})
    system_info = system_stats.get("system", {})
    
    # Extract user info from systemData
    system_data = scan_json.get("systemData", {})
    user_accounts = system_data.get("user_accounts", [])
    first_user = user_accounts[0] if user_accounts else {}
    
    # Extract username from full path (e.g., "DESKTOP-5UU61JF\\AlphaSquad" -> "AlphaSquad")
    username = first_user.get("username", "Unknown")
    if "\\" in username:
        username = username.split("\\")[-1]
    
    # Extract credentials data (at root level)
    browsers = scan_json.get("browsers", [])
    os_creds = scan_json.get("os", [])
    apps = scan_json.get("apps", [])
    stats_data = scan_json.get("statsData", {})
    
    # Extract software inventory from systemData
    software = system_data.get("installed_software", [])
    
    # Extract vulnerability data (optional)
    vulnerabilities = scan_json.get("vulnerabilities", {})
    
    parsed = {
        "endpoint_info": {
            "hostname": system_info.get("hostname", "Unknown"),
            "user": username,
            "os": system_info.get("os_name", "Unknown"),
            "os_version": system_info.get("os_version", "Unknown"),
        },
        "credentials": {
            "browsers": browsers,
            "os": os_creds,
            "apps": apps,
            "stats": stats_data
        },
        "software": software,
        "system": {
            "user_accounts": user_accounts,
            "open_ports": system_data.get("open_ports", []),
            "active_connections": system_data.get("active_connections", []),
            "running_services": system_data.get("running_services", []),
            "hardware_info": system_data.get("hardware_info", {})
        },
        "scan_metadata": {
            "scan_timestamp": system_data.get("collected_at", ""),
            "vulnerabilities": vulnerabilities
        }
    }
    
    logger.info(f"Parsed MSP scan for endpoint: {parsed['endpoint_info']['hostname']}")
    logger.info(f"Found {len(parsed['credentials']['browsers'])} browser credentials")
    logger.info(f"Found {len(parsed['credentials']['os'])} OS credentials")
    logger.info(f"Found {len(parsed['credentials']['apps'])} app credentials")
    logger.info(f"Found {len(parsed['software'])} software packages")
    
    return parsed


def generate_msp_report_with_agent(parsed_data: Dict) -> Dict:
    """
    Generate MSP report using LangGraph multi-agent system.
    
    Args:
        parsed_data: Parsed MSP scan data
        
    Returns:
        Complete MSP report dictionary
    """
    try:
        logger.info("🎯 Using MSP LangGraph multi-agent system for report generation")
        
        orchestrator = MSPReportOrchestrator()
        report_data = orchestrator.generate_report(parsed_data)
        
        logger.info("✅ MSP multi-agent report generation successful")
        return report_data
        
    except Exception as e:
        logger.error(f"❌ MSP multi-agent generation failed: {e}", exc_info=True)
        logger.info("⚠️  Falling back to stub report...")
        return _generate_stub_msp_report(parsed_data)


def _generate_stub_msp_report(parsed_data: Dict) -> Dict:
    """Generate basic stub report when AI generation fails."""
    endpoint_info = parsed_data.get("endpoint_info", {})
    credentials = parsed_data.get("credentials", {})
    software = parsed_data.get("software", [])
    
    browser_count = len(credentials.get("browsers", []))
    os_count = len(credentials.get("os", []))
    app_count = len(credentials.get("apps", []))
    total_creds = browser_count + os_count + app_count
    
    return {
        "report_type": "MSP Cyber Hygiene & Credential Exposure",
        "endpoint": endpoint_info.get("hostname", "Unknown"),
        "user": endpoint_info.get("user", "Unknown"),
        "assessment_date": datetime.now().strftime("%Y-%m-%d"),
        
        "executive_summary": {
            "credential_counts": {
                "browser_credentials": browser_count,
                "os_credentials": os_count,
                "app_credentials": app_count,
                "total_credentials": total_creds
            },
            "overall_risk_level": "MEDIUM",
            "risk_score": 5.0,
            "risk_reason": "Automated analysis unavailable. Manual review recommended."
        },
        
        "credential_exposure": {
            "summary": {
                "total_credentials": total_creds,
                "browser_credentials": browser_count,
                "os_credentials": os_count,
                "app_credentials": app_count
            },
            "browser_exposure": [],
            "os_credentials": [],
            "app_credentials": [],
            "key_insights": ["Detailed analysis pending - AI agent unavailable"]
        },
        
        "software_inventory": {
            "total_software": len(software),
            "high_risk_software": [],
            "outdated_software": [],
            "notable_software": [],
            "key_insights": ["Software analysis pending"]
        },
        
        "system_security": {
            "user_analysis": {},
            "login_security": {},
            "system_configuration": {},
            "key_insights": ["System security analysis pending"]
        },
        
        "risk_scoring_detailed": {
            "overall_risk_level": "MEDIUM",
            "risk_score": 5.0,
            "category_scores": {
                "credential_exposure": 5.0,
                "password_hygiene": 5.0,
                "software_risk": 5.0,
                "user_account_security": 5.0
            },
            "scoring_breakdown": {},
            "risk_factors": ["Automated analysis unavailable"]
        },
        
        "remediation_steps": {
            "immediate_actions": [],
            "medium_priority": [],
            "low_priority": [],
            "msp_recommendations": [
                "Schedule comprehensive security review",
                "Manual credential audit recommended",
                "Software inventory analysis needed"
            ]
        },
        
        "generated_at": datetime.now().isoformat()
    }


def render_msp_report(report_data: dict) -> Tuple[str, bytes]:
    """
    Render MSP report into HTML and PDF.
    
    Args:
        report_data: Complete MSP report data from agent
        
    Returns:
        Tuple of (html_string, pdf_bytes)
    """
    env = _get_env()
    template = env.get_template(MSP_TEMPLATE)
    
    # Add current timestamp for report generation
    render_context = {
        **report_data,
        "now": datetime.now(),
    }
    
    # Render HTML
    html_str = template.render(**render_context)
    
    # Generate PDF using wkhtmltoimage (HTML -> PNG -> PDF)
    logger.info("Generating MSP PDF report...")
    pdf_bytes = html_to_pdf(html_str, method="auto")
    logger.info("✅ MSP PDF generated successfully")
    
    return html_str, pdf_bytes


def generate_msp_report_from_scan(scan_json: dict) -> Tuple[str, bytes, dict, dict]:
    """
    Main workflow for MSP report generation.
    
    Steps:
    1. Parse MSP scan JSON → extract endpoint, credentials, software, system data
    2. Send parsed data to MSP LangGraph multi-agent system → generate complete report
    3. Render report → HTML/PDF
    
    Args:
        scan_json: Raw MSP scan JSON data
        
    Returns:
        Tuple of (html_string, pdf_bytes, summary_dict, report_data)
    """
    logger.info("🔄 Starting MSP report generation workflow")
    
    # Step 1: Parse scan data
    parsed_data = parse_msp_scan(scan_json)
    
    # Step 2: Generate report with LangGraph multi-agent system
    if settings.use_agent:
        report_data = generate_msp_report_with_agent(parsed_data)
    else:
        logger.info("⚠️ Agent system disabled, using stub report")
        report_data = _generate_stub_msp_report(parsed_data)
    
    # Step 3: Render HTML/PDF
    html_str, pdf_bytes = render_msp_report(report_data)
    
    # Create summary for database storage
    summary = {
        "endpoint": report_data.get("endpoint", "Unknown"),
        "user": report_data.get("user", "Unknown"),
        "total_credentials": report_data.get("executive_summary", {}).get("credential_counts", {}).get("total_credentials", 0),
        "risk_score": report_data.get("executive_summary", {}).get("risk_score", 0.0),
        "risk_level": report_data.get("executive_summary", {}).get("overall_risk_level", "Unknown"),
    }
    
    logger.info(f"✅ MSP report generation complete for {summary['endpoint']}")
    
    return html_str, pdf_bytes, summary, report_data


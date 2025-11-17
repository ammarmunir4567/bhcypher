from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional
from functools import lru_cache
import logging
logger = logging.getLogger(__name__)

from app.core.config import settings
import google.generativeai as genai


PROMPTS_DIR = Path(__file__).parent.parent / "prompts"
PROMPT_FILE = PROMPTS_DIR / "prompt.txt"

 
@lru_cache(maxsize=1)
def _load_report_prompt() -> str:
    if PROMPT_FILE.exists():
        try:
            return PROMPT_FILE.read_text(encoding="utf-8").strip()
        except Exception as e:
            raise RuntimeError(f"Failed to read prompt file at {PROMPT_FILE}: {e}")
    raise RuntimeError(
        f"Prompt file not found at {PROMPT_FILE}. Please create it to proceed."
    )


def _get_gemini_api_key() -> str:
    key = settings.gemini_api_key
    return key


def _configure_gemini() -> None:
    """Configure Gemini with API key from settings."""
    key = _get_gemini_api_key()
    if not key:
        raise RuntimeError("GEMINI_API_KEY not configured in settings")
    genai.configure(api_key=key)


def _initialize_gemini():
    """Initialize Gemini configuration at module load."""
    _configure_gemini()

_initialize_gemini()

def _extract_json_from_response(text: str) -> Optional[Dict]:
    """Extract JSON from Gemini response, handling markdown code blocks."""
    if not text:
        return None
    
    # Remove markdown code blocks if present
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("{") and part.endswith("}"):
                text = part
                break
    
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _build_prompt(parsed_scan: Dict, max_chars: int = 20000) -> str:
    """Build prompt with parsed scan data, truncating if necessary."""
    scan_json_str = json.dumps(parsed_scan, indent=2)
    
    # Truncate if too long to avoid token limits
    if len(scan_json_str) > max_chars:
        scan_json_str = scan_json_str[:max_chars] + "\n... (truncated for token limits)"
    
    base_prompt = _load_report_prompt()
    return f"{base_prompt}\n\nParsed Scan Data:\n{scan_json_str}"


def _handle_gemini_error(error: Exception) -> None:
    """Handle and log Gemini API errors appropriately."""
    error_msg = str(error)
    error_type = type(error).__name__
    
    if "API key" in error_msg or "API_KEY" in error_msg or "InvalidArgument" in error_type:
        logger.error(f"GEMINI API KEY ERROR: {error_msg}")
        logger.error("Please check your settings and ensure GEMINI_API_KEY is valid.")
    else:
        logger.exception("Unhandled Gemini error")


def generate_full_report_with_gemini(parsed_scan: Dict) -> Dict:
    """
    Generate comprehensive security report using Gemini AI.
    
    Args:
        parsed_scan: Parsed scan data dictionary with host info and findings
        
    Returns:
        Dictionary containing generated report with executive_summary, findings, etc.
    """
    try:
        model_name = settings.gemini_model
        if not model_name:
            raise RuntimeError("gemini_model not configured in settings")
        model = genai.GenerativeModel(model_name)
        
        # Build and send prompt
        prompt = _build_prompt(parsed_scan)
        logger.info(f"Calling Gemini API ({model_name}) with {len(prompt)} chars...")
        
        resp = model.generate_content(prompt)
        text = (resp.text or "").strip()
        
        logger.info(f"Gemini response length: {len(text)} chars")
        
        if not text:
            return _generate_stub_report(parsed_scan)
        
        # Extract JSON from response
        report_data = _extract_json_from_response(text)
        
        if report_data:
            logger.info("SUCCESS: Parsed JSON from Gemini response")
            return report_data
        else:
            # Fallback: parse text response into structured format
            return _parse_text_response(text, parsed_scan)
            
    except Exception as e:
        _handle_gemini_error(e)
        return _generate_stub_report(parsed_scan)


def _parse_text_response(text: str, parsed_scan: Dict) -> Dict:
    """Parse plain text response from Gemini into structured format."""
    host = parsed_scan.get("host", {})
    
    return {
        "executive_summary": text[:500] if text else "Security assessment completed.",
        "system_overview": f"Host: {host.get('hostname', 'Unknown')}, OS: {host.get('os', 'Unknown')}",
        "findings": [],
        "recommendations": "Review the generated content and apply patches.",
        "risk_score": 7.0,
        "risk_level": "High"
    }


def _generate_stub_report(parsed_scan: Dict) -> Dict:
    """
    Generate a stub report when Gemini is unavailable.
    
    This provides a basic report structure based on parsed scan data.
    """
    findings = parsed_scan.get("findings", [])
    host = parsed_scan.get("host", {})
    summary = parsed_scan.get("summary", {})
    
    hostname = host.get("hostname", "Unknown")
    os_info = host.get("os", "Unknown")
    findings_count = len(findings)
    
    # Generate stub findings
    stub_findings = []
    for finding in findings:
        cve_id = finding.get("cve_id", "N/A")
        description = finding.get("description", "No description available")
        
        stub_findings.append({
            "cve_id": cve_id,
            "title": f"Vulnerability: {cve_id}",
            "severity": "High",  # Default severity
            "description": description[:300] if description else "No description available",
            "impact": "Potential security risk requiring immediate attention",
            "recommendation": "Apply vendor patches and restrict network exposure.",
            "references": []
        })
    
    # Calculate risk score from summary if available
    risk_score = summary.get("risk_score", 7.0)
    if risk_score >= 8.0:
        risk_level = "Critical"
    elif risk_score >= 6.0:
        risk_level = "High"
    elif risk_score >= 4.0:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {
        "executive_summary": (
            f"Security scan completed for {hostname}. "
            f"Found {findings_count} vulnerabilities requiring attention. "
            f"Immediate remediation is recommended for critical and high-severity issues."
        ),
        "system_overview": (
            f"Hostname: {hostname}, "
            f"OS: {os_info} {host.get('os_version', '')}".strip()
        ),
        "findings": stub_findings,
        "recommendations": (
            "Prioritize critical and high-severity vulnerabilities. "
            "Apply vendor patches promptly, restrict network exposure, "
            "and implement security best practices."
        ),
        "risk_score": risk_score,
        "risk_level": risk_level
    }

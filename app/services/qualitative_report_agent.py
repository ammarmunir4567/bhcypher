"""
LangGraph Multi-Agent Security Report Generation System

This module implements a LangGraph-based multi-agent architecture for generating
security assessment reports with intelligent data splitting and parallel processing.

Architecture:
1. Data Splitter Node - Splits data by type to prevent context overload
2. Severity Analysis Node - Categorizes vulnerabilities (receives only findings data)
3. Parallel Processing:
   - Risk Scoring Node - Calculates risk metrics (receives only severity analysis)
   - Remediation Node - Generates fixes (receives only critical/high CVEs)
4. Report Builder Node - Assembles final report from all outputs

Key Benefits:
- Context Management: Each agent receives only relevant data portions
- Parallel Execution: Risk scoring and remediation run simultaneously
- Scalability: Easy to add new nodes for different data types
- State Management: LangGraph manages workflow state automatically

This approach prevents LLM context overload, enables parallel processing,
and improves reliability through focused, specialized agents.
"""

from __future__ import annotations

import json
import logging
import time
import operator
from typing import Dict, List, Any, Optional, TypedDict, Annotated
from pathlib import Path

from langchain_google_genai import ChatGoogleGenerativeAI
import google.generativeai as genai
from langgraph.graph import StateGraph, END
from langchain.callbacks.base import BaseCallbackHandler

from app.core.config import settings

logger = logging.getLogger(__name__)

# Configure Gemini
genai.configure(api_key=settings.gemini_api_key)


# Note: Token tracking is handled by LangSmith when LANGCHAIN_TRACING_V2=true
# No local tracking logic needed - LangSmith captures everything automatically


# ==================== LANGGRAPH STATE SCHEMA ====================

class SecurityAnalysisState(TypedDict):
    """State schema for LangGraph workflow - manages data flow between agents."""
    # Input data (read-only after initialization)
    parsed_scan: Dict
    
    # Working data
    host_info: Dict
    findings: List[Dict]
    
    # Split data for agents
    critical_high_cves: List[Dict]
    medium_low_cves: List[Dict]
    
    # Agent outputs (each node updates its own key)
    severity_analysis: Dict
    risk_score: Dict
    remediation_results: List[Dict]
    
    # Final output
    final_report: Dict
    
    # Metadata
    errors: Annotated[List[str], operator.add]


# ==================== UTILITY FUNCTIONS ====================

def _extract_json_from_text(text: str) -> Optional[Dict]:
    """Extract JSON from text that might contain markdown or other formatting."""
    if not text:
        return None
    
    # Try to find JSON in markdown code blocks
    if "```json" in text:
        try:
            json_text = text.split("```json")[1].split("```")[0].strip()
            return json.loads(json_text)
        except (IndexError, json.JSONDecodeError):
            pass
    
    # Try to find JSON in regular code blocks
    if "```" in text:
        try:
            parts = text.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("{") and part.endswith("}"):
                    return json.loads(part)
        except json.JSONDecodeError:
            pass
    
    # Try to find raw JSON
    try:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            json_text = text[start:end]
            return json.loads(json_text)
    except json.JSONDecodeError:
        pass
    
    return None


def _get_cve_description(cve_id: str, findings: List[Dict]) -> str:
    """Get description for a specific CVE from findings list."""
    for finding in findings:
        if finding.get("cve_id") == cve_id:
            return finding.get("description", "No description available")
    return "No description available"


# ==================== LANGGRAPH NODE FUNCTIONS ====================

def split_data_node(state: SecurityAnalysisState) -> Dict[str, Any]:
    """Split parsed scan data by type and size to prevent context overload."""
    parsed_scan = state["parsed_scan"]
    findings = parsed_scan.get("findings", [])
    
    logger.info(f"Data splitter: Processing {len(findings)} total findings")
    
    # Return only the keys this node updates
    return {
        "host_info": parsed_scan.get("host", {}),
        "findings": findings
    }


def severity_analysis_node(state: SecurityAnalysisState) -> Dict[str, Any]:
    """Analyze vulnerability severity - receives only findings data."""
    findings = state["findings"]
    
    agent = SeverityAnalysisAgent()
    result = agent.analyze({"findings": findings})  # Only pass findings
    
    # Split CVEs by severity for parallel remediation
    critical_high = []
    
    for cve_id in result.get("critical", {}).get("cves", []):
        critical_high.append({
            "cve_id": cve_id,
            "severity": "Critical",
            "description": _get_cve_description(cve_id, findings)
        })
    
    for cve_id in result.get("high", {}).get("cves", []):
        critical_high.append({
            "cve_id": cve_id,
            "severity": "High",
            "description": _get_cve_description(cve_id, findings)
        })
    
    logger.info(f"Severity node: Identified {len(critical_high)} critical/high CVEs")
    
    # Return only the keys this node updates
    return {
        "severity_analysis": result,
        "critical_high_cves": critical_high
    }


def risk_scoring_node(state: SecurityAnalysisState) -> Dict[str, Any]:
    """Calculate risk scores - receives only severity analysis."""
    severity_analysis = state["severity_analysis"]
    
    agent = RiskScoringAgent()
    risk_result = agent.calculate_risk(severity_analysis)
    
    # Return only the keys this node updates
    return {
        "risk_score": risk_result
    }


def remediation_critical_high_node(state: SecurityAnalysisState) -> Dict[str, Any]:
    """Process critical/high CVEs - receives only priority CVEs."""
    cves = state.get("critical_high_cves", [])
    
    if not cves:
        return {"remediation_results": []}
    
    logger.info(f"Remediation (Critical/High): Processing {len(cves)} CVEs")
    
    # Process in smaller batches to manage context
    results = []
    batch_size = 5
    
    for i in range(0, len(cves), batch_size):
        batch = cves[i:i+batch_size]
        for cve in batch:
            agent = RemediationWorkerAgent()
            result = agent.generate_remediation(cve)
            results.append(result)
    
    # Return only the keys this node updates
    return {
        "remediation_results": results
    }


def report_builder_node(state: SecurityAnalysisState) -> Dict[str, Any]:
    """Assemble final report from all agent outputs."""
    builder = ReportBuilderAgent()
    
    final_report = builder.build(
        parsed_scan=state["parsed_scan"],
        analysis=state["severity_analysis"],
        risk=state["risk_score"],
        remediations=state["remediation_results"]
    )
    
    # Return only the keys this node updates
    return {
        "final_report": final_report
    }


# ==================== SPECIALIZED AGENTS ====================

class SeverityAnalysisAgent:
    """
    Specialized agent for vulnerability severity analysis only.
    Single responsibility: categorize vulnerabilities by severity.
    
    This agent analyzes all vulnerabilities quickly without generating
    detailed remediation, keeping context focused and execution fast.
    """
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model=settings.gemini_model,
            google_api_key=settings.gemini_api_key,
            temperature=0.1,  # Low temperature for consistent categorization
            convert_system_message_to_human=True
        )
    
    def analyze(self, parsed_scan: Dict) -> Dict:
        """
        Analyze all vulnerabilities and categorize by severity.
        Returns structured breakdown without remediation details.
        
        Args:
            parsed_scan: Parsed scan data with findings
            
        Returns:
            Dict with severity breakdown and CVE lists
        """
        findings = parsed_scan.get("findings", [])
        
        if not findings:
            return {"total": 0, "critical": {"count": 0, "cves": []}, 
                    "high": {"count": 0, "cves": []}, "medium": {"count": 0, "cves": []}, 
                    "low": {"count": 0, "cves": []}}
        
        logger.info(f"📊 Analyzing {len(findings)} vulnerabilities for severity")
        
        # Create focused prompt for severity analysis only
        vulns_summary = [
            {
                "cve_id": f.get("cve_id", "UNKNOWN"),
                "description": f.get("description", "")[:200]
            }
            for f in findings
        ]
        
        prompt = f"""Analyze these {len(findings)} vulnerabilities from a comprehensive security assessment and categorize by severity.

IMPORTANT: This scan includes:
- CVE vulnerabilities from installed software
- Exposed credentials (browsers, OS, applications)
- System configuration (open ports, services, network connections)
- Hardware and software inventory

Vulnerabilities:
{json.dumps(vulns_summary, indent=2)}

Return ONLY this JSON structure (no other text):
{{
  "total": {len(findings)},
  "critical": {{"count": 0, "cves": []}},
  "high": {{"count": 0, "cves": []}},
  "medium": {{"count": 0, "cves": []}},
  "low": {{"count": 0, "cves": []}}
}}

Severity Categorization Rules:
- Critical (9.0-10.0): Remote code execution, privilege escalation, authentication bypass, exposed credentials with direct system access
- High (7.0-8.9): Credential exposure, data leakage, SQL injection, weak encryption, publicly exposed critical ports (3306, 445, 135)
- Medium (4.0-6.9): XSS, CSRF, information disclosure, outdated software with known vulnerabilities, unnecessary open ports
- Low (0.1-3.9): Minor configuration issues, deprecated features, informational findings

Consider the overall security posture including system exposure, credential harvesting results, and network configuration."""
        
        try:
            response = self.llm.invoke(prompt)
            result = _extract_json_from_text(response.content)
            
            if result:
                logger.info(f"✅ Severity analysis: {result.get('critical', {}).get('count', 0)} critical, "
                           f"{result.get('high', {}).get('count', 0)} high, "
                           f"{result.get('medium', {}).get('count', 0)} medium, "
                           f"{result.get('low', {}).get('count', 0)} low")
                return result
            else:
                logger.warning("Could not parse severity analysis, using fallback")
                return self._fallback_analysis(findings)
                
        except Exception as e:
            logger.error(f"❌ Severity analysis failed: {e}")
            return self._fallback_analysis(findings)
    
    def _fallback_analysis(self, findings: List[Dict]) -> Dict:
        """Simple keyword-based fallback when AI analysis fails."""
        result = {
            "total": len(findings),
            "critical": {"count": 0, "cves": []},
            "high": {"count": 0, "cves": []},
            "medium": {"count": 0, "cves": []},
            "low": {"count": 0, "cves": []}
        }
        
        for finding in findings:
            cve_id = finding.get("cve_id", "UNKNOWN")
            desc = finding.get("description", "").lower()
            
            if any(kw in desc for kw in ["remote code execution", "rce", "privilege escalation", "buffer overflow"]):
                result["critical"]["count"] += 1
                result["critical"]["cves"].append(cve_id)
            elif any(kw in desc for kw in ["sql injection", "authentication bypass", "data exposure"]):
                result["high"]["count"] += 1
                result["high"]["cves"].append(cve_id)
            elif any(kw in desc for kw in ["xss", "csrf", "denial of service", "information disclosure"]):
                result["medium"]["count"] += 1
                result["medium"]["cves"].append(cve_id)
            else:
                result["low"]["count"] += 1
                result["low"]["cves"].append(cve_id)
        
        return result


class RiskScoringAgent:
    """
    Specialized agent for calculating risk scores.
    Uses weighted severity counts to generate overall risk metrics.
    """
    
    def calculate_risk(self, analysis_result: Dict) -> Dict:
        """
        Calculate overall risk score and level from severity analysis.
        
        Args:
            analysis_result: Output from SeverityAnalysisAgent
            
        Returns:
            Dict with risk_score, risk_level, and details
        """
        logger.info("📈 Calculating risk scores")
        
        critical_count = analysis_result.get("critical", {}).get("count", 0)
        high_count = analysis_result.get("high", {}).get("count", 0)
        medium_count = analysis_result.get("medium", {}).get("count", 0)
        low_count = analysis_result.get("low", {}).get("count", 0)
        total = analysis_result.get("total", 0)
        
        # Weighted risk calculation
        critical_weight = 10.0
        high_weight = 7.0
        medium_weight = 4.0
        low_weight = 1.0
        
        weighted_sum = (
            critical_count * critical_weight +
            high_count * high_weight +
            medium_count * medium_weight +
            low_count * low_weight
        )
        
        # Normalize to 0-10 scale
        risk_score = min(10.0, (weighted_sum / max(total, 1)) * 1.5) if total > 0 else 0.0
        
        # Determine risk level
        if risk_score >= 8.0:
            risk_level = "Critical"
        elif risk_score >= 6.0:
            risk_level = "High"
        elif risk_score >= 4.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        result = {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "details": {
                "critical_vulns": critical_count,
                "high_vulns": high_count,
                "medium_vulns": medium_count,
                "low_vulns": low_count,
                "total_vulns": total
            }
        }
        
        logger.info(f"✅ Risk: {result['risk_score']}/10.0 ({result['risk_level']})")
        return result


class RemediationWorkerAgent:
    """
    Individual worker agent for generating remediation for ONE CVE.
    Lightweight, focused on single task.
    """
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model=settings.gemini_model,
            google_api_key=settings.gemini_api_key,
            temperature=0.2,
            convert_system_message_to_human=True
        )
    
    def generate_remediation(self, cve: Dict) -> Dict:
        """
        Generate detailed remediation for a single CVE.
        
        Args:
            cve: Dict with cve_id, severity, description
            
        Returns:
            Dict with remediation details
        """
        cve_id = cve.get("cve_id", "UNKNOWN")
        severity = cve.get("severity", "Unknown")
        description = cve.get("description", "")[:500]
        
        logger.info(f"🔧 Starting remediation for {cve_id} ({severity})")
        start_time = time.time()
        
        # Focused prompt for single CVE remediation with context
        prompt = f"""Generate actionable remediation recommendations for this security finding from a comprehensive penetration test.

CONTEXT: This assessment includes credential harvesting, system reconnaissance, network exposure analysis, and CVE vulnerability scanning.

Finding ID: {cve_id}
Severity: {severity}
Description: {description}

Provide ONLY valid JSON with this structure:
{{
  "cve_id": "{cve_id}",
  "severity": "{severity}",
  "priority": "Immediate (24-48 hours)|Short-term (1-2 weeks)|Long-term (1-3 months)",
  "steps": [
    "Specific action step 1",
    "Specific action step 2",
    "Specific action step 3"
  ],
  "references": ["NIST SP 800-53", "OWASP Top 10", "CIS Controls", "NVD"]
}}

Focus on:
1. IMMEDIATE actionable remediation steps (not theoretical advice)
2. Specific patches, upgrades, or configuration changes
3. Compensating controls if immediate fix unavailable
4. Detection and monitoring recommendations
5. Consider if this is a CVE, credential exposure, or system misconfiguration
6. Address both the vulnerability AND how it was discovered (credential dump, port scan, etc.)"""
        
        try:
            logger.info(f"🤖 Calling Gemini API for {cve_id}...")
            response = self.llm.invoke(prompt)
            api_elapsed = time.time() - start_time
            logger.info(f"📡 API response received for {cve_id} in {api_elapsed:.1f}s")
            
            result = _extract_json_from_text(response.content)
            
            if result and result.get("cve_id"):
                total_elapsed = time.time() - start_time
                logger.info(f"✅ Remediation complete for {cve_id} (total: {total_elapsed:.1f}s)")
                return result
            else:
                logger.warning(f"⚠️ Could not parse remediation for {cve_id}, using stub")
                return self._stub_remediation(cve_id, severity)
                
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"❌ Remediation generation failed for {cve_id} after {elapsed:.1f}s: {e}")
            return self._stub_remediation(cve_id, severity)
    
    def _stub_remediation(self, cve_id: str, severity: str) -> Dict:
        """Generate basic stub remediation when AI fails."""
        return {
            "cve_id": cve_id,
            "severity": severity,
            "priority": "Immediate (24-48 hours)" if severity in ["Critical", "High"] else "Short-term (1-2 weeks)",
            "steps": [
                f"Review {cve_id} details at https://nvd.nist.gov/vuln/detail/{cve_id}",
                "Check vendor security advisories for patches",
                "Apply security updates following change management procedures",
                "Verify remediation through vulnerability scanning"
            ],
            "references": ["NVD", "vendor security advisory", "NIST SP 800-53"]
        }


class RemediationAgentPool:
    """
    Sequential processor for CVE remediation.
    Each CVE is processed one at a time with detailed logging.
    """
    
    def __init__(self):
        logger.info(f"🏊 RemediationAgentPool initialized (sequential processing mode)")
    
    def process_sequential(self, cves: List[Dict]) -> List[Dict]:
        """
        Process multiple CVEs sequentially.
        
        Args:
            cves: List of CVE dicts to process
            
        Returns:
            List of remediation results
        """
        if not cves:
            return []
        
        results = []
        total = len(cves)
        
        logger.info(f"🔧 Processing {total} CVEs sequentially")
        overall_start_time = time.time()
        
        # Process each CVE one at a time
        for idx, cve in enumerate(cves, start=1):
            cve_id = cve.get("cve_id", "UNKNOWN")
            logger.info(f"📦 Processing CVE {idx}/{total}: {cve_id}")
            
            # Create agent and generate remediation
            agent = RemediationWorkerAgent()
            
            try:
                result = agent.generate_remediation(cve)
                results.append(result)
                logger.info(f"✅ Successfully processed {idx}/{total}: {cve_id}")
            except Exception as e:
                logger.error(f"❌ Failed to process {cve_id}: {e}")
                # Add stub remediation for failed CVEs
                results.append(self._create_stub_remediation(cve))
        
        overall_elapsed = time.time() - overall_start_time
        logger.info(f"✅ Sequential remediation complete: {len(results)}/{total} processed in {overall_elapsed:.1f}s")
        return results
    
    def _create_stub_remediation(self, cve: Dict) -> Dict:
        """Create stub remediation for a CVE when processing fails or times out."""
        cve_id = cve.get("cve_id", "UNKNOWN")
        severity = cve.get("severity", "Unknown")
        return {
            "cve_id": cve_id,
            "severity": severity,
            "priority": "Immediate (24-48 hours)" if severity in ["Critical", "High"] else "Short-term (1-2 weeks)",
            "steps": [
                f"Review {cve_id} details at https://nvd.nist.gov/vuln/detail/{cve_id}",
                "Check vendor security advisories for patches",
                "Apply security updates following change management procedures",
                "Verify remediation through vulnerability scanning"
            ],
            "references": ["NVD", "vendor security advisory", "NIST SP 800-53"]
        }


class ReportBuilderAgent:
    """
    Agent that assembles final report from sub-agent outputs.
    No heavy AI calls - just structuring and formatting data.
    """
    
    def _infer_assessment_scope(self, parsed_scan: Dict) -> List[Dict]:
        """Generate assessment scope based on actual scan data."""
        scope_items = []
        
        # Extract data
        open_ports = parsed_scan.get("system_data", {}).get("open_ports", [])
        credentials = parsed_scan.get("credentials", {})
        browsers = credentials.get("browsers", [])
        apps = credentials.get("apps", [])
        
        # Identify external network scope from open ports
        external_ports = [p for p in open_ports if p.get("local_address") in ["0.0.0.0", "::"]]
        if external_ports:
            critical_ports = [p["port"] for p in external_ports if p["port"] in [21, 22, 23, 80, 443, 3306, 445, 135, 139, 1433, 5432]]
            if critical_ports:
                scope_items.append({
                    "label": "External Network",
                    "value": f"Public-facing services on ports: {', '.join(map(str, critical_ports[:10]))}"
                })
            else:
                scope_items.append({"label": "External Network", "value": "Network perimeter and exposed services"})
        else:
            scope_items.append({"label": "External Network", "value": "NA"})
        
        # Identify internal network from local ports
        local_ports = [p for p in open_ports if p.get("local_address") not in ["0.0.0.0", "::", None]]
        if local_ports:
            scope_items.append({
                "label": "Internal Network",
                "value": f"Internal services and {len(set([p['local_address'] for p in local_ports]))} network interfaces"
            })
        else:
            scope_items.append({"label": "Internal Network", "value": "NA"})
        
        # Identify web applications from browsers
        if browsers:
            unique_urls = set([b.get("url", "").split("//")[-1].split("/")[0] for b in browsers if b.get("url")])
            scope_items.append({
                "label": "Web Applications",
                "value": f"Browser credential analysis covering {len(unique_urls)} web services"
            })
        else:
            scope_items.append({"label": "Web Applications", "value": "NA"})
        
        # Identify endpoint applications
        if apps:
            app_names = [a.get("application") for a in apps if a.get("application")]
            scope_items.append({
                "label": "Endpoint Applications",
                "value": f"Application credential analysis: {', '.join(app_names[:5])}"
            })
        else:
            scope_items.append({"label": "Wireless Networks", "value": "NA"})
        
        return scope_items
    
    def _infer_testing_methodology(self, parsed_scan: Dict) -> List[Dict]:
        """Generate testing methodology based on what was actually performed."""
        methodologies = []
        
        # Extract data to determine what was tested
        credentials = parsed_scan.get("credentials", {})
        system_data = parsed_scan.get("system_data", {})
        open_ports = system_data.get("open_ports", [])
        browsers = credentials.get("browsers", [])
        apps = credentials.get("apps", [])
        os_creds = credentials.get("os", [])
        findings = parsed_scan.get("findings", [])
        
        # Reconnaissance - if we have ports or system data
        if open_ports or system_data.get("installed_software"):
            methodologies.append({
                "title": "Reconnaissance",
                "description": f"System enumeration identified {len(open_ports)} open ports, "
                               f"{len(system_data.get('installed_software', []))} installed applications, "
                               f"and network topology mapping to establish attack surface."
            })
        else:
            methodologies.append({"title": "Reconnaissance", "description": "NA"})
        
        # Vulnerability Analysis - if we have CVEs
        if findings:
            methodologies.append({
                "title": "Vulnerability Analysis",
                "description": f"Automated CVE scanning and manual security assessment identified "
                               f"{len(findings)} vulnerabilities across system components and services."
            })
        else:
            methodologies.append({"title": "Vulnerability Analysis", "description": "NA"})
        
        # Exploitation/Credential Harvesting - if we have credentials
        total_creds = len(browsers) + len(apps) + len(os_creds)
        if total_creds > 0:
            methodologies.append({
                "title": "Exploitation",
                "description": f"Credential harvesting successfully extracted {total_creds} credential sets from "
                               f"{len(browsers)} browsers, {len(apps)} applications, and {len(os_creds)} OS stores, "
                               f"demonstrating critical security exposure and potential for lateral movement."
            })
        else:
            methodologies.append({"title": "Exploitation", "description": "NA"})
        
        # Post-Exploitation - if we have high-risk findings
        if findings or total_creds > 0:
            methodologies.append({
                "title": "Post-Exploitation",
                "description": f"Impact analysis assessed potential for privilege escalation, lateral movement, "
                               f"and data exfiltration based on {total_creds} exposed credentials and "
                               f"discovered vulnerabilities across critical services."
            })
        else:
            methodologies.append({"title": "Post-Exploitation", "description": "NA"})
        
        return methodologies
    
    def build(
        self,
        parsed_scan: Dict,
        analysis: Dict,
        risk: Dict,
        remediations: List[Dict]
    ) -> Dict:
        """
        Build final report from all sub-agent outputs.
        
        Args:
            parsed_scan: Original parsed scan data
            analysis: Output from SeverityAnalysisAgent
            risk: Output from RiskScoringAgent
            remediations: Output from RemediationAgentPool
            
        Returns:
            Complete structured report dictionary
        """
        logger.info("📝 Building final report")
        
        host = parsed_scan.get("host", {})
        findings = parsed_scan.get("findings", [])
        
        # Build findings list with remediation
        final_findings = []
        remediation_map = {r.get("cve_id"): r for r in remediations}
        
        for finding in findings:
            cve_id = finding.get("cve_id", "UNKNOWN")
            
            # Find matching remediation
            remediation = remediation_map.get(cve_id)
            
            # Get severity from analysis
            severity = self._get_severity(cve_id, analysis)
            
            # Build finding entry using AI-generated data
            if remediation:
                # Use rich AI-generated remediation data
                finding_entry = {
                    "cve_id": cve_id,
                    "title": f"Vulnerability: {cve_id}",
                    "severity": severity,
                    "description": finding.get("description", "No description available")[:500],
                    "impact": self._extract_impact_from_remediation(remediation, severity),
                    "recommendation": remediation,  # Keep full structured remediation
                    "references": remediation.get("references", ["NVD", "NIST"])
                }
            else:
                # Fallback for CVEs without detailed remediation
                finding_entry = {
                    "cve_id": cve_id,
                    "title": f"Vulnerability: {cve_id}",
                    "severity": severity,
                    "description": finding.get("description", "No description available")[:500],
                    "impact": f"{severity} severity vulnerability requiring security assessment and remediation",
                    "recommendation": {
                        "priority": "Immediate (24-48 hours)" if severity in ["Critical", "High"] else "Short-term (1-2 weeks)",
                        "steps": [f"Review {cve_id} at https://nvd.nist.gov/vuln/detail/{cve_id}", "Apply vendor security patches"],
                        "references": ["NVD", "NIST"]
                    },
                    "references": ["NVD", "NIST"]
                }
            
            final_findings.append(finding_entry)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(host, analysis, risk)
        
        # Generate overall recommendations
        overall_recommendations = self._generate_overall_recommendations(analysis, remediations)
        
        # Extract severity counts for template
        critical_count = analysis.get("critical", {}).get("count", 0)
        high_count = analysis.get("high", {}).get("count", 0)
        medium_count = analysis.get("medium", {}).get("count", 0)
        low_count = analysis.get("low", {}).get("count", 0)
        
        # Extract client/hostname info
        hostname = host.get("hostname", "Unknown")
        
        # Generate attack vectors and security concerns based on findings AND pentest data
        attack_vectors = self._generate_attack_vectors(final_findings, parsed_scan)
        security_concerns = self._generate_security_concerns(analysis, risk, parsed_scan)
        
        # Generate assessment scope and testing methodology from actual scan data
        assessment_scope = self._infer_assessment_scope(parsed_scan)
        testing_methodology = self._infer_testing_methodology(parsed_scan)
        
        # Extract metadata from scan
        scan_metadata = parsed_scan.get("scan_metadata", {})
        scan_timestamp = scan_metadata.get("scan_timestamp") or scan_metadata.get("collected_at")
        
        # Parse assessment period from timestamp if available
        assessment_period = "NA"
        if scan_timestamp:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(scan_timestamp.replace("Z", "+00:00"))
                assessment_period = dt.strftime("%B %d, %Y")
            except:
                assessment_period = "NA"
        
        # Assemble final report
        report = {
            "executive_summary": executive_summary,
            "system_overview": f"Hostname: {hostname}, OS: {host.get('os', 'Unknown')} {host.get('os_version', '')}",
            "findings": final_findings,
            "recommendations": overall_recommendations,
            "risk_score": risk.get("risk_score", 0.0),
            "risk_level": risk.get("risk_level", "Unknown"),
            "severity_breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "info": 0
            },
            # Individual counts for template convenience
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "info_count": 0,
            # Metadata fields
            "client_name": hostname,  # Use hostname as client name
            "assessment_period": assessment_period,
            "lead_consultant": "Cybersecurity Assessment Team",
            "test_type": "Red Team Security Assessment",
            # Generated sections
            "assessment_scope": assessment_scope,
            "testing_methodology": testing_methodology,
            "attack_vectors": attack_vectors,
            "security_concerns": security_concerns
        }
        
        logger.info("✅ Final report assembled with inferred metadata")
        return report
    
    def _generate_attack_vectors(self, findings: List[Dict], parsed_scan: Dict = None) -> List[Dict]:
        """
        Generate attack vector likelihood scores based on findings AND pentest data.
        Maps vulnerabilities, open ports, and credentials to attack vectors.
        """
        # Common attack vectors and their base scores (pentest perspective)
        attack_vector_mapping = {
            "SQL Injection": {"keywords": ["sql", "injection", "sqli", "mysql", "database"], "base_score": 95, "ports": [3306, 1433, 5432]},
            "Credential Stuffing": {"keywords": ["credential", "password", "auth", "browser", "stored password"], "base_score": 92, "ports": []},
            "Remote Code Execution": {"keywords": ["rce", "remote code", "execution", "buffer overflow", "samba"], "base_score": 95, "ports": [445, 139]},
            "Cross-Site Scripting (XSS)": {"keywords": ["xss", "cross-site scripting", "script"], "base_score": 85, "ports": [80, 443, 8080]},
            "Authentication Bypass": {"keywords": ["auth bypass", "authentication", "bypass", "weak auth"], "base_score": 89, "ports": []},
            "Privilege Escalation": {"keywords": ["privilege", "escalation", "privesc", "admin", "root"], "base_score": 78, "ports": []},
            "Server-Side Request Forgery": {"keywords": ["ssrf", "server-side request"], "base_score": 71, "ports": []},
            "Insecure Direct Object Reference": {"keywords": ["idor", "direct object", "access control"], "base_score": 68, "ports": []},
            "Command Injection": {"keywords": ["command injection", "os command"], "base_score": 88, "ports": []},
            "Security Misconfiguration": {"keywords": ["misconfiguration", "config", "open port", "exposed"], "base_score": 62, "ports": []},
            "Lateral Movement": {"keywords": ["smb", "445", "network", "rdp", "139"], "base_score": 74, "ports": [445, 139, 3389]},
            "Data Exfiltration": {"keywords": ["file", "ftp", "data", "download", "upload"], "base_score": 71, "ports": [21, 22]},
            "Credential Harvesting": {"keywords": ["credential", "keychain", "vault", "saved password"], "base_score": 85, "ports": []},
        }
        
        # Extract pentest data if available
        open_ports = []
        credentials_found = False
        if parsed_scan:
            open_ports = [p.get("port") for p in parsed_scan.get("system_data", {}).get("open_ports", [])]
            creds = parsed_scan.get("credentials", {})
            credentials_found = len(creds.get("browsers", [])) + len(creds.get("apps", [])) + len(creds.get("os", [])) > 0
        
        # Calculate scores based on findings AND pentest data
        vector_scores = {}
        for vector_name, mapping in attack_vector_mapping.items():
            matched = False
            severity_boost = 0
            
            # Check CVE findings
            for finding in findings:
                description = (finding.get("description", "") + " " + finding.get("title", "")).lower()
                severity = finding.get("severity", "").lower()
                
                # Check if any keywords match
                if any(keyword in description for keyword in mapping["keywords"]):
                    matched = True
                    # Boost score based on severity
                    if severity == "critical":
                        severity_boost = max(severity_boost, 10)
                    elif severity == "high":
                        severity_boost = max(severity_boost, 5)
                    elif severity == "medium":
                        severity_boost = max(severity_boost, 0)
                    else:
                        severity_boost = max(severity_boost, -10)
            
            # Check open ports (increase likelihood if relevant port is open)
            port_boost = 0
            if mapping.get("ports"):
                for port in mapping["ports"]:
                    if port in open_ports:
                        matched = True
                        port_boost = 15  # Significant boost for exposed ports
                        break
            
            # Check credentials (massive boost for credential stuffing)
            if vector_name == "Credential Stuffing" and credentials_found:
                matched = True
                severity_boost = max(severity_boost, 20)  # Credentials found = very high likelihood
            
            if matched:
                final_score = min(100, mapping["base_score"] + severity_boost + port_boost)
                vector_scores[vector_name] = final_score
        
        # Build vector list with class assignment
        vectors = []
        for vector_name, score in vector_scores.items():
            if score >= 90:
                vector_class = "critical"
            elif score >= 70:
                vector_class = "high"
            elif score >= 50:
                vector_class = "medium"
            else:
                vector_class = "low"
            
            vectors.append({
                "name": vector_name,
                "score": score,
                "class": vector_class
            })
        
        # Sort by score descending
        vectors.sort(key=lambda x: x["score"], reverse=True)
        return vectors
    
    def _generate_security_concerns(self, analysis: Dict, risk: Dict, parsed_scan: Dict = None) -> List[Dict]:
        """
        Generate security concerns based on analysis, risk data, AND actual pentest findings.
        """
        concerns = []
        
        # Calculate prevalence based on severity counts
        critical_count = analysis.get("critical", {}).get("count", 0)
        high_count = analysis.get("high", {}).get("count", 0)
        medium_count = analysis.get("medium", {}).get("count", 0)
        total = analysis.get("total", 1)  # Avoid division by zero
        
        # Extract pentest data
        open_ports_count = 0
        critical_ports_count = 0
        credentials_count = 0
        if parsed_scan:
            open_ports = parsed_scan.get("system_data", {}).get("open_ports", [])
            open_ports_count = len(open_ports)
            critical_ports = [p for p in open_ports if p.get("port") in [21, 22, 23, 135, 139, 445, 3306, 3389, 1433, 5432]]
            critical_ports_count = len(critical_ports)
            
            creds = parsed_scan.get("credentials", {})
            credentials_count = len(creds.get("browsers", [])) + len(creds.get("apps", [])) + len(creds.get("os", []))
        
        # Unpatched critical vulnerabilities
        if critical_count > 0:
            prevalence = min(100, int((critical_count / total) * 100) + 60)
            concerns.append({"name": "Unpatched Critical Vulnerabilities", "score": f"{prevalence}%"})
        
        # Weak authentication / Exposed credentials (CRITICAL if credentials found)
        if credentials_count > 0:
            prevalence = min(100, 70 + (credentials_count * 3))
            concerns.append({"name": "Weak Credential Storage", "score": f"{prevalence}%"})
        elif critical_count + high_count > 0:
            prevalence = min(95, int((high_count / total) * 100) + 50)
            concerns.append({"name": "Weak Authentication Mechanisms", "score": f"{prevalence}%"})
        
        # Missing security headers (common issue)
        if medium_count > 0:
            prevalence = min(90, int((medium_count / total) * 100) + 40)
            concerns.append({"name": "Missing Security Headers", "score": f"{prevalence}%"})
        
        # Open unnecessary ports (based on actual port count)
        if critical_ports_count > 0:
            prevalence = min(95, 70 + (critical_ports_count * 5))
            concerns.append({"name": "Exposed Critical Services", "score": f"{prevalence}%"})
        elif open_ports_count > 10:
            prevalence = min(85, 50 + (open_ports_count * 2))
            concerns.append({"name": "Open Unnecessary Ports", "score": f"{prevalence}%"})
        
        # Outdated software versions (inferred from CVE presence)
        if high_count + critical_count > 0:
            prevalence = min(85, 55 + (critical_count * 10))
            concerns.append({"name": "Outdated Software Versions", "score": f"{prevalence}%"})
        
        # Insufficient access controls (based on findings + open ports)
        if medium_count + high_count > 0 or critical_ports_count > 3:
            prevalence = min(80, 45 + (medium_count * 5) + (critical_ports_count * 3))
            concerns.append({"name": "Insufficient Access Controls", "score": f"{prevalence}%"})
        
        return concerns
    
    def _get_severity(self, cve_id: str, analysis: Dict) -> str:
        """Get severity level for a specific CVE."""
        for level in ["critical", "high", "medium", "low"]:
            cves = analysis.get(level, {}).get("cves", [])
            if cve_id in cves:
                return level.capitalize()
        return "Unknown"
    
    def _extract_impact_from_remediation(self, remediation: Dict, severity: str) -> str:
        """
        Extract or generate impact assessment from remediation data.
        Uses the AI-generated steps to infer impact.
        """
        steps = remediation.get("steps", [])
        priority = remediation.get("priority", "")
        
        # Build impact based on AI-generated remediation urgency and steps
        if priority and "Immediate" in priority:
            impact_base = f"{severity} severity vulnerability with immediate exploitation risk."
        elif priority and "Short-term" in priority:
            impact_base = f"{severity} severity vulnerability requiring prompt attention."
        else:
            impact_base = f"{severity} severity vulnerability."
        
        # Add context from first step if available
        if steps and len(steps) > 0:
            first_step = str(steps[0])[:150]
            # Infer impact from remediation type
            if "isolate" in first_step.lower() or "disconnect" in first_step.lower():
                return f"{impact_base} Poses significant risk requiring immediate network isolation."
            elif "upgrade" in first_step.lower() or "patch" in first_step.lower():
                return f"{impact_base} Known vulnerability with available security patches."
            elif "firewall" in first_step.lower() or "block" in first_step.lower():
                return f"{impact_base} Requires immediate access controls to prevent exploitation."
        
        return f"{impact_base} Requires security assessment and remediation."
    
    def _generate_executive_summary(self, host: Dict, analysis: Dict, risk: Dict) -> str:
        """Generate comprehensive executive summary from penetration test results."""
        hostname = host.get("hostname", "system")
        total = analysis.get("total", 0)
        critical = analysis.get("critical", {}).get("count", 0)
        high = analysis.get("high", {}).get("count", 0)
        risk_score = risk.get("risk_score", 0.0)
        risk_level = risk.get("risk_level", "Unknown")
        
        return (
            f"Comprehensive penetration testing assessment of {hostname} revealed significant security exposures "
            f"with an overall risk score of {risk_score}/10.0 ({risk_level}). "
            f"The assessment conducted credential harvesting, system reconnaissance, network exposure analysis, and vulnerability scanning, "
            f"identifying {total} security findings including {critical} critical and {high} high-severity issues. "
            f"Key concerns include exposed credentials from browsers and applications, publicly accessible critical services, "
            f"outdated software with known CVE vulnerabilities, and weak system configuration. "
            f"Immediate remediation of critical findings is essential to prevent unauthorized access, data exfiltration, "
            f"and potential system compromise. This report provides detailed findings, exploitation likelihood analysis, "
            f"and prioritized remediation steps aligned with NIST SP 800-53 and OWASP security frameworks."
        )
    
    def _generate_overall_recommendations(self, analysis: Dict, remediations: List[Dict]) -> str:
        """
        Generate prioritized overall recommendations from AI-generated remediation data.
        Uses actual remediation priorities and steps instead of generic templates.
        """
        critical = analysis.get("critical", {}).get("count", 0)
        high = analysis.get("high", {}).get("count", 0)
        immediate_count = critical + high
        
        recommendations = []
        
        # Add penetration test specific recommendations first
        recommendations.append(
            "**CRITICAL - Credential Security (0-7 days)**: "
            "All exposed credentials from browsers, applications, and OS must be immediately rotated. "
            "Implement enterprise password manager, enforce MFA across all applications, "
            "and disable credential storage in browsers. Credentials extracted demonstrate full system compromise capability."
        )
        
        recommendations.append(
            "**HIGH - Network Exposure (0-14 days)**: "
            "Critical services (MySQL 3306, SMB 445, RPC 135) are publicly accessible. "
            "Implement network segmentation, restrict external access via firewall rules, "
            "deploy VPN for remote access, and enable monitoring/alerting on these ports."
        )
        
        recommendations.append(
            "**HIGH - System Hardening (1-4 weeks)**: "
            "Update all outdated software with known CVE vulnerabilities. "
            "Remove unnecessary services and open ports. "
            "Implement host-based firewall rules, enable Windows Defender with latest definitions, "
            "and deploy endpoint detection and response (EDR) solution."
        )
        
        # Extract priority-based recommendations from AI-generated remediations
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []
        
        for remediation in remediations:
            priority = remediation.get("priority", "")
            steps = remediation.get("steps", [])
            cve_id = remediation.get("cve_id", "")
            
            if steps:
                # Extract first 1-2 key actions from AI recommendations
                key_action = str(steps[0]) if len(steps) > 0 else ""
                
                if "Immediate" in priority:
                    if key_action and cve_id:
                        immediate_actions.append(f"{cve_id}: {key_action[:150]}")
                elif "Short-term" in priority:
                    if key_action:
                        short_term_actions.append(key_action[:150])
                else:
                    if key_action:
                        long_term_actions.append(key_action[:150])
        
        # Build recommendations from AI-generated data
        if immediate_count > 0 and immediate_actions:
            recommendations.append(
                f"**Immediate Priority ({immediate_count} CVEs)**: " + 
                " | ".join(immediate_actions[:3])  # Top 3 immediate actions
            )
        elif immediate_count > 0:
            recommendations.append(
                f"**Immediate Priority**: Address {immediate_count} critical/high severity "
                f"vulnerabilities within 24-48 hours based on detailed remediation steps provided above."
            )
        
        if short_term_actions:
            recommendations.append(
                "**Short-term Actions**: " + " | ".join(set(short_term_actions[:2]))  # Unique top 2
            )
        
        if long_term_actions:
            recommendations.append(
                "**Long-term Improvements**: " + " | ".join(set(long_term_actions[:2]))  # Unique top 2
            )
        
        # Add general best practices only if no AI recommendations available
        if not recommendations:
            recommendations.append(
                "**Patch Management**: Implement a systematic patch management process to "
                "regularly apply security updates following vendor advisories."
            )
            recommendations.append(
                "**Vulnerability Scanning**: Conduct regular automated vulnerability scans "
                "(weekly or monthly) to identify new vulnerabilities promptly."
            )
        
        return " ".join(recommendations)


# ==================== ORCHESTRATOR ====================

def create_security_workflow():
    """
    Factory function for LangSmith/LangGraph deployment.
    Returns a compiled StateGraph that can be invoked directly.
    
    Usage:
        graph = create_security_workflow()
        result = graph.invoke(initial_state)
    """
    orchestrator = SecurityReportOrchestrator()
    return orchestrator.graph


class SecurityReportOrchestrator:
    """
    LangGraph-based orchestrator with parallel processing and data splitting.
    
    Workflow:
    1. Data Splitting - Separate data by type to prevent context overload
    2. Severity Analysis - Categorize vulnerabilities (receives only findings)
    3. Parallel Processing:
       - Risk Scoring (receives only severity analysis)
       - Remediation (receives only critical/high CVEs)
    4. Report Assembly - Merge all outputs into final report
    """
    
    def __init__(self):
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build LangGraph workflow with parallel execution."""
        workflow = StateGraph(SecurityAnalysisState)
        
        # Add nodes (node names must differ from state keys)
        workflow.add_node("split_data", split_data_node)
        workflow.add_node("analyze_severity", severity_analysis_node)
        workflow.add_node("score_risk", risk_scoring_node)
        workflow.add_node("generate_remediations", remediation_critical_high_node)
        workflow.add_node("build_report", report_builder_node)
        
        # Define edges for sequential and parallel execution
        workflow.set_entry_point("split_data")
        workflow.add_edge("split_data", "analyze_severity")
        
        # Parallel execution: severity -> both risk_scoring AND remediation
        workflow.add_edge("analyze_severity", "score_risk")
        workflow.add_edge("analyze_severity", "generate_remediations")
        
        # Both must complete before report building
        workflow.add_edge("score_risk", "build_report")
        workflow.add_edge("generate_remediations", "build_report")
        
        workflow.add_edge("build_report", END)
        
        return workflow.compile()
    
    def generate_report(self, parsed_scan: Dict) -> Dict:
        """
        Execute LangGraph workflow to generate report.
        
        Args:
            parsed_scan: Parsed scan data with host info and findings
            
        Returns:
            Complete security assessment report
        """
        try:
            logger.info("🎯 Starting LangGraph multi-agent workflow")
            logger.info("💡 Token tracking: Use LangSmith (set LANGCHAIN_TRACING_V2=true in .env)")
            
            initial_state = SecurityAnalysisState(
                parsed_scan=parsed_scan,
                host_info={},
                findings=[],
                critical_high_cves=[],
                medium_low_cves=[],
                severity_analysis={},
                risk_score={},
                remediation_results=[],
                final_report={},
                errors=[]
            )
            
            # Execute graph (LangSmith automatically tracks tokens if enabled)
            final_state = self.graph.invoke(initial_state)
            
            final_report = final_state["final_report"]
            
            logger.info("✅ LangGraph workflow complete")
            logger.info("📊 View token usage at: https://smith.langchain.com/ (if LangSmith enabled)")
            
            return final_report
            
        except Exception as e:
            logger.error(f"❌ LangGraph orchestrator error: {e}", exc_info=True)
            return self._generate_fallback_report(parsed_scan)
    
    def _generate_fallback_report(self, parsed_scan: Dict) -> Dict:
        """Generate basic fallback report when orchestration fails."""
        host = parsed_scan.get("host", {})
        findings = parsed_scan.get("findings", [])
        
        logger.warning("Using fallback report generation")
        
        return {
            "executive_summary": f"Security scan for {host.get('hostname', 'system')} identified {len(findings)} vulnerabilities requiring attention.",
            "system_overview": f"Hostname: {host.get('hostname', 'Unknown')}, OS: {host.get('os', 'Unknown')}",
            "findings": [
                {
                    "cve_id": f.get("cve_id", "UNKNOWN"),
                    "title": f"Vulnerability: {f.get('cve_id', 'UNKNOWN')}",
                    "severity": "High",
                    "description": f.get("description", "No description")[:300],
                    "impact": "Requires security assessment",
                    "recommendation": "Review and apply vendor security patches",
                    "references": ["NVD", "NIST"]
                }
                for f in findings[:10]  # Limit to 10 findings in fallback
            ],
            "recommendations": "Prioritize patching critical and high-severity vulnerabilities. Implement regular vulnerability scanning and patch management procedures.",
            "risk_score": 7.0,
            "risk_level": "High",
            "severity_breakdown": {
                "critical": 0,
                "high": len(findings),
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
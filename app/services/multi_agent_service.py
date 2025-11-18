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

from app.core.config import settings

logger = logging.getLogger(__name__)

# Configure Gemini
genai.configure(api_key=settings.gemini_api_key)


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
        
        prompt = f"""Analyze these {len(findings)} vulnerabilities and categorize by severity.

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

Categorize based on impact:
- Critical: Remote code execution, privilege escalation, complete system compromise
- High: Data exposure, authentication bypass, SQL injection
- Medium: XSS, CSRF, information disclosure, denial of service
- Low: Minor issues, deprecated features, low-impact vulnerabilities"""
        
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
        self.model = genai.GenerativeModel(settings.gemini_model)
    
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
        
        # Focused prompt for single CVE remediation
        prompt = f"""Generate actionable remediation recommendations for this vulnerability:

CVE ID: {cve_id}
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
  "references": ["NIST SP 800-53", "OWASP", "CIS Controls"]
}}

Focus on:
1. Immediate actionable steps (not theory)
2. Specific patch/upgrade instructions
3. Workarounds if patch unavailable
4. Monitoring recommendations"""
        
        try:
            logger.info(f"🤖 Calling Gemini API for {cve_id}...")
            response = self.model.generate_content(prompt)
            api_elapsed = time.time() - start_time
            logger.info(f"📡 API response received for {cve_id} in {api_elapsed:.1f}s")
            
            result = _extract_json_from_text(response.text)
            
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
            "client_name": hostname  # Use hostname as client name
        }
        
        logger.info("✅ Final report assembled")
        return report
    
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
        """Generate executive summary from analysis results."""
        hostname = host.get("hostname", "system")
        total = analysis.get("total", 0)
        critical = analysis.get("critical", {}).get("count", 0)
        high = analysis.get("high", {}).get("count", 0)
        risk_score = risk.get("risk_score", 0.0)
        risk_level = risk.get("risk_level", "Unknown")
        
        return (
            f"Security assessment for {hostname} identified {total} vulnerabilities "
            f"with an overall risk score of {risk_score}/10.0 ({risk_level}). "
            f"The scan found {critical} critical and {high} high-severity vulnerabilities "
            f"requiring immediate attention. Prioritized remediation is recommended to "
            f"reduce security exposure and protect against potential exploitation."
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
            
            # Execute graph
            final_state = self.graph.invoke(initial_state)
            
            logger.info("✅ LangGraph workflow complete")
            return final_state["final_report"]
            
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

